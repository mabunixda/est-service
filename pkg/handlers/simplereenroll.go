package handlers

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
	"github.com/mabunixda/est-service/pkg/est"
	"github.com/mabunixda/est-service/pkg/observability"
)

// SimpleReenrollHandler handles POST /.well-known/est/simplereenroll
type SimpleReenrollHandler struct {
	backend   backend.Backend
	authMgr   *auth.Manager
	config    *EnrollmentConfig
	logger    *slog.Logger
	telemetry Telemetry
	auditLog  *slog.Logger
}

// NewSimpleReenrollHandler creates a new simple reenrollment handler
func NewSimpleReenrollHandler(backend backend.Backend, authMgr *auth.Manager, config *EnrollmentConfig, logger *slog.Logger, telemetry Telemetry) *SimpleReenrollHandler {
	if logger == nil {
		logger = slog.Default()
	}

	if config.MaxCSRSize == 0 {
		config.MaxCSRSize = 64 * 1024
	}

	return &SimpleReenrollHandler{
		backend:   backend,
		authMgr:   authMgr,
		config:    config,
		logger:    logger,
		telemetry: telemetry,
	}
}

// SetAuditLogger sets the audit logger for structured audit events
func (h *SimpleReenrollHandler) SetAuditLogger(logger *slog.Logger) {
	h.auditLog = logger
}

// ServeHTTP handles the simple reenrollment request
// @Summary Reenroll an existing certificate
// @Description Submit a Certificate Signing Request (CSR) to renew an existing certificate. Requires authentication and optionally validates that the CSR matches the client certificate.
// @Tags EST
// @Accept application/pkcs10
// @Produce application/pkcs7-mime
// @Param body body string true "Base64-encoded PKCS#10 Certificate Signing Request"
// @Success 200 {string} string "Renewed certificate in base64-encoded PKCS#7 format"
// @Failure 400 {string} string "Invalid CSR, CSR signature, or CSR does not match client certificate"
// @Failure 401 {string} string "Authentication required"
// @Failure 500 {string} string "Reenrollment failed"
// @Security BasicAuth
// @Security BearerAuth
// @Router /.well-known/est/simplereenroll [post]
func (h *SimpleReenrollHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.logger.Debug("Invalid method for /simplereenroll", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// Try to get TLS client certificate (optional for non-TLS environments)
	clientCert, err := est.ExtractTLSClientCertificate(r)
	hasTLSCert := err == nil && clientCert != nil

	// Authentication is required (either TLS cert or other methods like Basic Auth)
	authResult := h.authMgr.Authenticate(ctx, r)
	if !authResult.Authenticated {
		h.logger.Debug("Authentication failed", "error", authResult.Error)
		if h.telemetry != nil {
			h.telemetry.RecordAuthFailure(ctx, authResult.Method, authResult.Error.Error())
		}
		if h.auditLog != nil {
			h.auditLog.Info("audit.reenroll",
				"request_id", observability.RequestIDFromContext(ctx),
				"action", "reenroll",
				"result", "denied",
				"reason", "auth_failed",
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent())
		}
		h.sendAuthRequired(w)
		return
	}

	if h.telemetry != nil {
		h.telemetry.RecordAuthSuccess(ctx, authResult.Method, authResult.Identity)
	}

	if hasTLSCert {
		h.logger.Info("Reenrollment request authenticated with TLS certificate",
			"method", authResult.Method)
	} else {
		h.logger.Info("Reenrollment request authenticated without TLS certificate",
			"method", authResult.Method)
	}

	csr, err := est.ReadCSRPayloadWithLimit(r, h.config.MaxCSRSize)
	if err != nil {
		if errors.Is(err, est.ErrRequestTooLarge) {
			h.logger.Error("CSR request too large", "error", err)
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		h.logger.Error("Failed to parse CSR", "error", err)
		if h.telemetry != nil {
			h.telemetry.RecordCertificateRejected(ctx, "reenroll", "invalid_csr")
		}
		http.Error(w, "Invalid CSR", http.StatusBadRequest)
		return
	}

	if err := est.ValidateCSRSignatureAlgorithm(csr, h.config.AllowedSignatureAlgos); err != nil {
		h.logger.Error("Disallowed CSR signature algorithm", "error", err)
		if h.telemetry != nil {
			h.telemetry.RecordCertificateRejected(ctx, "reenroll", "invalid_signature_algorithm")
		}
		if h.auditLog != nil {
			h.auditLog.Info("audit.reenroll",
				"request_id", observability.RequestIDFromContext(ctx),
				"action", "reenroll",
				"result", "denied",
				"reason", "invalid_signature_algorithm",
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent())
		}
		http.Error(w, "Invalid CSR signature algorithm", http.StatusBadRequest)
		return
	}

	if err := est.ValidateCSRSignature(csr); err != nil {
		h.logger.Error("Invalid CSR signature", "error", err)
		if h.telemetry != nil {
			h.telemetry.RecordCertificateRejected(ctx, "reenroll", "invalid_signature")
		}
		if h.auditLog != nil {
			h.auditLog.Info("audit.reenroll",
				"request_id", observability.RequestIDFromContext(ctx),
				"action", "reenroll",
				"result", "denied",
				"reason", "invalid_signature",
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent())
		}
		http.Error(w, "Invalid CSR signature", http.StatusBadRequest)
		return
	}

	// Only validate CSR matches certificate if TLS cert was provided
	if hasTLSCert {
		if err := est.ValidateCSRMatchesCertificate(csr, clientCert); err != nil {
			h.logger.Error("CSR does not match client certificate",
				"error", err,
				"csr_subject", csr.Subject.String(),
				"cert_subject", clientCert.Subject.String())
			if h.telemetry != nil {
				h.telemetry.RecordCertificateRejected(ctx, "reenroll", "csr_cert_mismatch")
			}
			if h.auditLog != nil {
				h.auditLog.Info("audit.reenroll",
					"request_id", observability.RequestIDFromContext(ctx),
					"action", "reenroll",
					"result", "denied",
					"reason", "csr_cert_mismatch",
					"remote_addr", r.RemoteAddr,
					"user_agent", r.UserAgent())
			}
			http.Error(w, "CSR public key must match client certificate", http.StatusBadRequest)
			return
		}

		// RFC 7030 Section 4.2.2: Validate Subject and SubjectAltName match
		// unless ChangeSubjectName attribute is present
		if err := est.ValidateReenrollmentSubject(csr, clientCert); err != nil {
			h.logger.Error("CSR subject/SAN validation failed",
				"error", err,
				"csr_subject", csr.Subject.String(),
				"cert_subject", clientCert.Subject.String())
			if h.telemetry != nil {
				h.telemetry.RecordCertificateRejected(ctx, "reenroll", "subject_mismatch")
			}
			if h.auditLog != nil {
				h.auditLog.Info("audit.reenroll",
					"request_id", observability.RequestIDFromContext(ctx),
					"action", "reenroll",
					"result", "denied",
					"reason", "subject_san_mismatch",
					"remote_addr", r.RemoteAddr,
					"user_agent", r.UserAgent())
			}
			http.Error(w, "CSR Subject and SubjectAltName must match existing certificate (or include ChangeSubjectName attribute)", http.StatusBadRequest)
			return
		}
	}

	enrollReq := &EnrollmentRequest{
		CSR:          csr,
		ClientCert:   clientCert,
		Label:        "",
		IsReenroll:   true,
		AuthToken:    authResult.Token,
		AuthMethod:   authResult.Method,
		AuthIdentity: authResult.Identity,
		Policy:       h.config.DefaultPolicy,
	}

	cert, err := h.processReenrollment(ctx, enrollReq)
	if err != nil {
		h.logger.Error("Reenrollment failed",
			"error", err,
			"subject", csr.Subject.String())
		if h.telemetry != nil {
			h.telemetry.RecordCertificateRejected(ctx, "reenroll", "backend_error")
		}
		if h.auditLog != nil {
			h.auditLog.Info("audit.reenroll",
				"request_id", observability.RequestIDFromContext(ctx),
				"action", "reenroll",
				"result", "error",
				"reason", "backend_error",
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent())
		}
		SendBackendError(w, err, "certificate re-enrollment")
		return
	}

	if err := h.sendCertificateResponse(w, cert); err != nil {
		h.logger.Error("Failed to send response", "error", err)
		return
	}

	// Track certificate issuance
	if h.telemetry != nil {
		h.telemetry.RecordCertificateIssued(ctx, "reenroll",
			cert.Subject.String(),
			cert.SerialNumber.String(),
			enrollReq.Policy.TTL)
	}
	if h.auditLog != nil {
		h.auditLog.Info("audit.reenroll",
			"request_id", observability.RequestIDFromContext(ctx),
			"action", "reenroll",
			"result", "success",
			"auth_method", authResult.Method,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent())
	}

	// Log successful reenrollment with optional old serial
	logAttrs := []any{
		"ttl", enrollReq.Policy.TTL,
	}
	h.logger.Info("Certificate reenrolled successfully", logAttrs...)
}

func (h *SimpleReenrollHandler) processReenrollment(ctx context.Context, req *EnrollmentRequest) (*x509.Certificate, error) {
	h.logger.Info("Using authenticated token for PKI operations",
		"identity", req.AuthIdentity,
		"auth_method", req.AuthMethod)

	return processCSRSigning(ctx, h.backend, req, h.config)
}

func (h *SimpleReenrollHandler) sendCertificateResponse(w http.ResponseWriter, cert *x509.Certificate) error {
	pkcs7Data, err := est.CreatePKCS7CertsOnly([]*x509.Certificate{cert})
	if err != nil {
		return fmt.Errorf("failed to create PKCS#7: %w", err)
	}

	// RFC 7030 requires base64 encoding for EST responses
	base64Data := base64.StdEncoding.EncodeToString(pkcs7Data)

	w.Header().Set("Content-Type", est.PKCS7ContentType)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write([]byte(base64Data)); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}

	return nil
}

func (h *SimpleReenrollHandler) sendAuthRequired(w http.ResponseWriter) {
	headers := h.authMgr.GetWWWAuthenticateHeaders()
	for _, header := range headers {
		w.Header().Add("WWW-Authenticate", header)
	}
	http.Error(w, "Authentication required", http.StatusUnauthorized)
}
