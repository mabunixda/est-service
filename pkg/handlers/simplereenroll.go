package handlers

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net/http"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
	"github.com/mabunixda/est-service/pkg/est"
	"github.com/mabunixda/est-service/pkg/observability"
)

// SimpleReenrollHandler handles POST /.well-known/est/simplereenroll
type SimpleReenrollHandler struct {
	*baseEnrollmentHandler // Embed base handler for shared functionality
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
		baseEnrollmentHandler: &baseEnrollmentHandler{
			backend:   backend,
			authMgr:   authMgr,
			config:    config,
			logger:    logger,
			telemetry: telemetry,
		},
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

	// Authenticate using shared authentication logic
	authResult, ok := h.authenticateRequest(ctx, r, w, "reenroll")
	if !ok {
		return
	}

	if hasTLSCert {
		h.logger.Info("Reenrollment request authenticated with TLS certificate",
			"method", authResult.Method)
	} else {
		h.logger.Info("Reenrollment request authenticated without TLS certificate",
			"method", authResult.Method)
	}

	// Parse and validate CSR using shared validation logic
	csr, ok := h.parseAndValidateCSR(ctx, r, w, "reenroll")
	if !ok {
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
		h.recordRejection(ctx, r, "reenroll", "backend_error")
		SendBackendError(w, err, "certificate re-enrollment")
		return
	}

	if err := h.sendCertificateResponse(w, cert); err != nil {
		h.logger.Error("Failed to send response", "error", err)
		return
	}

	// Record successful certificate issuance
	h.recordSuccess(ctx, r, "reenroll", cert, authResult, enrollReq.Policy)
}

func (h *SimpleReenrollHandler) processReenrollment(ctx context.Context, req *EnrollmentRequest) (*x509.Certificate, error) {
	h.logger.Info("Using authenticated token for PKI operations",
		"identity", req.AuthIdentity,
		"auth_method", req.AuthMethod)

	return processCSRSigning(ctx, h.backend, req, h.config)
}
