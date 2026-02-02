package handlers

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
	"github.com/mabunixda/est-service/pkg/est"
)

// SimpleEnrollHandler handles POST /.well-known/est/simpleenroll
type SimpleEnrollHandler struct {
	backend   backend.Backend
	authMgr   *auth.Manager
	config    *EnrollmentConfig
	logger    *slog.Logger
	telemetry Telemetry // Telemetry interface for metrics
}

// NewSimpleEnrollHandler creates a new simple enrollment handler
func NewSimpleEnrollHandler(backend backend.Backend, authMgr *auth.Manager, config *EnrollmentConfig, logger *slog.Logger, telemetry Telemetry) *SimpleEnrollHandler {
	if logger == nil {
		logger = slog.Default()
	}

	if config.MaxCSRSize == 0 {
		config.MaxCSRSize = 10 * 1024 * 1024
	}

	return &SimpleEnrollHandler{
		backend:   backend,
		authMgr:   authMgr,
		config:    config,
		logger:    logger,
		telemetry: telemetry,
	}
}

// ServeHTTP handles the simple enrollment request
// @Summary Enroll a new certificate
// @Description Submit a Certificate Signing Request (CSR) to receive a signed certificate. Requires authentication via Basic Auth, TLS client certificate, or Bearer token.
// @Tags EST
// @Accept application/pkcs10
// @Produce application/pkcs7-mime
// @Param body body string true "Base64-encoded PKCS#10 Certificate Signing Request"
// @Success 200 {string} string "Signed certificate in base64-encoded PKCS#7 format"
// @Failure 400 {string} string "Invalid CSR or CSR signature"
// @Failure 401 {string} string "Authentication required"
// @Failure 500 {string} string "Enrollment failed"
// @Security BasicAuth
// @Security BearerAuth
// @Router /.well-known/est/simpleenroll [post]
func (h *SimpleEnrollHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.logger.Debug("Invalid method for /simpleenroll", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// DEBUG: Log TLS connection state (redacted)
	if r.TLS == nil {
		h.logger.Debug("TLS connection state is NIL")
	} else {
		h.logger.Debug("TLS connection state available",
			"peer_certs_count", len(r.TLS.PeerCertificates),
			"version", r.TLS.Version)
	}

	authResult := h.authMgr.Authenticate(ctx, r)
	if !authResult.Authenticated {
		h.logger.Debug("Authentication failed", "error", authResult.Error)
		if h.telemetry != nil {
			h.telemetry.RecordAuthFailure(ctx, "unknown", authResult.Error.Error())
		}
		h.sendAuthRequired(w)
		return
	}

	if h.telemetry != nil {
		h.telemetry.RecordAuthSuccess(ctx, authResult.Method, authResult.Identity)
	}

	h.logger.Info("Request authenticated",
		"method", authResult.Method)

	csr, err := est.ReadCSRPayloadWithLimit(r, h.config.MaxCSRSize)
	if err != nil {
		h.logger.Error("Failed to parse CSR", "error", err)
		http.Error(w, "Invalid CSR", http.StatusBadRequest)
		return
	}

	if err := est.ValidateCSRSignatureAlgorithm(csr, h.config.AllowedSignatureAlgos); err != nil {
		h.logger.Error("Disallowed CSR signature algorithm", "error", err)
		http.Error(w, "Invalid CSR signature algorithm", http.StatusBadRequest)
		return
	}

	if err := est.ValidateCSRSignature(csr); err != nil {
		h.logger.Error("Invalid CSR signature", "error", err)
		http.Error(w, "Invalid CSR signature", http.StatusBadRequest)
		return
	}

	enrollReq := &EnrollmentRequest{
		CSR:          csr,
		Label:        "",
		IsReenroll:   false,
		AuthToken:    authResult.Token,
		AuthMethod:   authResult.Method,
		AuthIdentity: authResult.Identity, Policy: h.config.DefaultPolicy}

	cert, err := h.processEnrollment(ctx, enrollReq)
	if err != nil {
		h.logger.Error("Enrollment failed",
			"error", err,
			"subject", csr.Subject.String())
		if h.telemetry != nil {
			h.telemetry.RecordCertificateRejected(ctx, "enroll", err.Error())
		}
		SendBackendError(w, err, "certificate enrollment")
		return
	}

	if err := h.sendCertificateResponse(w, cert); err != nil {
		h.logger.Error("Failed to send response", "error", err)
		return
	}

	// Record successful certificate issuance
	if h.telemetry != nil {
		h.telemetry.RecordCertificateIssued(ctx, "enroll",
			cert.Subject.String(),
			cert.SerialNumber.String(),
			enrollReq.Policy.TTL)
	}

	h.logger.Info("Certificate enrolled successfully",
		"ttl", enrollReq.Policy.TTL)
}

func (h *SimpleEnrollHandler) processEnrollment(ctx context.Context, req *EnrollmentRequest) (*x509.Certificate, error) {
	h.logger.Info("Using authenticated token for PKI operations",
		"identity", req.AuthIdentity,
		"auth_method", req.AuthMethod)

	return processCSRSigning(ctx, h.backend, req, h.config)
}

func (h *SimpleEnrollHandler) sendCertificateResponse(w http.ResponseWriter, cert *x509.Certificate) error {
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

func (h *SimpleEnrollHandler) sendAuthRequired(w http.ResponseWriter) {
	headers := h.authMgr.GetWWWAuthenticateHeaders()
	for _, header := range headers {
		w.Header().Add("WWW-Authenticate", header)
	}
	http.Error(w, "Authentication required", http.StatusUnauthorized)
}
