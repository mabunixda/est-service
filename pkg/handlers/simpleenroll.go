package handlers

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net/http"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
)

// SimpleEnrollHandler handles POST /.well-known/est/simpleenroll
type SimpleEnrollHandler struct {
	*baseEnrollmentHandler // Embed base handler for shared functionality
}

// NewSimpleEnrollHandler creates a new simple enrollment handler
func NewSimpleEnrollHandler(backend backend.Backend, authMgr *auth.Manager, config *EnrollmentConfig, logger *slog.Logger, telemetry Telemetry) *SimpleEnrollHandler {
	if logger == nil {
		logger = slog.Default()
	}

	if config.MaxCSRSize == 0 {
		config.MaxCSRSize = 64 * 1024
	}

	return &SimpleEnrollHandler{
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
func (h *SimpleEnrollHandler) SetAuditLogger(logger *slog.Logger) {
	h.auditLog = logger
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

	// Authenticate using shared authentication logic
	authResult, ok := h.authenticateRequest(ctx, r, w, "enroll")
	if !ok {
		return
	}

	// Parse and validate CSR using shared validation logic
	csr, ok := h.parseAndValidateCSR(ctx, r, w, "enroll")
	if !ok {
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
		h.recordRejection(ctx, r, "enroll", "backend_error")
		SendBackendError(w, err, "certificate enrollment")
		return
	}

	if err := h.sendCertificateResponse(w, cert); err != nil {
		h.logger.Error("Failed to send response", "error", err)
		return
	}

	// Record successful certificate issuance
	h.recordSuccess(ctx, r, "enroll", cert, authResult, enrollReq.Policy)
}

func (h *SimpleEnrollHandler) processEnrollment(ctx context.Context, req *EnrollmentRequest) (*x509.Certificate, error) {
	h.logger.Info("Using authenticated token for PKI operations",
		"identity", req.AuthIdentity,
		"auth_method", req.AuthMethod)

	return processCSRSigning(ctx, h.backend, req, h.config)
}
