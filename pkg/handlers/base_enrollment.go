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

// baseEnrollmentHandler contains shared enrollment logic for simpleenroll and simplereenroll
// This eliminates code duplication between the two handlers while maintaining their
// specific business logic for enrollment vs reenrollment flows.
type baseEnrollmentHandler struct {
	backend   backend.Backend
	authMgr   *auth.Manager
	config    *EnrollmentConfig
	logger    *slog.Logger
	telemetry Telemetry
	auditLog  *slog.Logger
}

// authenticateRequest handles the authentication flow and records telemetry/audit events
// Returns the authentication result if successful, or sends appropriate error response
func (b *baseEnrollmentHandler) authenticateRequest(ctx context.Context, r *http.Request, w http.ResponseWriter, operation string) (*auth.Result, bool) {
	authResult := b.authMgr.Authenticate(ctx, r)
	if !authResult.Authenticated {
		b.logger.Debug("Authentication failed", "error", authResult.Error, "operation", operation)

		if b.telemetry != nil {
			method := authResult.Method
			if method == "" {
				method = "unknown"
			}
			b.telemetry.RecordAuthFailure(ctx, method, authResult.Error.Error())
		}

		if b.auditLog != nil {
			b.auditLog.Info(fmt.Sprintf("audit.%s", operation),
				"request_id", observability.RequestIDFromContext(ctx),
				"action", operation,
				"result", "denied",
				"reason", "auth_failed",
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent())
		}

		b.sendAuthRequired(w)
		return nil, false
	}

	if b.telemetry != nil {
		b.telemetry.RecordAuthSuccess(ctx, authResult.Method, authResult.Identity)
	}

	b.logger.Info("Request authenticated",
		"method", authResult.Method,
		"operation", operation)

	return authResult, true
}

// parseAndValidateCSR parses the CSR from the request and validates its signature
// Returns the CSR if successful, or sends appropriate error response
func (b *baseEnrollmentHandler) parseAndValidateCSR(ctx context.Context, r *http.Request, w http.ResponseWriter, operation string) (*x509.CertificateRequest, bool) {
	csr, err := est.ReadCSRPayloadWithLimit(r, b.config.MaxCSRSize)
	if err != nil {
		if errors.Is(err, est.ErrRequestTooLarge) {
			b.logger.Error("CSR request too large", "error", err, "operation", operation)
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return nil, false
		}
		b.logger.Error("Failed to parse CSR", "error", err, "operation", operation)
		http.Error(w, "Invalid CSR", http.StatusBadRequest)
		return nil, false
	}

	// Validate signature algorithm
	if err := est.ValidateCSRSignatureAlgorithm(csr, b.config.AllowedSignatureAlgos); err != nil {
		b.logger.Error("Disallowed CSR signature algorithm", "error", err, "operation", operation)

		if b.auditLog != nil {
			b.auditLog.Info(fmt.Sprintf("audit.%s", operation),
				"request_id", observability.RequestIDFromContext(ctx),
				"action", operation,
				"result", "denied",
				"reason", "invalid_signature_algorithm",
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent())
		}

		http.Error(w, "Invalid CSR signature algorithm", http.StatusBadRequest)
		return nil, false
	}

	// Validate CSR signature
	if err := est.ValidateCSRSignature(csr); err != nil {
		b.logger.Error("Invalid CSR signature", "error", err, "operation", operation)

		if b.auditLog != nil {
			b.auditLog.Info(fmt.Sprintf("audit.%s", operation),
				"request_id", observability.RequestIDFromContext(ctx),
				"action", operation,
				"result", "denied",
				"reason", "invalid_signature",
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent())
		}

		http.Error(w, "Invalid CSR signature", http.StatusBadRequest)
		return nil, false
	}

	return csr, true
}

// recordRejection records a rejection in telemetry and audit logs
func (b *baseEnrollmentHandler) recordRejection(ctx context.Context, r *http.Request, operation, reason string) {
	if b.telemetry != nil {
		b.telemetry.RecordCertificateRejected(ctx, operation, reason)
	}

	if b.auditLog != nil {
		b.auditLog.Info(fmt.Sprintf("audit.%s", operation),
			"request_id", observability.RequestIDFromContext(ctx),
			"action", operation,
			"result", "error",
			"reason", reason,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent())
	}
}

// recordSuccess records a successful certificate issuance in telemetry and audit logs
func (b *baseEnrollmentHandler) recordSuccess(ctx context.Context, r *http.Request, operation string, cert *x509.Certificate, authResult *auth.Result, policy LabelPolicy) {
	if b.telemetry != nil {
		b.telemetry.RecordCertificateIssued(ctx, operation,
			cert.Subject.String(),
			cert.SerialNumber.String(),
			policy.TTL)
	}

	if b.auditLog != nil {
		b.auditLog.Info(fmt.Sprintf("audit.%s", operation),
			"request_id", observability.RequestIDFromContext(ctx),
			"action", operation,
			"result", "success",
			"auth_method", authResult.Method,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent())
	}

	b.logger.Info(fmt.Sprintf("Certificate %sed successfully", operation),
		"ttl", policy.TTL)
}

// sendCertificateResponse sends a certificate in PKCS#7 format per RFC 7030
func (b *baseEnrollmentHandler) sendCertificateResponse(w http.ResponseWriter, cert *x509.Certificate) error {
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

// sendAuthRequired sends a 401 response with appropriate WWW-Authenticate headers
func (b *baseEnrollmentHandler) sendAuthRequired(w http.ResponseWriter) {
	headers := b.authMgr.GetWWWAuthenticateHeaders()
	for _, header := range headers {
		w.Header().Add("WWW-Authenticate", header)
	}
	http.Error(w, "Authentication required", http.StatusUnauthorized)
}
