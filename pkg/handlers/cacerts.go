package handlers

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/mabunixda/est-service/pkg/backend"
	"github.com/mabunixda/est-service/pkg/est"
)

// CACertsHandler handles GET /.well-known/est/cacerts
type CACertsHandler struct {
	backend backend.Backend
	mount   string
	logger  *slog.Logger
}

// NewCACertsHandler creates a new CA certificates handler
func NewCACertsHandler(backend backend.Backend, mount string, logger *slog.Logger) *CACertsHandler {
	if logger == nil {
		logger = slog.Default()
	}

	return &CACertsHandler{
		backend: backend,
		mount:   mount,
		logger:  logger,
	}
}

// ServeHTTP handles the CA certificates request
// @Summary Get CA certificates
// @Description Retrieve the current CA certificate(s) used by the EST server. Returns a PKCS#7 certs-only structure containing one or more certificates.
// @Tags EST
// @Produce application/pkcs7-mime
// @Success 200 {string} string "CA certificates in base64-encoded PKCS#7 format"
// @Failure 500 {string} string "Failed to retrieve CA certificates"
// @Router /.well-known/est/cacerts [get]
func (h *CACertsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.logger.Debug("Invalid method for /cacerts", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	certs, err := h.getCAChain(ctx)
	if err != nil {
		h.logger.Error("Failed to get CA chain", "error", err)
		http.Error(w, "Failed to retrieve CA certificates", http.StatusInternalServerError)
		return
	}

	if len(certs) == 0 {
		h.logger.Error("No CA certificates available")
		http.Error(w, "No CA certificates available", http.StatusInternalServerError)
		return
	}

	pkcs7Data, err := est.CreatePKCS7CertsOnly(certs)
	if err != nil {
		h.logger.Error("Failed to create PKCS#7", "error", err)
		http.Error(w, "Failed to encode certificates", http.StatusInternalServerError)
		return
	}

	// RFC 7030 requires base64 encoding for EST responses
	base64Data := base64.StdEncoding.EncodeToString(pkcs7Data)

	w.Header().Set("Content-Type", est.PKCS7ContentType)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write([]byte(base64Data)); err != nil {
		h.logger.Error("Failed to write response", "error", err)
		return
	}

	h.logger.Info("CA certificates served",
		"certificates", len(certs),
		"bytes", len(pkcs7Data))
}

func (h *CACertsHandler) getCAChain(ctx context.Context) ([]*x509.Certificate, error) {
	certs, err := h.backend.GetCAChain(ctx, h.mount)
	if err != nil {
		h.logger.Debug("Failed to get CA chain, trying single CA cert", "error", err)

		cert, err := h.backend.GetCACertificate(ctx, h.mount)
		if err != nil {
			return nil, fmt.Errorf("failed to get CA certificate: %w", err)
		}

		return []*x509.Certificate{cert}, nil
	}

	return certs, nil
}
