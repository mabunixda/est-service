package handlers

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mabunixda/est-service/pkg/auth"
)

func TestSimpleEnroll_BasicAuth(t *testing.T) {
	backendMock := &mockBackendHandlers{}
	authMgr := auth.NewManager(backendMock, &auth.Config{
		UserpassEnabled:   true,
		UserpassMountPath: "userpass",
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "est",
			TTL:   "24h",
		},
		MaxCSRSize:            64 * 1024,
		AllowedSignatureAlgos: []string{"SHA256WithRSA"},
	}

	handler := NewSimpleEnrollHandler(
		backendMock,
		authMgr,
		config,
		slog.Default(),
		&mockTelemetry{},
	)

	csrDER, _, err := generateTestCSR()
	if err != nil {
		t.Fatalf("Failed to generate test CSR: %v", err)
	}
	csrB64 := base64.StdEncoding.EncodeToString(csrDER)

	tests := []struct {
		name           string
		method         string
		body           string
		auth           string
		expectedStatus int
	}{
		{
			name:           "successful enrollment with basic auth",
			method:         http.MethodPost,
			body:           csrB64,
			auth:           "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass")),
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing authentication",
			method:         http.MethodPost,
			body:           csrB64,
			auth:           "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid method",
			method:         http.MethodGet,
			body:           "",
			auth:           "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass")),
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "invalid CSR",
			method:         http.MethodPost,
			body:           "invalid-base64",
			auth:           "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass")),
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/.well-known/est/simpleenroll", bytes.NewReader([]byte(tt.body)))
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			req.Header.Set("Content-Type", "application/pkcs10")

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Status = %d, want %d", w.Code, tt.expectedStatus)
			}
		})
	}
}
