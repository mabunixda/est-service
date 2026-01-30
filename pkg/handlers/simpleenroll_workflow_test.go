package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
)

// TestSimpleEnrollWorkflow_Success tests a complete successful enrollment
func TestSimpleEnrollWorkflow_Success(t *testing.T) {
	// Create a test CSR
	csrPEM, csrDER := generateTestCSRPEM(t)

	// Setup mock backend
	mock := &backend.MockBackend{
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			if username == "testuser" && password == "testpass" {
				return "test-token-123", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		CloneWithTokenFunc: func(ctx context.Context, token string) (backend.Backend, error) {
			// Return a mock that can sign CSRs
			return &backend.MockBackend{
				SignCSRFunc: func(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
					// Generate test certificate from CSR
					return generateTestCertFromCSR(csr)
				},
			}, nil
		},
	}

	authMgr := auth.NewManager(mock, &auth.Config{
		UserpassEnabled:   true,
		UserpassMountPath: "userpass",
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "est",
		},
	}

	handler := NewSimpleEnrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	// Create request with Basic Auth
	req := httptest.NewRequest("POST", "/.well-known/est/simpleenroll", bytes.NewReader(csrDER))
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testuser:testpass")))
	req.Header.Set("Content-Type", "application/pkcs10")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify response is base64-encoded PKCS#7
	if w.Header().Get("Content-Type") != "application/pkcs7-mime; smime-type=certs-only" {
		t.Errorf("Expected PKCS#7 content type, got %s", w.Header().Get("Content-Type"))
	}

	// Verify we can decode the response
	respBody := w.Body.Bytes()
	if len(respBody) == 0 {
		t.Error("Response body is empty")
	}

	t.Logf("CSR PEM:\n%s", csrPEM)
	t.Logf("Response length: %d bytes", len(respBody))
}

// TestSimpleEnrollWorkflow_InvalidCredentials tests enrollment with wrong credentials
func TestSimpleEnrollWorkflow_InvalidCredentials(t *testing.T) {
	_, csrDER := generateTestCSRPEM(t)

	mock := &backend.MockBackend{
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			return "", fmt.Errorf("invalid credentials")
		},
	}

	authMgr := auth.NewManager(mock, &auth.Config{
		UserpassEnabled:   true,
		UserpassMountPath: "userpass",
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
	}

	handler := NewSimpleEnrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	req := httptest.NewRequest("POST", "/.well-known/est/simpleenroll", bytes.NewReader(csrDER))
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("wronguser:wrongpass")))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

// TestSimpleEnrollWorkflow_MissingAuth tests enrollment without authentication
func TestSimpleEnrollWorkflow_MissingAuth(t *testing.T) {
	_, csrDER := generateTestCSRPEM(t)

	mock := &backend.MockBackend{}
	authMgr := auth.NewManager(mock, &auth.Config{
		UserpassEnabled: true,
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
	}

	handler := NewSimpleEnrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	req := httptest.NewRequest("POST", "/.well-known/est/simpleenroll", bytes.NewReader(csrDER))
	// No Authorization header

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

// TestSimpleEnrollWorkflow_InvalidCSR tests enrollment with malformed CSR
func TestSimpleEnrollWorkflow_InvalidCSR(t *testing.T) {
	mock := &backend.MockBackend{
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			return "test-token", nil
		},
	}

	authMgr := auth.NewManager(mock, &auth.Config{
		UserpassEnabled: true,
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
	}

	handler := NewSimpleEnrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	// Send garbage data as CSR
	req := httptest.NewRequest("POST", "/.well-known/est/simpleenroll", bytes.NewReader([]byte("invalid csr data")))
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testuser:testpass")))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// TestSimpleEnrollWorkflow_BackendError tests enrollment when backend fails
func TestSimpleEnrollWorkflow_BackendError(t *testing.T) {
	_, csrDER := generateTestCSRPEM(t)

	mock := &backend.MockBackend{
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			return "test-token", nil
		},
		CloneWithTokenFunc: func(ctx context.Context, token string) (backend.Backend, error) {
			return &backend.MockBackend{
				SignCSRFunc: func(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
					return nil, fmt.Errorf("backend error: PKI mount not found")
				},
			}, nil
		},
	}

	authMgr := auth.NewManager(mock, &auth.Config{
		UserpassEnabled: true,
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "est",
		},
	}

	handler := NewSimpleEnrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	req := httptest.NewRequest("POST", "/.well-known/est/simpleenroll", bytes.NewReader(csrDER))
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testuser:testpass")))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 404 { // Backend error returns 404 for "mount not found"
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

// TestSimpleEnrollWorkflow_WithLabel tests enrollment with label-based policy
func TestSimpleEnrollWorkflow_WithLabel(t *testing.T) {
	_, csrDER := generateTestCSRPEM(t)

	mock := &backend.MockBackend{
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			return "test-token", nil
		},
		CloneWithTokenFunc: func(ctx context.Context, token string) (backend.Backend, error) {
			return &backend.MockBackend{
				SignCSRFunc: func(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
					// Verify correct mount and role are used
					if mount != "pki" {
						return nil, fmt.Errorf("wrong mount: %s", mount)
					}
					if role != "mobile-devices" {
						return nil, fmt.Errorf("wrong role: %s", role)
					}
					return generateTestCertFromCSR(csr)
				},
			}, nil
		},
	}

	authMgr := auth.NewManager(mock, &auth.Config{
		UserpassEnabled: true,
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki", DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "mobile-devices",
		}, Labels: map[string]LabelPolicy{
			"mobile": {
				Type:  "role",
				Value: "mobile-devices",
				Mount: "pki",
			},
		},
	}

	handler := NewSimpleEnrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	// Request with label parameter
	req := httptest.NewRequest("POST", "/.well-known/est/mobile/simpleenroll", bytes.NewReader(csrDER))
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testuser:testpass")))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSimpleEnrollWorkflow_VerbatimSigning tests enrollment with sign-verbatim policy
func TestSimpleEnrollWorkflow_VerbatimSigning(t *testing.T) {
	_, csrDER := generateTestCSRPEM(t)

	signVerbatimCalled := false

	mock := &backend.MockBackend{
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			return "test-token", nil
		},
		CloneWithTokenFunc: func(ctx context.Context, token string) (backend.Backend, error) {
			return &backend.MockBackend{
				SignCSRVerbatimFunc: func(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
					signVerbatimCalled = true
					return generateTestCertFromCSR(csr)
				},
			}, nil
		},
	}

	authMgr := auth.NewManager(mock, &auth.Config{
		UserpassEnabled: true,
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		DefaultPolicy: LabelPolicy{
			Type: "sign-verbatim",
		},
	}

	handler := NewSimpleEnrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	req := httptest.NewRequest("POST", "/.well-known/est/simpleenroll", bytes.NewReader(csrDER))
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testuser:testpass")))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if !signVerbatimCalled {
		t.Error("SignCSRVerbatim was not called")
	}
}

// Helper function to generate a test CSR
func generateTestCSRPEM(t *testing.T) (string, []byte) {
	t.Helper()

	// Generate key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create CSR template
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		DNSNames: []string{"test.example.com"},
	}

	// Create CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Encode as PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// Also return base64-encoded DER for direct use
	csrBase64 := []byte(base64.StdEncoding.EncodeToString(csrDER))

	return string(csrPEM), csrBase64
}
