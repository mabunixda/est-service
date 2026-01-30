package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
	"github.com/mabunixda/est-service/pkg/handlers"
	"github.com/openbao/openbao/api/v2"
)

// mockBackend implements backend.Backend for testing
type mockBackend struct {
	healthFunc func(context.Context) (*api.HealthResponse, error)
}

func (m *mockBackend) Health(ctx context.Context) (*api.HealthResponse, error) {
	if m.healthFunc != nil {
		return m.healthFunc(ctx)
	}
	return &api.HealthResponse{Initialized: true, Sealed: false, Version: "test"}, nil
}

func (m *mockBackend) GetCACertificate(ctx context.Context, mount string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockBackend) GetCAChain(ctx context.Context, mount string) ([]*x509.Certificate, error) {
	return nil, nil
}
func (m *mockBackend) SignCSR(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockBackend) SignCSRVerbatim(ctx context.Context, mount string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockBackend) GetIssuerPEM(ctx context.Context, mount, issuer string) (string, error) {
	return "", nil
}
func (m *mockBackend) AuthenticateUserpass(ctx context.Context, mount, username, password string) (string, error) {
	return "", nil
}
func (m *mockBackend) AuthenticateCert(ctx context.Context, mount string, connState *tls.ConnectionState, role string) (string, error) {
	return "", nil
}
func (m *mockBackend) ValidateToken(ctx context.Context, token string) (bool, error) {
	return true, nil
}
func (m *mockBackend) LookupToken(ctx context.Context, token string) (map[string]interface{}, error) {
	return nil, nil
}
func (m *mockBackend) RenewToken(ctx context.Context) error {
	return nil
}
func (m *mockBackend) StartTokenRenewal(ctx context.Context) {}
func (m *mockBackend) GetAPIClient() *api.Client {
	return nil
}
func (m *mockBackend) CloneWithToken(ctx context.Context, token string) (backend.Backend, error) {
	return m, nil
}
func (m *mockBackend) Type() backend.BackendType {
	return backend.BackendTypeOpenBao
}

// TestNew tests server creation with various configurations
func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		wantError bool
	}{
		{
			name: "basic configuration",
			config: &Config{
				ListenAddr: ":8080",
				PKIMount:   "pki",
				AuthConfig: &auth.Config{
					UserpassEnabled:   true,
					UserpassMountPath: "userpass",
				},
				EnrollmentConfig: &handlers.EnrollmentConfig{
					DefaultMount: "pki",
					DefaultPolicy: handlers.LabelPolicy{
						Type:  "role",
						Value: "est",
					},
				},
			},
			wantError: false,
		},
		{
			name: "with rate limiting",
			config: &Config{
				ListenAddr: ":8080",
				PKIMount:   "pki",
				RateLimit: &RateLimitConfig{
					Enabled:           true,
					RequestsPerSecond: 10,
					Burst:             20,
				},
				AuthConfig: &auth.Config{},
				EnrollmentConfig: &handlers.EnrollmentConfig{
					DefaultMount: "pki",
				},
			},
			wantError: false,
		},
		{
			name: "with custom timeouts",
			config: &Config{
				ListenAddr:   ":8080",
				PKIMount:     "pki",
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  120 * time.Second,
				AuthConfig:   &auth.Config{},
				EnrollmentConfig: &handlers.EnrollmentConfig{
					DefaultMount: "pki",
				},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &backend.Client{}
			// Note: We can't set the backend field directly, but for these tests
			// the server creation doesn't actually call backend methods

			srv, err := New(client, tt.config, slog.Default())

			if tt.wantError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.wantError && srv == nil {
				t.Error("Expected server but got nil")
			}

			// Verify defaults were applied
			if !tt.wantError && srv != nil {
				if tt.config.ReadTimeout == 0 && srv.httpServer.ReadTimeout != 15*time.Second {
					t.Errorf("Default ReadTimeout = %v, want 15s", srv.httpServer.ReadTimeout)
				}
				if tt.config.WriteTimeout == 0 && srv.httpServer.WriteTimeout != 15*time.Second {
					t.Errorf("Default WriteTimeout = %v, want 15s", srv.httpServer.WriteTimeout)
				}
				if tt.config.IdleTimeout == 0 && srv.httpServer.IdleTimeout != 60*time.Second {
					t.Errorf("Default IdleTimeout = %v, want 60s", srv.httpServer.IdleTimeout)
				}
			}
		})
	}
}

// TestConfig_Defaults tests that Config applies sensible defaults
func TestConfig_Defaults(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		PKIMount:   "pki",
		AuthConfig: &auth.Config{},
		EnrollmentConfig: &handlers.EnrollmentConfig{
			DefaultMount: "pki",
		},
	}

	client := &backend.Client{}
	srv, err := New(client, cfg, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Verify defaults
	if srv.httpServer.ReadTimeout != 15*time.Second {
		t.Errorf("ReadTimeout = %v, want 15s", srv.httpServer.ReadTimeout)
	}
	if srv.httpServer.WriteTimeout != 15*time.Second {
		t.Errorf("WriteTimeout = %v, want 15s", srv.httpServer.WriteTimeout)
	}
	if srv.httpServer.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout = %v, want 60s", srv.httpServer.IdleTimeout)
	}
	if srv.httpServer.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 10s", srv.httpServer.ReadHeaderTimeout)
	}
}

// TestHealthHandler tests the health check endpoint
// Note: Full end-to-end health tests require integration tests with real backend
func TestHealthHandler_MethodValidation(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		PKIMount:   "pki",
		AuthConfig: &auth.Config{},
		EnrollmentConfig: &handlers.EnrollmentConfig{
			DefaultMount: "pki",
		},
	}

	srv, err := New(&backend.Client{}, cfg, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test invalid method
	req := httptest.NewRequest("POST", "/health", nil)
	w := httptest.NewRecorder()

	srv.healthHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// TestReadyHandler tests the readiness check endpoint
func TestReadyHandler(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "ready",
			method:         "GET",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ready"}`,
		},
		{
			name:           "invalid method",
			method:         "POST",
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ListenAddr: ":8080",
				PKIMount:   "pki",
				AuthConfig: &auth.Config{},
				EnrollmentConfig: &handlers.EnrollmentConfig{
					DefaultMount: "pki",
				},
			}

			srv, err := New(&backend.Client{}, cfg, slog.Default())
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			req := httptest.NewRequest(tt.method, "/ready", nil)
			w := httptest.NewRecorder()

			srv.readyHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Status = %d, want %d", w.Code, tt.expectedStatus)
			}

			if tt.expectedBody != "" && w.Body.String() != tt.expectedBody {
				t.Errorf("Body = %q, want %q", w.Body.String(), tt.expectedBody)
			}
		})
	}
}

// TestRecoveryMiddleware tests panic recovery
func TestRecoveryMiddleware(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		PKIMount:   "pki",
		AuthConfig: &auth.Config{},
		EnrollmentConfig: &handlers.EnrollmentConfig{
			DefaultMount: "pki",
		},
	}

	srv, err := New(&backend.Client{}, cfg, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	wrapped := srv.recoveryMiddleware(panicHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	// Should not panic
	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusInternalServerError)
	}

	body := w.Body.String()
	if !contains(body, "Internal server error") {
		t.Errorf("Body = %q, want to contain 'Internal server error'", body)
	}
}

// TestLoggingMiddleware tests request logging
func TestLoggingMiddleware(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		PKIMount:   "pki",
		AuthConfig: &auth.Config{},
		EnrollmentConfig: &handlers.EnrollmentConfig{
			DefaultMount: "pki",
		},
	}

	srv, err := New(&backend.Client{}, cfg, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrapped := srv.loggingMiddleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestResponseWriter tests the responseWriter wrapper
func TestResponseWriter(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

	// Default status
	if rw.statusCode != http.StatusOK {
		t.Errorf("Default statusCode = %d, want %d", rw.statusCode, http.StatusOK)
	}

	// Write header
	rw.WriteHeader(http.StatusCreated)
	if rw.statusCode != http.StatusCreated {
		t.Errorf("StatusCode = %d, want %d", rw.statusCode, http.StatusCreated)
	}
	if w.Code != http.StatusCreated {
		t.Errorf("Wrapped statusCode = %d, want %d", w.Code, http.StatusCreated)
	}
}

// TestSetupRoutes tests route configuration
func TestSetupRoutes(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		PKIMount:   "pki",
		AuthConfig: &auth.Config{},
		EnrollmentConfig: &handlers.EnrollmentConfig{
			DefaultMount: "pki",
			DefaultPolicy: handlers.LabelPolicy{
				Type:  "role",
				Value: "est",
			},
		},
	}

	srv, err := New(&backend.Client{}, cfg, slog.Default())
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	mux := srv.setupRoutes()

	// Verify mux was created
	if mux == nil {
		t.Fatal("setupRoutes returned nil")
	}

	// Test EST endpoints that should exist (but we won't actually call them due to backend limitations)
	// Just verify the server has a mux configured
	if srv.httpServer.Handler == nil {
		t.Error("HTTP server handler not configured")
	}
}

// TestSetupTLS tests TLS configuration
func TestSetupTLS(t *testing.T) {
	// Create temporary cert and key files
	certFile, keyFile, cleanup := createTestCertFiles(t)
	defer cleanup()

	tests := []struct {
		name      string
		tlsConfig *TLSConfig
		wantError bool
	}{
		{
			name: "valid cert and key",
			tlsConfig: &TLSConfig{
				CertFile: certFile,
				KeyFile:  keyFile,
			},
			wantError: false,
		},
		{
			name: "missing cert file",
			tlsConfig: &TLSConfig{
				CertFile: "/nonexistent/cert.pem",
				KeyFile:  keyFile,
			},
			wantError: true,
		},
		{
			name: "missing key file",
			tlsConfig: &TLSConfig{
				CertFile: certFile,
				KeyFile:  "/nonexistent/key.pem",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ListenAddr: ":8080",
				PKIMount:   "pki",
				AuthConfig: &auth.Config{},
				EnrollmentConfig: &handlers.EnrollmentConfig{
					DefaultMount: "pki",
				},
			}

			srv, err := New(&backend.Client{}, cfg, slog.Default())
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			tlsConfig, err := srv.setupTLS(tt.tlsConfig)

			if tt.wantError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.wantError && tlsConfig == nil {
				t.Error("Expected TLS config but got nil")
			}

			// Verify TLS settings
			if !tt.wantError && tlsConfig != nil {
				if tlsConfig.MinVersion != tls.VersionTLS12 {
					t.Errorf("MinVersion = %d, want %d", tlsConfig.MinVersion, tls.VersionTLS12)
				}
				if len(tlsConfig.Certificates) != 1 {
					t.Errorf("Certificates count = %d, want 1", len(tlsConfig.Certificates))
				}
			}
		})
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && len(substr) > 0 && s[:len(substr)] == substr || len(s) > len(substr) && s[len(s)-len(substr):] == substr)
}

func createTestCertFiles(t *testing.T) (certFile, keyFile string, cleanup func()) {
	t.Helper()

	// Generate a test certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Write certificate
	certF, err := os.CreateTemp("", "cert-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp cert file: %v", err)
	}
	certFile = certF.Name()
	pem.Encode(certF, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certF.Close()

	// Write key
	keyF, err := os.CreateTemp("", "key-*.pem")
	if err != nil {
		os.Remove(certFile)
		t.Fatalf("Failed to create temp key file: %v", err)
	}
	keyFile = keyF.Name()
	pem.Encode(keyF, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyF.Close()

	cleanup = func() {
		os.Remove(certFile)
		os.Remove(keyFile)
	}

	return certFile, keyFile, cleanup
}
