package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
)

// TestSimpleReenrollWorkflow_Success tests a complete successful re-enrollment
func TestSimpleReenrollWorkflow_Success(t *testing.T) {
	// Generate existing client certificate and key
	clientCert, clientKey := generateTestClientCert(t)

	// Create a CSR with the same key
	csrDER := generateTestCSRWithKey(t, clientKey)

	// Setup mock backend
	mock := &backend.MockBackend{
		AuthenticateCertFunc: func(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
			if connState != nil && len(connState.PeerCertificates) > 0 {
				return "cert-token-123", nil
			}
			return "", fmt.Errorf("no client certificate")
		},
		CloneWithTokenFunc: func(ctx context.Context, token string) (backend.Backend, error) {
			return &backend.MockBackend{
				SignCSRFunc: func(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
					return generateTestCertFromCSR(csr)
				},
			}, nil
		},
	}

	authMgr := auth.NewManager(mock, &auth.Config{
		CertEnabled:   true,
		CertMountPath: "cert",
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "est",
		},
	}

	handler := NewSimpleReenrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	// Create request with TLS client certificate
	req := httptest.NewRequest("POST", "/.well-known/est/simplereenroll", bytes.NewReader(csrDER))
	req.Header.Set("Content-Type", "application/pkcs10")

	// Add TLS connection state with client cert
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify response is base64-encoded PKCS#7
	if w.Header().Get("Content-Type") != "application/pkcs7-mime; smime-type=certs-only" {
		t.Errorf("Expected PKCS#7 content type, got %s", w.Header().Get("Content-Type"))
	}
}

// TestSimpleReenrollWorkflow_WithBasicAuth tests re-enrollment with Basic Auth instead of cert
func TestSimpleReenrollWorkflow_WithBasicAuth(t *testing.T) {
	_, clientKey := generateTestClientCert(t)
	csrDER := generateTestCSRWithKey(t, clientKey)

	mock := &backend.MockBackend{
		AuthenticateUserpassFunc: func(ctx context.Context, mount, username, password string) (string, error) {
			if username == "testuser" && password == "testpass" {
				return "test-token", nil
			}
			return "", fmt.Errorf("invalid credentials")
		},
		CloneWithTokenFunc: func(ctx context.Context, token string) (backend.Backend, error) {
			return &backend.MockBackend{
				SignCSRFunc: func(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
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
			Type:  "role",
			Value: "est",
		},
	}

	handler := NewSimpleReenrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	req := httptest.NewRequest("POST", "/.well-known/est/simplereenroll", bytes.NewReader(csrDER))
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testuser:testpass")))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSimpleReenrollWorkflow_NoAuth tests re-enrollment without authentication
func TestSimpleReenrollWorkflow_NoAuth(t *testing.T) {
	_, clientKey := generateTestClientCert(t)
	csrDER := generateTestCSRWithKey(t, clientKey)

	mock := &backend.MockBackend{}
	authMgr := auth.NewManager(mock, &auth.Config{
		CertEnabled:     true,
		UserpassEnabled: true,
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
	}

	handler := NewSimpleReenrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	req := httptest.NewRequest("POST", "/.well-known/est/simplereenroll", bytes.NewReader(csrDER))
	// No auth provided

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

// TestSimpleReenrollWorkflow_InvalidCSR tests re-enrollment with malformed CSR
func TestSimpleReenrollWorkflow_InvalidCSR(t *testing.T) {
	clientCert, _ := generateTestClientCert(t)

	mock := &backend.MockBackend{
		AuthenticateCertFunc: func(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
			return "cert-token", nil
		},
	}

	authMgr := auth.NewManager(mock, &auth.Config{
		CertEnabled: true,
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
	}

	handler := NewSimpleReenrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	req := httptest.NewRequest("POST", "/.well-known/est/simplereenroll", bytes.NewReader([]byte("invalid csr")))
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// TestSimpleReenrollWorkflow_BackendError tests re-enrollment when backend fails
func TestSimpleReenrollWorkflow_BackendError(t *testing.T) {
	clientCert, clientKey := generateTestClientCert(t)
	csrDER := generateTestCSRWithKey(t, clientKey)

	mock := &backend.MockBackend{
		AuthenticateCertFunc: func(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
			return "cert-token", nil
		},
		CloneWithTokenFunc: func(ctx context.Context, token string) (backend.Backend, error) {
			return &backend.MockBackend{
				SignCSRFunc: func(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
					return nil, fmt.Errorf("PKI backend unavailable")
				},
			}, nil
		},
	}

	authMgr := auth.NewManager(mock, &auth.Config{
		CertEnabled: true,
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "est",
		},
	}

	handler := NewSimpleReenrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	req := httptest.NewRequest("POST", "/.well-known/est/simplereenroll", bytes.NewReader(csrDER))
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 502 { // Backend unavailable returns 502
		t.Errorf("Expected status 502, got %d", w.Code)
	}
}

// TestSimpleReenrollWorkflow_WithCustomTTL tests re-enrollment with custom TTL
func TestSimpleReenrollWorkflow_WithCustomTTL(t *testing.T) {
	clientCert, clientKey := generateTestClientCert(t)
	csrDER := generateTestCSRWithKey(t, clientKey)

	ttlUsed := ""

	mock := &backend.MockBackend{
		AuthenticateCertFunc: func(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
			return "cert-token", nil
		},
		CloneWithTokenFunc: func(ctx context.Context, token string) (backend.Backend, error) {
			return &backend.MockBackend{
				SignCSRFunc: func(ctx context.Context, mount, role string, csr *x509.CertificateRequest, ttl string) (*x509.Certificate, error) {
					ttlUsed = ttl
					return generateTestCertFromCSR(csr)
				},
			}, nil
		},
	}

	authMgr := auth.NewManager(mock, &auth.Config{
		CertEnabled: true,
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "est",
			TTL:   "720h",
		},
	}

	handler := NewSimpleReenrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	req := httptest.NewRequest("POST", "/.well-known/est/simplereenroll", bytes.NewReader(csrDER))
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if ttlUsed != "720h" {
		t.Errorf("Expected TTL 720h, got %s", ttlUsed)
	}
}

// Helper: generate a test client certificate
func generateTestClientCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test-client.example.com",
			Organization: []string{"Test Org"},
		},
		DNSNames:              []string{"test-client.example.com"}, // Must match CSR SANs for RFC 7030
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, priv
}

// Helper: generate a CSR using an existing key
func generateTestCSRWithKey(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test-client.example.com",
			Organization: []string{"Test Org"},
		},
		DNSNames: []string{"test-client.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Return base64-encoded DER
	return []byte(base64.StdEncoding.EncodeToString(csrDER))
}

// Helper: generate a CSR with custom subject/SANs
func generateTestCSRWithSubject(t *testing.T, priv *ecdsa.PrivateKey, subject pkix.Name, dnsNames []string) []byte {
	t.Helper()

	template := x509.CertificateRequest{
		Subject:  subject,
		DNSNames: dnsNames,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	// Return base64-encoded DER
	return []byte(base64.StdEncoding.EncodeToString(csrDER))
}

// TestSimpleReenrollWorkflow_SubjectMismatch tests RFC 7030 Subject validation
func TestSimpleReenrollWorkflow_SubjectMismatch(t *testing.T) {
	// Generate existing client certificate
	clientCert, clientKey := generateTestClientCert(t)

	// Create a CSR with DIFFERENT subject (should fail RFC 7030 validation)
	csrDER := generateTestCSRWithSubject(t, clientKey,
		pkix.Name{
			CommonName:   "different.example.com", // Different from cert
			Organization: []string{"Different Org"},
		},
		[]string{"different.example.com"},
	)

	mock := &backend.MockBackend{
		AuthenticateCertFunc: func(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
			return "cert-token-123", nil
		},
	}

	authMgr := auth.NewManager(mock, &auth.Config{
		CertEnabled:   true,
		CertMountPath: "cert",
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "est",
		},
	}

	handler := NewSimpleReenrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	req := httptest.NewRequest("POST", "/.well-known/est/simplereenroll", bytes.NewReader(csrDER))
	req.Header.Set("Content-Type", "application/pkcs10")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should reject with 400 Bad Request due to Subject mismatch
	if w.Code != 400 {
		t.Errorf("Expected status 400 for subject mismatch, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSimpleReenrollWorkflow_SANMismatch tests RFC 7030 SubjectAltName validation
func TestSimpleReenrollWorkflow_SANMismatch(t *testing.T) {
	// Generate existing client certificate
	clientCert, clientKey := generateTestClientCert(t)

	// Create a CSR with same subject but DIFFERENT SANs (should fail RFC 7030 validation)
	csrDER := generateTestCSRWithSubject(t, clientKey,
		pkix.Name{
			CommonName:   "test-client.example.com", // Same as cert
			Organization: []string{"Test Org"},
		},
		[]string{"different-san.example.com"}, // Different SANs
	)

	mock := &backend.MockBackend{
		AuthenticateCertFunc: func(ctx context.Context, mount string, connState *tls.ConnectionState, role, entityAliasPrefix, tokenTTL string) (string, error) {
			return "cert-token-123", nil
		},
	}

	authMgr := auth.NewManager(mock, &auth.Config{
		CertEnabled:   true,
		CertMountPath: "cert",
	}, slog.Default())

	config := &EnrollmentConfig{
		DefaultMount: "pki",
		DefaultPolicy: LabelPolicy{
			Type:  "role",
			Value: "est",
		},
	}

	handler := NewSimpleReenrollHandler(mock, authMgr, config, slog.Default(), &mockTelemetry{})

	req := httptest.NewRequest("POST", "/.well-known/est/simplereenroll", bytes.NewReader(csrDER))
	req.Header.Set("Content-Type", "application/pkcs10")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should reject with 400 Bad Request due to SAN mismatch
	if w.Code != 400 {
		t.Errorf("Expected status 400 for SAN mismatch, got %d: %s", w.Code, w.Body.String())
	}
}
