package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mabunixda/est-service/pkg/auth"
	"github.com/mabunixda/est-service/pkg/backend"
	"github.com/mabunixda/est-service/pkg/handlers"
	"github.com/mabunixda/est-service/pkg/server"
)

// TestEnvironment holds the test setup
type TestEnvironment struct {
	Backend      *backend.Client
	Server       *httptest.Server
	ServerURL    string
	RootToken    string
	PKIMount     string
	Logger       *slog.Logger
	CleanupFuncs []func()
}

// Setup creates a test environment
func Setup(t *testing.T) *TestEnvironment {
	t.Helper()

	// Check if backend is available
	backendAddr := os.Getenv("VAULT_ADDR")
	if backendAddr == "" {
		backendAddr = os.Getenv("BAO_ADDR")
	}
	if backendAddr == "" {
		t.Skip("No backend available (set VAULT_ADDR or BAO_ADDR)")
	}

	rootToken := os.Getenv("VAULT_TOKEN")
	if rootToken == "" {
		rootToken = os.Getenv("BAO_TOKEN")
	}
	if rootToken == "" {
		t.Skip("No backend token available (set VAULT_TOKEN or BAO_TOKEN)")
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create backend client
	backendCfg := &backend.Config{
		Address: backendAddr,
		Token:   rootToken,
	}

	ctx := context.Background()
	backendClient, err := backend.NewClient(ctx, backendCfg, logger)
	if err != nil {
		t.Fatalf("Failed to create backend client: %v", err)
	}

	// Verify backend health
	_, err = backendClient.Health(ctx)
	if err != nil {
		t.Fatalf("Backend not healthy: %v", err)
	}

	env := &TestEnvironment{
		Backend:      backendClient,
		RootToken:    rootToken,
		PKIMount:     "pki-test",
		Logger:       logger,
		CleanupFuncs: []func(){},
	}

	// Setup PKI backend for testing
	env.setupPKI(t)

	return env
}

// Cleanup tears down the test environment
func (e *TestEnvironment) Cleanup(t *testing.T) {
	t.Helper()
	for i := len(e.CleanupFuncs) - 1; i >= 0; i-- {
		e.CleanupFuncs[i]()
	}
	if e.Server != nil {
		e.Server.Close()
	}
}

// setupPKI configures a PKI backend for testing
func (e *TestEnvironment) setupPKI(t *testing.T) {
	t.Helper()

	// Note: In real test, you'd enable PKI mount, create CA, etc.
	// For now, assume PKI is already configured via setup scripts
	t.Logf("Using PKI mount: %s", e.PKIMount)
}

// StartServer starts a test EST server
func (e *TestEnvironment) StartServer(t *testing.T, config *handlers.EnrollmentConfig) {
	t.Helper()

	authCfg := &auth.Config{
		UserpassEnabled:   true,
		UserpassMountPath: "userpass",
		CertEnabled:       true,
		CertMountPath:     "cert",
		TokenEnabled:      true,
	}

	authMgr := auth.NewManager(e.Backend, authCfg, e.Logger)

	serverCfg := &server.Config{
		PKIMount:         e.PKIMount,
		AuthConfig:       authCfg,
		EnrollmentConfig: config,
	}

	srv, err := server.New(e.Backend, serverCfg, e.Logger)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create test server
	mux := http.NewServeMux()

	// Register handlers
	cacertsHandler := handlers.NewCACertsHandler(e.Backend, e.PKIMount, e.Logger)
	mux.Handle("/.well-known/est/cacerts", cacertsHandler)

	enrollHandler := handlers.NewSimpleEnrollHandler(e.Backend, authMgr, config, e.Logger, nil)
	mux.Handle("/.well-known/est/simpleenroll", enrollHandler)

	reenrollHandler := handlers.NewSimpleReenrollHandler(e.Backend, authMgr, config, e.Logger, nil)
	mux.Handle("/.well-known/est/simplereenroll", reenrollHandler)

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	e.Server = httptest.NewServer(mux)
	e.ServerURL = e.Server.URL

	e.CleanupFuncs = append(e.CleanupFuncs, func() {
		srv.Shutdown(context.Background())
	})
}

// GenerateCSR creates a test CSR
func GenerateCSR(t *testing.T, cn string) (*x509.CertificateRequest, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	return csr, key
}

// EncodeCSR encodes a CSR to PEM format
func EncodeCSR(csr *x509.CertificateRequest) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	})
}

// EnrollCertificate performs an enrollment request
func (e *TestEnvironment) EnrollCertificate(t *testing.T, csr *x509.CertificateRequest, authHeader string) (*x509.Certificate, error) {
	t.Helper()

	csrPEM := EncodeCSR(csr)
	csrB64 := base64.StdEncoding.EncodeToString(csrPEM)

	req, err := http.NewRequest("POST", e.ServerURL+"/.well-known/est/simpleenroll",
		strings.NewReader(csrB64))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Content-Transfer-Encoding", "base64")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("enrollment failed: %d - %s", resp.StatusCode, string(body))
	}

	// Decode response
	bodyB64, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	bodyBytes, err := base64.StdEncoding.DecodeString(string(bodyB64))
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Parse PKCS#7
	// For simplicity, assume first PEM block contains cert
	block, _ := pem.Decode(bodyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// Helper to create TLS config with client cert
func CreateTLSConfig(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey) *tls.Config {
	t.Helper()

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to create TLS cert: %v", err)
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
	}
}

// ReenrollCertificate performs a reenrollment request
func (e *TestEnvironment) ReenrollCertificate(t *testing.T, csr *x509.CertificateRequest, authHeader string, oldCert *x509.Certificate) (*x509.Certificate, error) {
	t.Helper()

	csrPEM := EncodeCSR(csr)
	csrB64 := base64.StdEncoding.EncodeToString(csrPEM)

	req, err := http.NewRequest("POST", e.ServerURL+"/.well-known/est/simplereenroll",
		strings.NewReader(csrB64))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Content-Transfer-Encoding", "base64")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("reenrollment failed: %d - %s", resp.StatusCode, string(body))
	}

	// Decode response
	bodyB64, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	bodyBytes, err := base64.StdEncoding.DecodeString(string(bodyB64))
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Parse PKCS#7
	block, _ := pem.Decode(bodyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
