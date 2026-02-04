//go:build integration
// +build integration

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
	"github.com/mabunixda/est-service/pkg/est"
	"github.com/mabunixda/est-service/pkg/handlers"
	"github.com/mabunixda/est-service/pkg/server"
	"github.com/openbao/openbao/api/v2"
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

	apiClient := e.Backend.GetAPIClient()

	// Enable PKI mount
	err := apiClient.Sys().Mount(e.PKIMount, &api.MountInput{
		Type:        "pki",
		Description: "Test PKI for EST integration tests",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		t.Fatalf("Failed to enable PKI mount: %v", err)
	}

	// Generate root CA
	_, err = apiClient.Logical().Write(e.PKIMount+"/root/generate/internal", map[string]interface{}{
		"common_name":  "EST Test CA",
		"issuer_name":  "est-test-root-ca",
		"ttl":          "87600h",
		"organization": "EST Test",
		"country":      "US",
	})
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// Configure URLs
	_, err = apiClient.Logical().Write(e.PKIMount+"/config/urls", map[string]interface{}{
		"issuing_certificates":    apiClient.Address() + "/v1/" + e.PKIMount + "/ca",
		"crl_distribution_points": apiClient.Address() + "/v1/" + e.PKIMount + "/crl",
	})
	if err != nil {
		t.Logf("Warning: Failed to configure URLs: %v", err)
	}

	// Create PKI role for EST devices
	_, err = apiClient.Logical().Write(e.PKIMount+"/roles/est-devices", map[string]interface{}{
		"allowed_domains":  []string{"example.com", "test.local"},
		"allow_subdomains": true,
		"max_ttl":          "48h",
		"ttl":              "24h",
		"key_type":         "rsa",
		"key_bits":         2048,
		"require_cn":       true,
	})
	if err != nil {
		t.Fatalf("Failed to create est-devices role: %v", err)
	}

	// Create additional roles for testing
	_, err = apiClient.Logical().Write(e.PKIMount+"/roles/est-servers", map[string]interface{}{
		"allowed_domains":  []string{"example.com"},
		"allow_subdomains": true,
		"max_ttl":          "720h",
		"key_type":         "rsa",
		"key_bits":         2048,
	})
	if err != nil {
		t.Logf("Warning: Failed to create est-servers role: %v", err)
	}

	_, err = apiClient.Logical().Write(e.PKIMount+"/roles/est-users", map[string]interface{}{
		"allowed_domains":  []string{"example.com"},
		"allow_subdomains": true,
		"max_ttl":          "168h",
		"key_type":         "rsa",
		"key_bits":         2048,
	})
	if err != nil {
		t.Logf("Warning: Failed to create est-users role: %v", err)
	}

	// Create test-role for reenrollment tests
	_, err = apiClient.Logical().Write(e.PKIMount+"/roles/test-role", map[string]interface{}{
		"allowed_domains":  []string{"example.com", "test.local"},
		"allow_subdomains": true,
		"max_ttl":          "48h",
		"ttl":              "24h",
		"key_type":         "rsa",
		"key_bits":         2048,
		"require_cn":       false,
	})
	if err != nil {
		t.Fatalf("Failed to create test-role: %v", err)
	}

	// Enable userpass auth if not already enabled
	err = apiClient.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type:        "userpass",
		Description: "Test userpass auth",
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		t.Fatalf("Failed to enable userpass auth: %v", err)
	}

	// Create policy for EST operations
	policyRules := `
path "` + e.PKIMount + `/sign/*" {
	capabilities = ["create", "update"]
}

path "` + e.PKIMount + `/sign-verbatim" {
	capabilities = ["create", "update"]
}

path "` + e.PKIMount + `/ca" {
	capabilities = ["read"]
}

path "` + e.PKIMount + `/ca/pem" {
	capabilities = ["read"]
}

path "` + e.PKIMount + `/ca_chain" {
	capabilities = ["read"]
}

path "` + e.PKIMount + `/cert/ca_chain" {
	capabilities = ["read"]
}
`

	err = apiClient.Sys().PutPolicy("est-test-policy", policyRules)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	// Create test user
	_, err = apiClient.Logical().Write("auth/userpass/users/est-device", map[string]interface{}{
		"password":       "device-secret-123",
		"token_ttl":      "1h",
		"token_policies": []string{"est-test-policy"},
	})
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create testuser for reenrollment tests
	_, err = apiClient.Logical().Write("auth/userpass/users/testuser", map[string]interface{}{
		"password":       "testpass",
		"token_ttl":      "1h",
		"token_policies": []string{"est-test-policy"},
	})
	if err != nil {
		t.Fatalf("Failed to create testuser: %v", err)
	}

	// Add cleanup function to disable mounts
	e.CleanupFuncs = append([]func(){func() {
		apiClient.Sys().Unmount(e.PKIMount)
	}}, e.CleanupFuncs...)

	t.Logf("PKI backend configured at: %s", e.PKIMount)
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

	// EST RFC 7030 requires base64-encoded DER CSR
	csrB64 := base64.StdEncoding.EncodeToString(csr.Raw)

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

	// Decode response - EST returns base64-encoded PKCS#7
	bodyB64, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	bodyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(bodyB64)))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 response: %w", err)
	}

	// EST returns PKCS#7 with certificates
	certs, err := est.ParsePKCS7(bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 response: %w", err)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates in PKCS#7 response")
	}

	// Return the first certificate (the issued certificate)
	return certs[0], nil
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

	// EST RFC 7030 requires base64-encoded DER CSR
	csrB64 := base64.StdEncoding.EncodeToString(csr.Raw)

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

	// Decode response - EST returns base64-encoded PKCS#7
	bodyB64, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	bodyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(bodyB64)))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 response: %w", err)
	}

	// EST returns PKCS#7 with certificates
	certs, err := est.ParsePKCS7(bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 response: %w", err)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates in PKCS#7 response")
	}

	// Return the first certificate (the issued certificate)
	return certs[0], nil
}
