//go:build integration
// +build integration

package backend

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	// Shared test infrastructure
	vaultContainer testcontainers.Container
	vaultAddr      string
	vaultToken     = "root-token"
	testBackend    Backend
	testLogger     *slog.Logger
)

// func init() {

// }

// TestMain sets up and tears down the test environment
func TestMain(m *testing.M) {
	ctx := context.Background()

	// Setup logger
	testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Start Vault container
	if err := setupVaultContainer(ctx); err != nil {
		testLogger.Error("Failed to setup Vault container", "error", err)
		os.Exit(1)
	}

	// Initialize PKI and auth
	if err := initializeVault(ctx); err != nil {
		testLogger.Error("Failed to initialize Vault", "error", err)
		vaultContainer.Terminate(ctx)
		os.Exit(1)
	}

	// Create test backend
	cfg := &Config{
		Address: vaultAddr,
		Token:   vaultToken,
		Type:    BackendTypeVault,
	}

	var err error
	testBackend, err = NewBackend(ctx, cfg, testLogger)
	if err != nil {
		testLogger.Error("Failed to create test backend", "error", err)
		vaultContainer.Terminate(ctx)
		os.Exit(1)
	}

	testLogger.Info("Integration test environment ready", "vault_addr", vaultAddr)

	// Run tests
	code := m.Run()

	// Cleanup
	if vaultContainer != nil {
		if err := vaultContainer.Terminate(ctx); err != nil {
			testLogger.Error("Failed to terminate Vault container", "error", err)
		}
	}

	os.Exit(code)
}

// setupVaultContainer starts a Vault container using testcontainers
func setupVaultContainer(ctx context.Context) error {
	req := testcontainers.ContainerRequest{
		Image:        "hashicorp/vault:1.15.0",
		ExposedPorts: []string{"8200/tcp"},
		Env: map[string]string{
			"VAULT_DEV_ROOT_TOKEN_ID":  vaultToken,
			"VAULT_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
			"VAULT_ADDR":               "http://0.0.0.0:8200",
		},
		WaitingFor: wait.ForLog("Vault server started!").WithStartupTimeout(30 * time.Second),
	}

	var err error
	vaultContainer, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	// Get mapped port
	host, err := vaultContainer.Host(ctx)
	if err != nil {
		return fmt.Errorf("failed to get container host: %w", err)
	}

	port, err := vaultContainer.MappedPort(ctx, "8200")
	if err != nil {
		return fmt.Errorf("failed to get mapped port: %w", err)
	}

	vaultAddr = fmt.Sprintf("http://%s:%s", host, port.Port())

	// Wait a bit more for Vault to be fully ready
	time.Sleep(2 * time.Second)

	return nil
}

// initializeVault configures PKI and auth methods in the test Vault instance
func initializeVault(ctx context.Context) error {
	apiConfig := api.DefaultConfig()
	apiConfig.Address = vaultAddr

	client, err := api.NewClient(apiConfig)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	client.SetToken(vaultToken)

	// Enable PKI secrets engine
	if err := client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h", // 10 years
		},
	}); err != nil {
		return fmt.Errorf("failed to mount PKI: %w", err)
	}

	// Generate root CA
	_, err = client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"common_name": "Test Root CA",
		"ttl":         "87600h",
		"key_type":    "rsa",
		"key_bits":    2048,
	})
	if err != nil {
		return fmt.Errorf("failed to generate root CA: %w", err)
	}

	// Configure CA and CRL URLs
	_, err = client.Logical().Write("pki/config/urls", map[string]interface{}{
		"issuing_certificates":    []string{vaultAddr + "/v1/pki/ca"},
		"crl_distribution_points": []string{vaultAddr + "/v1/pki/crl"},
	})
	if err != nil {
		return fmt.Errorf("failed to configure URLs: %w", err)
	}

	// Create a role for testing
	_, err = client.Logical().Write("pki/roles/test-role", map[string]interface{}{
		"allowed_domains":    []string{"example.com", "test.local"},
		"allow_subdomains":   true,
		"allow_bare_domains": true,
		"max_ttl":            "720h",
		"key_type":           "rsa",
		"key_bits":           2048,
	})
	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	// Create a role with shorter TTL for testing
	_, err = client.Logical().Write("pki/roles/short-ttl", map[string]interface{}{
		"allowed_domains":  []string{"short.example.com"},
		"allow_subdomains": true,
		"max_ttl":          "1h",
	})
	if err != nil {
		return fmt.Errorf("failed to create short-ttl role: %w", err)
	}

	// Enable userpass auth
	if err := client.Sys().EnableAuth("userpass", "userpass", ""); err != nil {
		return fmt.Errorf("failed to enable userpass: %w", err)
	}

	// Create test user
	_, err = client.Logical().Write("auth/userpass/users/testuser", map[string]interface{}{
		"password": "testpass",
		"policies": []string{"default"},
	})
	if err != nil {
		return fmt.Errorf("failed to create test user: %w", err)
	}

	// Create another test user for failure tests
	_, err = client.Logical().Write("auth/userpass/users/anotheruser", map[string]interface{}{
		"password": "anotherpass",
		"policies": []string{"default"},
	})
	if err != nil {
		return fmt.Errorf("failed to create another test user: %w", err)
	}

	// Enable cert auth
	if err := client.Sys().EnableAuth("cert", "cert", ""); err != nil {
		return fmt.Errorf("failed to enable cert auth: %w", err)
	}

	testLogger.Info("Vault initialization complete")
	return nil
}

// generateTestCSR creates a test CSR for certificate signing tests
func generateTestCSR(commonName string) (*x509.CertificateRequest, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Organization"},
			Country:      []string{"US"},
		},
		DNSNames: []string{commonName},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	return csr, key, nil
}

// Integration Tests

// TestIntegration_Health tests the health check with a real backend
func TestIntegration_Health(t *testing.T) {
	ctx := context.Background()

	health, err := testBackend.Health(ctx)
	if err != nil {
		t.Fatalf("Health() failed: %v", err)
	}

	if !health.Initialized {
		t.Error("Expected Vault to be initialized")
	}

	if health.Sealed {
		t.Error("Expected Vault to be unsealed")
	}

	if health.Version == "" {
		t.Error("Expected version to be set")
	}

	t.Logf("Vault version: %s", health.Version)
}

// TestIntegration_GetCACertificate tests retrieving the CA certificate
func TestIntegration_GetCACertificate(t *testing.T) {
	ctx := context.Background()

	cert, err := testBackend.GetCACertificate(ctx, "pki")
	if err != nil {
		t.Fatalf("GetCACertificate() failed: %v", err)
	}

	if cert == nil {
		t.Fatal("Expected certificate, got nil")
	}

	if cert.Subject.CommonName != "Test Root CA" {
		t.Errorf("Expected CN 'Test Root CA', got '%s'", cert.Subject.CommonName)
	}

	if !cert.IsCA {
		t.Error("Expected certificate to be a CA")
	}

	t.Logf("CA certificate: CN=%s, Serial=%s", cert.Subject.CommonName, cert.SerialNumber)
}

// TestIntegration_GetCACertificate_InvalidMount tests error handling for invalid mount
func TestIntegration_GetCACertificate_InvalidMount(t *testing.T) {
	ctx := context.Background()

	_, err := testBackend.GetCACertificate(ctx, "nonexistent")
	if err == nil {
		t.Fatal("Expected error for invalid mount, got nil")
	}

	t.Logf("Expected error: %v", err)
}

// TestIntegration_GetCAChain tests retrieving the full CA chain
func TestIntegration_GetCAChain(t *testing.T) {
	ctx := context.Background()

	chain, err := testBackend.GetCAChain(ctx, "pki")
	if err != nil {
		t.Fatalf("GetCAChain() failed: %v", err)
	}

	if len(chain) == 0 {
		t.Fatal("Expected at least one certificate in chain")
	}

	// First cert should be the CA
	if chain[0].Subject.CommonName != "Test Root CA" {
		t.Errorf("Expected first cert CN 'Test Root CA', got '%s'", chain[0].Subject.CommonName)
	}

	t.Logf("CA chain length: %d", len(chain))
}

// TestIntegration_SignCSR tests signing a CSR with a role
func TestIntegration_SignCSR(t *testing.T) {
	ctx := context.Background()

	csr, _, err := generateTestCSR("server.example.com")
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	cert, err := testBackend.SignCSR(ctx, "pki", "test-role", csr, "24h")
	if err != nil {
		t.Fatalf("SignCSR() failed: %v", err)
	}

	if cert == nil {
		t.Fatal("Expected certificate, got nil")
	}

	if cert.Subject.CommonName != "server.example.com" {
		t.Errorf("Expected CN 'server.example.com', got '%s'", cert.Subject.CommonName)
	}

	// Check validity period (should be ~24h)
	duration := cert.NotAfter.Sub(cert.NotBefore)
	if duration > 25*time.Hour || duration < 23*time.Hour {
		t.Errorf("Expected TTL ~24h, got %v", duration)
	}

	t.Logf("Signed certificate: CN=%s, Serial=%s, TTL=%v", cert.Subject.CommonName, cert.SerialNumber, duration)
}

// TestIntegration_SignCSR_WithCustomTTL tests signing with a custom TTL
func TestIntegration_SignCSR_WithCustomTTL(t *testing.T) {
	ctx := context.Background()

	csr, _, err := generateTestCSR("custom.example.com")
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	cert, err := testBackend.SignCSR(ctx, "pki", "test-role", csr, "48h")
	if err != nil {
		t.Fatalf("SignCSR() failed: %v", err)
	}

	duration := cert.NotAfter.Sub(cert.NotBefore)
	if duration > 49*time.Hour || duration < 47*time.Hour {
		t.Errorf("Expected TTL ~48h, got %v", duration)
	}

	t.Logf("Certificate TTL: %v", duration)
}

// TestIntegration_SignCSR_InvalidRole tests error handling for invalid role
func TestIntegration_SignCSR_InvalidRole(t *testing.T) {
	ctx := context.Background()

	csr, _, err := generateTestCSR("test.example.com")
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	_, err = testBackend.SignCSR(ctx, "pki", "nonexistent-role", csr, "")
	if err == nil {
		t.Fatal("Expected error for invalid role, got nil")
	}

	t.Logf("Expected error: %v", err)
}

// TestIntegration_SignCSR_InvalidDomain tests CSR with domain not allowed by role
func TestIntegration_SignCSR_InvalidDomain(t *testing.T) {
	ctx := context.Background()

	csr, _, err := generateTestCSR("invalid.notallowed.com")
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	_, err = testBackend.SignCSR(ctx, "pki", "test-role", csr, "")
	if err == nil {
		t.Fatal("Expected error for disallowed domain, got nil")
	}

	t.Logf("Expected error: %v", err)
}

// TestIntegration_SignCSRVerbatim tests signing without a role
func TestIntegration_SignCSRVerbatim(t *testing.T) {
	ctx := context.Background()

	csr, _, err := generateTestCSR("verbatim.test.local")
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	cert, err := testBackend.SignCSRVerbatim(ctx, "pki", csr, "12h")
	if err != nil {
		t.Fatalf("SignCSRVerbatim() failed: %v", err)
	}

	if cert == nil {
		t.Fatal("Expected certificate, got nil")
	}

	if cert.Subject.CommonName != "verbatim.test.local" {
		t.Errorf("Expected CN 'verbatim.test.local', got '%s'", cert.Subject.CommonName)
	}

	t.Logf("Verbatim signed certificate: CN=%s, Serial=%s", cert.Subject.CommonName, cert.SerialNumber)
}

// TestIntegration_GetIssuerPEM tests retrieving issuer certificate in PEM format
func TestIntegration_GetIssuerPEM(t *testing.T) {
	ctx := context.Background()

	// Get the default issuer (should be "default" or similar)
	pem, err := testBackend.GetIssuerPEM(ctx, "pki", "default")
	if err != nil {
		t.Fatalf("GetIssuerPEM() failed: %v", err)
	}

	if pem == "" {
		t.Fatal("Expected PEM data, got empty string")
	}

	// Verify it's valid PEM
	if len(pem) < 100 {
		t.Errorf("PEM data seems too short: %d bytes", len(pem))
	}

	if !contains(pem, "BEGIN CERTIFICATE") {
		t.Error("PEM data doesn't contain certificate header")
	}

	t.Logf("PEM certificate length: %d bytes", len(pem))
}

// TestIntegration_AuthenticateUserpass tests userpass authentication
func TestIntegration_AuthenticateUserpass(t *testing.T) {
	ctx := context.Background()

	token, err := testBackend.AuthenticateUserpass(ctx, "userpass", "testuser", "testpass")
	if err != nil {
		t.Fatalf("AuthenticateUserpass() failed: %v", err)
	}

	if token == "" {
		t.Fatal("Expected token, got empty string")
	}

	t.Logf("Received token: %s", token[:10]+"...")
}

// TestIntegration_AuthenticateUserpass_InvalidPassword tests authentication with wrong password
func TestIntegration_AuthenticateUserpass_InvalidPassword(t *testing.T) {
	ctx := context.Background()

	_, err := testBackend.AuthenticateUserpass(ctx, "userpass", "testuser", "wrongpassword")
	if err == nil {
		t.Fatal("Expected error for invalid password, got nil")
	}

	t.Logf("Expected error: %v", err)
}

// TestIntegration_AuthenticateUserpass_NonexistentUser tests authentication with non-existent user
func TestIntegration_AuthenticateUserpass_NonexistentUser(t *testing.T) {
	ctx := context.Background()

	_, err := testBackend.AuthenticateUserpass(ctx, "userpass", "nonexistent", "password")
	if err == nil {
		t.Fatal("Expected error for non-existent user, got nil")
	}

	t.Logf("Expected error: %v", err)
}

// TestIntegration_ValidateToken tests token validation
func TestIntegration_ValidateToken(t *testing.T) {
	ctx := context.Background()

	// Use the root token for testing
	valid, err := testBackend.ValidateToken(ctx, vaultToken)
	if err != nil {
		t.Fatalf("ValidateToken() failed: %v", err)
	}

	if !valid {
		t.Error("Expected root token to be valid")
	}
}

// TestIntegration_ValidateToken_Invalid tests validation of invalid token
func TestIntegration_ValidateToken_Invalid(t *testing.T) {
	ctx := context.Background()

	valid, err := testBackend.ValidateToken(ctx, "invalid-token-12345")
	if err != nil {
		t.Fatalf("ValidateToken() should not error on invalid token: %v", err)
	}

	if valid {
		t.Error("Expected invalid token to be rejected")
	}
}

// TestIntegration_LookupToken tests token lookup
func TestIntegration_LookupToken(t *testing.T) {
	ctx := context.Background()

	// Lookup root token
	data, err := testBackend.LookupToken(ctx, vaultToken)
	if err != nil {
		t.Fatalf("LookupToken() failed: %v", err)
	}

	if data == nil {
		t.Fatal("Expected token data, got nil")
	}

	// Check for expected fields
	if _, ok := data["id"]; !ok {
		t.Error("Expected 'id' field in token data")
	}

	t.Logf("Token data fields: %v", getMapKeys(data))
}

// TestIntegration_CloneWithToken tests creating a client with a different token
func TestIntegration_CloneWithToken(t *testing.T) {
	ctx := context.Background()

	// First authenticate to get a user token
	userToken, err := testBackend.AuthenticateUserpass(ctx, "userpass", "testuser", "testpass")
	if err != nil {
		t.Fatalf("Failed to get user token: %v", err)
	}

	// Clone backend with user token
	cloned, err := testBackend.CloneWithToken(ctx, userToken)
	if err != nil {
		t.Fatalf("CloneWithToken() failed: %v", err)
	}

	if cloned == nil {
		t.Fatal("Expected cloned backend, got nil")
	}

	// Verify cloned backend works
	health, err := cloned.Health(ctx)
	if err != nil {
		t.Fatalf("Cloned backend Health() failed: %v", err)
	}

	if !health.Initialized {
		t.Error("Expected cloned backend to work")
	}

	// Verify it's using the user token by looking it up
	tokenData, err := cloned.LookupToken(ctx, userToken)
	if err != nil {
		t.Fatalf("Failed to lookup user token: %v", err)
	}

	if tokenData == nil {
		t.Fatal("Expected token data")
	}

	t.Logf("Cloned backend works with user token")
}

// TestIntegration_Type tests backend type reporting
func TestIntegration_Type(t *testing.T) {
	backendType := testBackend.Type()

	if backendType != BackendTypeVault {
		t.Errorf("Expected BackendTypeVault, got %v", backendType)
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
