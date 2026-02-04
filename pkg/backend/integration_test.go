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
)

var (
	// Shared test infrastructure
	vaultAddr   string
	vaultToken  string
	testBackend Backend
	testLogger  *slog.Logger
	pkiMount    string // Configurable PKI mount path for tests
)

// TestMain sets up and tears down the test environment
func TestMain(m *testing.M) {
	ctx := context.Background()

	// Setup logger
	testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Get Vault/OpenBao connection info from environment
	vaultAddr = os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = os.Getenv("BAO_ADDR")
	}
	if vaultAddr == "" {
		testLogger.Error("VAULT_ADDR or BAO_ADDR environment variable not set")
		testLogger.Info("Integration tests require a running Vault or OpenBao instance")
		testLogger.Info("Set VAULT_ADDR/BAO_ADDR and VAULT_TOKEN/BAO_TOKEN environment variables")
		os.Exit(1)
	}

	vaultToken = os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		vaultToken = os.Getenv("BAO_TOKEN")
	}
	if vaultToken == "" {
		testLogger.Error("VAULT_TOKEN or BAO_TOKEN environment variable not set")
		os.Exit(1)
	}

	testLogger.Info("Using existing Vault/OpenBao instance",
		"addr", vaultAddr,
		"token_prefix", vaultToken[:min(10, len(vaultToken))]+"...")

	// Get PKI mount path from environment or use default
	pkiMount = os.Getenv("PKI_MOUNT_PATH")
	if pkiMount == "" {
		pkiMount = "pki-backend-test" // Default separate mount for backend tests
	}
	testLogger.Info("Using PKI mount", "mount", pkiMount)

	// Initialize PKI and auth (idempotent - safe to run multiple times)
	if err := initializeVault(ctx); err != nil {
		testLogger.Error("Failed to initialize Vault", "error", err)
		os.Exit(1)
	}

	// Determine backend type from environment or auto-detect
	backendTypeStr := os.Getenv("BACKEND_TYPE")
	var backendType BackendType
	if backendTypeStr != "" {
		backendType = BackendType(backendTypeStr)
	} else {
		backendType = BackendTypeAuto // Auto-detect
	}

	// Create test backend
	cfg := &Config{
		Address: vaultAddr,
		Token:   vaultToken,
		Type:    backendType,
	}

	var err error
	testBackend, err = NewBackend(ctx, cfg, testLogger)
	if err != nil {
		testLogger.Error("Failed to create test backend", "error", err)
		os.Exit(1)
	}

	testLogger.Info("Integration test environment ready",
		"vault_addr", vaultAddr,
		"backend_type", testBackend.Type())

	// Run tests
	code := m.Run()

	os.Exit(code)
}

// initializeVault configures PKI and auth methods in the Vault instance
// This function is idempotent - it's safe to run multiple times
func initializeVault(ctx context.Context) error {
	apiConfig := api.DefaultConfig()
	apiConfig.Address = vaultAddr

	// Handle TLS verification
	if os.Getenv("VAULT_SKIP_VERIFY") == "true" {
		// For dev/test environments only
		testLogger.Warn("TLS verification disabled (VAULT_SKIP_VERIFY=true)")
	}

	client, err := api.NewClient(apiConfig)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	client.SetToken(vaultToken)

	// Check if PKI mount already exists
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("failed to list mounts: %w", err)
	}

	pkiMountPath := pkiMount + "/"
	pkiExists := false
	if _, ok := mounts[pkiMountPath]; ok {
		pkiExists = true
		testLogger.Info("PKI mount already exists, skipping creation", "mount", pkiMount)
	}

	if !pkiExists {
		// Enable PKI secrets engine
		if err := client.Sys().Mount(pkiMount, &api.MountInput{
			Type: "pki",
			Config: api.MountConfigInput{
				MaxLeaseTTL: "87600h", // 10 years
			},
		}); err != nil {
			return fmt.Errorf("failed to mount PKI: %w", err)
		}
		testLogger.Info("Created PKI mount", "mount", pkiMount)
	}

	// Check if root CA exists (idempotent check)
	caResp, err := client.Logical().Read(pkiMount + "/cert/ca")
	if err != nil {
		// Error might mean mount doesn't have a CA yet, which is fine
		testLogger.Debug("No existing CA found", "error", err)
	}

	caExists := false
	if caResp != nil && caResp.Data != nil {
		if certPEM, ok := caResp.Data["certificate"].(string); ok && len(certPEM) > 100 {
			caExists = true
			testLogger.Info("Root CA already exists, skipping generation", "mount", pkiMount)
		}
	}

	if !caExists {
		// Generate root CA
		_, err = client.Logical().Write(pkiMount+"/root/generate/internal", map[string]interface{}{
			"common_name": "Test Root CA",
			"ttl":         "87600h",
			"key_type":    "rsa",
			"key_bits":    2048,
		})
		if err != nil {
			return fmt.Errorf("failed to generate root CA: %w", err)
		}
		testLogger.Info("Generated root CA", "mount", pkiMount)

		// Configure CA and CRL URLs
		_, err = client.Logical().Write(pkiMount+"/config/urls", map[string]interface{}{
			"issuing_certificates":    []string{vaultAddr + "/v1/" + pkiMount + "/ca"},
			"crl_distribution_points": []string{vaultAddr + "/v1/" + pkiMount + "/crl"},
		})
		if err != nil {
			return fmt.Errorf("failed to configure URLs: %w", err)
		}
	}

	// Create/update roles (idempotent)
	_, err = client.Logical().Write(pkiMount+"/roles/test-role", map[string]interface{}{
		"allowed_domains":    []string{"example.com", "test.local"},
		"allow_subdomains":   true,
		"allow_bare_domains": true,
		"max_ttl":            "720h",
		"key_type":           "rsa",
		"key_bits":           2048,
	})
	if err != nil {
		return fmt.Errorf("failed to create/update test-role: %w", err)
	}

	_, err = client.Logical().Write(pkiMount+"/roles/short-ttl", map[string]interface{}{
		"allowed_domains":  []string{"short.example.com"},
		"allow_subdomains": true,
		"max_ttl":          "1h",
	})
	if err != nil {
		return fmt.Errorf("failed to create/update short-ttl role: %w", err)
	}

	// Check if userpass auth already exists
	auths, err := client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("failed to list auth methods: %w", err)
	}

	userpassExists := false
	if _, ok := auths["userpass/"]; ok {
		userpassExists = true
		testLogger.Info("Userpass auth already exists, skipping creation")
	}

	if !userpassExists {
		// Enable userpass auth
		if err := client.Sys().EnableAuth("userpass", "userpass", ""); err != nil {
			return fmt.Errorf("failed to enable userpass: %w", err)
		}
		testLogger.Info("Enabled userpass auth")
	}

	// Create/update test users (idempotent)
	_, err = client.Logical().Write("auth/userpass/users/testuser", map[string]interface{}{
		"password": "testpass",
		"policies": []string{"default"},
	})
	if err != nil {
		return fmt.Errorf("failed to create/update testuser: %w", err)
	}

	_, err = client.Logical().Write("auth/userpass/users/anotheruser", map[string]interface{}{
		"password": "anotherpass",
		"policies": []string{"default"},
	})
	if err != nil {
		return fmt.Errorf("failed to create/update anotheruser: %w", err)
	}

	// Check if cert auth already exists
	certExists := false
	if _, ok := auths["cert/"]; ok {
		certExists = true
		testLogger.Info("Cert auth already exists, skipping creation")
	}

	if !certExists {
		// Enable cert auth
		if err := client.Sys().EnableAuth("cert", "cert", ""); err != nil {
			return fmt.Errorf("failed to enable cert auth: %w", err)
		}
		testLogger.Info("Enabled cert auth")
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

	cert, err := testBackend.GetCACertificate(ctx, pkiMount)
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

	chain, err := testBackend.GetCAChain(ctx, pkiMount)
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

	cert, err := testBackend.SignCSR(ctx, pkiMount, "test-role", csr, "24h")
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

	cert, err := testBackend.SignCSR(ctx, pkiMount, "test-role", csr, "48h")
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

	_, err = testBackend.SignCSR(ctx, pkiMount, "nonexistent-role", csr, "")
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

	_, err = testBackend.SignCSR(ctx, pkiMount, "test-role", csr, "")
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

	cert, err := testBackend.SignCSRVerbatim(ctx, pkiMount, csr, "12h")
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
	pem, err := testBackend.GetIssuerPEM(ctx, pkiMount, "default")
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

	t.Logf("Received token: %s", token[:min(10, len(token))]+"...")
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

	// Should be either Vault or OpenBao depending on what's running
	if backendType != BackendTypeVault && backendType != BackendTypeOpenBao {
		t.Errorf("Expected BackendTypeVault or BackendTypeOpenBao, got %v", backendType)
	}

	t.Logf("Backend type: %s", backendType)
}

// Helper functions

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

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
