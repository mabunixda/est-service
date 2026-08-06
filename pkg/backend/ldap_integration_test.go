//go:build integration
// +build integration

package backend

import (
	"context"
	"os"
	"testing"

	"github.com/openbao/openbao/api/v2"
)

// setupLDAP configures LDAP auth method if LDAP server is available
// Returns true if LDAP is configured and ready, false if LDAP tests should be skipped
func setupLDAP(t *testing.T, ctx context.Context, client *api.Client) bool {
	t.Helper()

	// Check if LDAP test credentials are provided
	ldapURL := os.Getenv("LDAP_URL")
	ldapBindDN := os.Getenv("LDAP_BIND_DN")
	ldapBindPass := os.Getenv("LDAP_BIND_PASS")
	ldapUserDN := os.Getenv("LDAP_USER_DN")

	if ldapURL == "" || ldapBindDN == "" || ldapBindPass == "" || ldapUserDN == "" {
		t.Log("Skipping LDAP tests: LDAP_URL, LDAP_BIND_DN, LDAP_BIND_PASS, or LDAP_USER_DN not set")
		t.Log("To enable LDAP tests, set environment variables:")
		t.Log("  LDAP_URL=ldap://localhost:389")
		t.Log("  LDAP_BIND_DN=cn=admin,dc=example,dc=com")
		t.Log("  LDAP_BIND_PASS=adminpassword")
		t.Log("  LDAP_USER_DN=ou=users,dc=example,dc=com")
		t.Log("  LDAP_TEST_USER=testuser")
		t.Log("  LDAP_TEST_PASS=testpass")
		return false
	}

	// Check if ldap auth is already enabled
	auths, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatalf("Failed to list auth methods: %v", err)
	}

	ldapExists := false
	if _, ok := auths["ldap/"]; ok {
		ldapExists = true
		testLogger.Info("LDAP auth already exists")
	}

	if !ldapExists {
		// Enable LDAP auth method
		if err := client.Sys().EnableAuth("ldap", "ldap", ""); err != nil {
			t.Fatalf("Failed to enable ldap auth: %v", err)
		}
		testLogger.Info("Enabled LDAP auth")
	}

	// Configure LDAP
	_, err = client.Logical().WriteWithContext(ctx, "auth/ldap/config", map[string]interface{}{
		"url":          ldapURL,
		"binddn":       ldapBindDN,
		"bindpass":     ldapBindPass,
		"userdn":       ldapUserDN,
		"userattr":     "uid",
		"insecure_tls": true, // For testing only
	})
	if err != nil {
		t.Logf("Warning: Failed to configure LDAP: %v", err)
		t.Log("LDAP tests will be skipped")
		return false
	}

	testLogger.Info("Configured LDAP auth", "url", ldapURL)
	return true
}

// TestIntegration_AuthenticateLDAP tests LDAP authentication
func TestIntegration_AuthenticateLDAP(t *testing.T) {
	ctx := context.Background()

	// Setup LDAP
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	if !setupLDAP(t, ctx, client) {
		t.Skip("LDAP not available, skipping test")
	}

	// Get test credentials
	ldapUser := os.Getenv("LDAP_TEST_USER")
	ldapPass := os.Getenv("LDAP_TEST_PASS")

	if ldapUser == "" || ldapPass == "" {
		t.Skip("LDAP_TEST_USER or LDAP_TEST_PASS not set, skipping test")
	}

	// Test authentication
	token, err := testBackend.AuthenticateLDAP(ctx, "ldap", ldapUser, ldapPass)
	if err != nil {
		t.Fatalf("AuthenticateLDAP() failed: %v", err)
	}

	if token == "" {
		t.Fatal("Expected token, got empty string")
	}

	// Verify the token works
	valid, err := testBackend.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("ValidateToken() failed: %v", err)
	}

	if !valid {
		t.Error("Expected LDAP token to be valid")
	}

	t.Logf("LDAP authentication successful: token=%s...", token[:min(10, len(token))])
}

// TestIntegration_AuthenticateLDAP_InvalidPassword tests error handling for invalid password
func TestIntegration_AuthenticateLDAP_InvalidPassword(t *testing.T) {
	ctx := context.Background()

	// Setup LDAP
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	if !setupLDAP(t, ctx, client) {
		t.Skip("LDAP not available, skipping test")
	}

	// Get test user
	ldapUser := os.Getenv("LDAP_TEST_USER")
	if ldapUser == "" {
		t.Skip("LDAP_TEST_USER not set, skipping test")
	}

	// Try to authenticate with wrong password
	_, err = testBackend.AuthenticateLDAP(ctx, "ldap", ldapUser, "wrong-password")
	if err == nil {
		t.Fatal("Expected error for invalid password, got nil")
	}

	t.Logf("Expected error for invalid password: %v", err)
}

// TestIntegration_AuthenticateLDAP_NonexistentUser tests error handling for non-existent user
func TestIntegration_AuthenticateLDAP_NonexistentUser(t *testing.T) {
	ctx := context.Background()

	// Setup LDAP
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	if !setupLDAP(t, ctx, client) {
		t.Skip("LDAP not available, skipping test")
	}

	// Try to authenticate with non-existent user
	_, err = testBackend.AuthenticateLDAP(ctx, "ldap", "nonexistent-user-12345", "password")
	if err == nil {
		t.Fatal("Expected error for non-existent user, got nil")
	}

	t.Logf("Expected error for non-existent user: %v", err)
}

// TestIntegration_AuthenticateLDAP_InvalidMount tests error handling for invalid mount
func TestIntegration_AuthenticateLDAP_InvalidMount(t *testing.T) {
	ctx := context.Background()

	// Try to authenticate against non-existent mount
	_, err := testBackend.AuthenticateLDAP(ctx, "nonexistent-ldap", "user", "pass")
	if err == nil {
		t.Fatal("Expected error for invalid mount, got nil")
	}

	t.Logf("Expected error for invalid mount: %v", err)
}

// TestIntegration_Client_AuthenticateLDAP tests LDAP authentication through Client wrapper
func TestIntegration_Client_AuthenticateLDAP(t *testing.T) {
	ctx := context.Background()

	// Create a client
	cfg := &Config{
		Address: openbaoAddr,
		Token:   openbaoToken,
		Type:    BackendTypeOpenBao,
	}

	client, err := NewClient(ctx, cfg, testLogger)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	// Setup LDAP using API client
	apiClient := client.GetAPIClient()
	if !setupLDAP(t, ctx, apiClient) {
		t.Skip("LDAP not available, skipping test")
	}

	// Get test credentials
	ldapUser := os.Getenv("LDAP_TEST_USER")
	ldapPass := os.Getenv("LDAP_TEST_PASS")

	if ldapUser == "" || ldapPass == "" {
		t.Skip("LDAP_TEST_USER or LDAP_TEST_PASS not set, skipping test")
	}

	// Authenticate through Client wrapper
	token, err := client.AuthenticateLDAP(ctx, "ldap", ldapUser, ldapPass)
	if err != nil {
		t.Fatalf("Client.AuthenticateLDAP() failed: %v", err)
	}

	if token == "" {
		t.Fatal("Expected token, got empty string")
	}

	// Verify the token
	valid, err := client.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("ValidateToken() failed: %v", err)
	}

	if !valid {
		t.Error("Expected LDAP token to be valid")
	}

	t.Logf("Client LDAP authentication successful: token=%s...", token[:min(10, len(token))])
}

// TestIntegration_AuthenticateLDAP_TokenLookup tests looking up LDAP token details
func TestIntegration_AuthenticateLDAP_TokenLookup(t *testing.T) {
	ctx := context.Background()

	// Setup LDAP
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	if !setupLDAP(t, ctx, client) {
		t.Skip("LDAP not available, skipping test")
	}

	// Get test credentials
	ldapUser := os.Getenv("LDAP_TEST_USER")
	ldapPass := os.Getenv("LDAP_TEST_PASS")

	if ldapUser == "" || ldapPass == "" {
		t.Skip("LDAP_TEST_USER or LDAP_TEST_PASS not set, skipping test")
	}

	// Authenticate
	token, err := testBackend.AuthenticateLDAP(ctx, "ldap", ldapUser, ldapPass)
	if err != nil {
		t.Fatalf("AuthenticateLDAP() failed: %v", err)
	}

	// Lookup token details
	tokenData, err := testBackend.LookupToken(ctx, token)
	if err != nil {
		t.Fatalf("LookupToken() failed: %v", err)
	}

	if len(tokenData) == 0 {
		t.Fatal("Expected token data")
	}

	// Check for expected fields
	if _, ok := tokenData["id"]; !ok {
		t.Error("Expected 'id' field in token data")
	}

	t.Logf("LDAP token data fields: %d", len(tokenData))
}

// TestIntegration_AuthenticateLDAP_CloneWithToken tests cloning backend with LDAP token
func TestIntegration_AuthenticateLDAP_CloneWithToken(t *testing.T) {
	ctx := context.Background()

	// Setup LDAP
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	if !setupLDAP(t, ctx, client) {
		t.Skip("LDAP not available, skipping test")
	}

	// Get test credentials
	ldapUser := os.Getenv("LDAP_TEST_USER")
	ldapPass := os.Getenv("LDAP_TEST_PASS")

	if ldapUser == "" || ldapPass == "" {
		t.Skip("LDAP_TEST_USER or LDAP_TEST_PASS not set, skipping test")
	}

	// Authenticate
	token, err := testBackend.AuthenticateLDAP(ctx, "ldap", ldapUser, ldapPass)
	if err != nil {
		t.Fatalf("AuthenticateLDAP() failed: %v", err)
	}

	// Clone backend with LDAP token
	cloned, err := testBackend.CloneWithToken(ctx, token)
	if err != nil {
		t.Fatalf("CloneWithToken() failed: %v", err)
	}

	// Verify cloned backend works
	health, err := cloned.Health(ctx)
	if err != nil {
		t.Fatalf("Cloned backend Health() failed: %v", err)
	}

	if !health.Initialized {
		t.Error("Expected cloned backend to work")
	}

	t.Log("Successfully cloned backend with LDAP token")
}
