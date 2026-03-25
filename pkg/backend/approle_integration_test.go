//go:build integration
// +build integration

package backend

import (
	"context"
	"testing"

	"github.com/openbao/openbao/api/v2"
)

// setupAppRole creates and configures an AppRole for testing
// Returns roleID and secretID
func setupAppRole(t *testing.T, ctx context.Context, client *api.Client, roleName string) (string, string) {
	t.Helper()

	// Check if approle auth is already enabled
	auths, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatalf("Failed to list auth methods: %v", err)
	}

	approleExists := false
	if _, ok := auths["approle/"]; ok {
		approleExists = true
		testLogger.Info("AppRole auth already exists")
	}

	if !approleExists {
		// Enable AppRole auth method
		if err := client.Sys().EnableAuth("approle", "approle", ""); err != nil {
			t.Fatalf("Failed to enable approle auth: %v", err)
		}
		testLogger.Info("Enabled AppRole auth")
	}

	// Create/update the AppRole
	_, err = client.Logical().WriteWithContext(ctx, "auth/approle/role/"+roleName, map[string]interface{}{
		"token_ttl":     "1h",
		"token_max_ttl": "4h",
		"policies":      []string{"default"},
		// Allow binding tokens to any CIDR for testing
		"bind_secret_id": true,
	})
	if err != nil {
		t.Fatalf("Failed to create AppRole role: %v", err)
	}

	// Get the role ID
	roleIDResp, err := client.Logical().ReadWithContext(ctx, "auth/approle/role/"+roleName+"/role-id")
	if err != nil {
		t.Fatalf("Failed to read role ID: %v", err)
	}

	roleID, ok := roleIDResp.Data["role_id"].(string)
	if !ok {
		t.Fatalf("Failed to get role_id from response")
	}

	// Generate a secret ID
	secretIDResp, err := client.Logical().WriteWithContext(ctx, "auth/approle/role/"+roleName+"/secret-id", nil)
	if err != nil {
		t.Fatalf("Failed to generate secret ID: %v", err)
	}

	secretID, ok := secretIDResp.Data["secret_id"].(string)
	if !ok {
		t.Fatalf("Failed to get secret_id from response")
	}

	testLogger.Info("Created AppRole credentials",
		"role", roleName,
		"role_id", roleID[:min(10, len(roleID))]+"...",
		"secret_id", secretID[:min(10, len(secretID))]+"...")

	return roleID, secretID
}

// TestIntegration_AuthenticateAppRole tests AppRole authentication
func TestIntegration_AuthenticateAppRole(t *testing.T) {
	ctx := context.Background()

	// Setup AppRole with unique name
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	roleName := generateUniqueTestName(t, "role")
	t.Cleanup(func() { cleanupAppRole(ctx, t, "approle", roleName) })

	roleID, secretID := setupAppRole(t, ctx, client, roleName)

	// Test authentication
	token, err := testBackend.AuthenticateAppRole(ctx, "approle", roleID, secretID)
	if err != nil {
		t.Fatalf("AuthenticateAppRole() failed: %v", err)
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
		t.Error("Expected AppRole token to be valid")
	}

	t.Logf("AppRole authentication successful: token=%s...", token[:min(10, len(token))])
}

// TestIntegration_AuthenticateAppRole_InvalidRoleID tests error handling for invalid role ID
func TestIntegration_AuthenticateAppRole_InvalidRoleID(t *testing.T) {
	ctx := context.Background()

	// Setup valid AppRole first to get a valid secret ID
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	_, secretID := setupAppRole(t, ctx, client, "test-role-2")

	// Try to authenticate with invalid role ID
	_, err = testBackend.AuthenticateAppRole(ctx, "approle", "invalid-role-id", secretID)
	if err == nil {
		t.Fatal("Expected error for invalid role ID, got nil")
	}

	t.Logf("Expected error for invalid role ID: %v", err)
}

// TestIntegration_AuthenticateAppRole_InvalidSecretID tests error handling for invalid secret ID
func TestIntegration_AuthenticateAppRole_InvalidSecretID(t *testing.T) {
	ctx := context.Background()

	// Setup valid AppRole
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	roleID, _ := setupAppRole(t, ctx, client, "test-role-3")

	// Try to authenticate with invalid secret ID
	_, err = testBackend.AuthenticateAppRole(ctx, "approle", roleID, "invalid-secret-id")
	if err == nil {
		t.Fatal("Expected error for invalid secret ID, got nil")
	}

	t.Logf("Expected error for invalid secret ID: %v", err)
}

// TestIntegration_AuthenticateAppRole_InvalidMount tests error handling for invalid mount
func TestIntegration_AuthenticateAppRole_InvalidMount(t *testing.T) {
	ctx := context.Background()

	// Try to authenticate against non-existent mount
	_, err := testBackend.AuthenticateAppRole(ctx, "nonexistent-approle", "role-id", "secret-id")
	if err == nil {
		t.Fatal("Expected error for invalid mount, got nil")
	}

	t.Logf("Expected error for invalid mount: %v", err)
}

// TestIntegration_AuthenticateAppRole_MultipleRoles tests multiple AppRoles
func TestIntegration_AuthenticateAppRole_MultipleRoles(t *testing.T) {
	ctx := context.Background()

	// Setup API client
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	// Create multiple AppRoles
	roleID1, secretID1 := setupAppRole(t, ctx, client, "test-role-a")
	roleID2, secretID2 := setupAppRole(t, ctx, client, "test-role-b")

	// Authenticate with first role
	token1, err := testBackend.AuthenticateAppRole(ctx, "approle", roleID1, secretID1)
	if err != nil {
		t.Fatalf("AuthenticateAppRole() for role-a failed: %v", err)
	}

	// Authenticate with second role
	token2, err := testBackend.AuthenticateAppRole(ctx, "approle", roleID2, secretID2)
	if err != nil {
		t.Fatalf("AuthenticateAppRole() for role-b failed: %v", err)
	}

	// Tokens should be different
	if token1 == token2 {
		t.Error("Expected different tokens for different roles")
	}

	// Both tokens should be valid
	valid1, err := testBackend.ValidateToken(ctx, token1)
	if err != nil || !valid1 {
		t.Errorf("Token 1 should be valid: valid=%v, err=%v", valid1, err)
	}

	valid2, err := testBackend.ValidateToken(ctx, token2)
	if err != nil || !valid2 {
		t.Errorf("Token 2 should be valid: valid=%v, err=%v", valid2, err)
	}

	t.Logf("Multiple AppRole authentication successful: tokens are unique and valid")
}

// TestIntegration_AuthenticateAppRole_WithPolicies tests AppRole with specific policies
func TestIntegration_AuthenticateAppRole_WithPolicies(t *testing.T) {
	ctx := context.Background()

	// Setup API client
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	// Create AppRole with specific policies
	roleName := "test-role-policies"
	_, err = client.Logical().WriteWithContext(ctx, "auth/approle/role/"+roleName, map[string]interface{}{
		"token_ttl":      "30m",
		"token_max_ttl":  "2h",
		"policies":       []string{"default"}, // Specify policies
		"bind_secret_id": true,
	})
	if err != nil {
		t.Fatalf("Failed to create AppRole role: %v", err)
	}

	// Get credentials
	roleIDResp, err := client.Logical().ReadWithContext(ctx, "auth/approle/role/"+roleName+"/role-id")
	if err != nil {
		t.Fatalf("Failed to read role ID: %v", err)
	}
	roleID := roleIDResp.Data["role_id"].(string)

	secretIDResp, err := client.Logical().WriteWithContext(ctx, "auth/approle/role/"+roleName+"/secret-id", nil)
	if err != nil {
		t.Fatalf("Failed to generate secret ID: %v", err)
	}
	secretID := secretIDResp.Data["secret_id"].(string)

	// Authenticate
	token, err := testBackend.AuthenticateAppRole(ctx, "approle", roleID, secretID)
	if err != nil {
		t.Fatalf("AuthenticateAppRole() failed: %v", err)
	}

	// Verify token has correct policies
	tokenData, err := testBackend.LookupToken(ctx, token)
	if err != nil {
		t.Fatalf("LookupToken() failed: %v", err)
	}

	// Check policies
	policies, ok := tokenData["policies"]
	if !ok {
		t.Error("Expected 'policies' field in token data")
	}

	t.Logf("AppRole token has policies: %v", policies)
}

// TestIntegration_Client_AuthenticateAppRole tests AppRole authentication through Client wrapper
func TestIntegration_Client_AuthenticateAppRole(t *testing.T) {
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

	// Setup AppRole using API client
	apiClient := client.GetAPIClient()
	roleID, secretID := setupAppRole(t, ctx, apiClient, "test-role-client")

	// Authenticate through Client wrapper
	token, err := client.AuthenticateAppRole(ctx, "approle", roleID, secretID)
	if err != nil {
		t.Fatalf("Client.AuthenticateAppRole() failed: %v", err)
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
		t.Error("Expected AppRole token to be valid")
	}

	t.Logf("Client AppRole authentication successful: token=%s...", token[:min(10, len(token))])
}
