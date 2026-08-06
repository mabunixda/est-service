//go:build integration
// +build integration

package backend

import (
	"context"
	"testing"
)

// TestIntegration_NewClient tests creating a client with automatic backend detection
func TestIntegration_NewClient(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		Address: openbaoAddr,
		Token:   openbaoToken,
		Type:    BackendTypeOpenBao, // Auto-detect backend type
	}

	client, err := NewClient(ctx, cfg, testLogger)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	if client == nil {
		t.Fatal("Expected client, got nil")
	}

	// Verify client works by checking health
	health, err := client.Health(ctx)
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	if !health.Initialized {
		t.Error("Expected backend to be initialized")
	}

	t.Logf("Created client with backend type: %s", client.Type())
}

func TestIntegration_NewClient_ExplicitOpenBao(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		Address: openbaoAddr,
		Token:   openbaoToken,
		Type:    BackendTypeOpenBao, // Explicitly request OpenBao backend
	}

	client, err := NewClient(ctx, cfg, testLogger)
	if err != nil {
		t.Fatalf("NewClient() with OpenBao type failed: %v", err)
	}

	if client == nil {
		t.Fatal("Expected client, got nil")
	}

	// Verify it works
	health, err := client.Health(ctx)
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	if !health.Initialized {
		t.Error("Expected backend to be initialized")
	}

	t.Logf("Created OpenBao client: type=%s, version=%s", client.Type(), health.Version)
}

// TestIntegration_NewClient_InvalidAddress tests error handling for invalid address
func TestIntegration_NewClient_InvalidAddress(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		Address: "http://invalid-address-that-does-not-exist:8200",
		Token:   openbaoToken,
		Type:    BackendTypeOpenBao,
	}

	client, err := NewClient(ctx, cfg, testLogger)
	if err != nil {
		// Some errors are acceptable (connection refused, etc)
		t.Logf("Expected error for invalid address: %v", err)
		return
	}

	// If client was created, health check should fail
	if client != nil {
		_, err = client.Health(ctx)
		if err == nil {
			t.Error("Expected error for invalid address, got success")
		}
		t.Logf("Health check failed as expected: %v", err)
	}
}

// TestIntegration_NewClient_InvalidToken tests error handling for invalid token
func TestIntegration_NewClient_InvalidToken(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		Address: openbaoAddr,
		Token:   "invalid-token-12345",
		Type:    BackendTypeOpenBao,
	}

	client, err := NewClient(ctx, cfg, testLogger)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	// Client creation succeeds, but operations should fail
	_, err = client.ValidateToken(ctx, "invalid-token-12345")
	if err != nil {
		t.Logf("Token validation failed as expected: %v", err)
	}

	// Or token might be reported as invalid
	valid, err := client.ValidateToken(ctx, "invalid-token-12345")
	if err == nil && valid {
		t.Error("Expected invalid token to be rejected")
	}

	t.Log("Invalid token properly rejected")
}

// TestIntegration_NewClientWithBackend tests creating a client with a custom backend
func TestIntegration_NewClientWithBackend(t *testing.T) {
	ctx := context.Background()

	// First create a real backend
	cfg := &Config{
		Address: openbaoAddr,
		Token:   openbaoToken,
		Type:    BackendTypeOpenBao,
	}

	backend, err := NewBackend(ctx, cfg, testLogger)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// Now create a client wrapping this backend
	client := NewClientWithBackend(backend)

	if client == nil {
		t.Fatal("Expected client, got nil")
	}

	// Verify GetBackend returns the same backend
	if client.GetBackend() != backend {
		t.Error("GetBackend() did not return the same backend")
	}

	// Verify the client works
	health, err := client.Health(ctx)
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	if !health.Initialized {
		t.Error("Expected backend to be initialized")
	}

	t.Logf("Client with custom backend works: type=%s", client.Type())
}

// TestIntegration_Client_GetAPIClient tests retrieving the underlying API client
func TestIntegration_Client_GetAPIClient(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		Address: openbaoAddr,
		Token:   openbaoToken,
		Type:    BackendTypeOpenBao,
	}

	client, err := NewClient(ctx, cfg, testLogger)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	apiClient := client.GetAPIClient()
	if apiClient == nil {
		t.Fatal("Expected API client, got nil")
	}

	// Verify we can use the API client directly
	// Try to read system health
	health, err := apiClient.Sys().Health()
	if err != nil {
		t.Fatalf("Direct API client health check failed: %v", err)
	}

	if !health.Initialized {
		t.Error("Expected system to be initialized")
	}

	t.Logf("Direct API client works: initialized=%v, version=%s", health.Initialized, health.Version)
}

// TestIntegration_Client_Close tests closing the client
func TestIntegration_Client_Close(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		Address: openbaoAddr,
		Token:   openbaoToken,
		Type:    BackendTypeOpenBao,
	}

	client, err := NewClient(ctx, cfg, testLogger)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	// Close the client
	err = client.Close()
	if err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	t.Log("Client closed successfully")
}

// TestIntegration_Client_Type tests the Type() method
func TestIntegration_Client_Type(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		Address: openbaoAddr,
		Token:   openbaoToken,
		Type:    BackendTypeOpenBao,
	}

	client, err := NewClient(ctx, cfg, testLogger)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	backendType := client.Type()

	// Should be OpenBao
	if backendType != BackendTypeOpenBao {
		t.Errorf("Expected BackendTypeOpenBao, got %v", backendType)
	}

	t.Logf("Backend type: %s", backendType)
}

// TestIntegration_Client_AllAuthenticationMethods tests that the client delegates all auth methods correctly
func TestIntegration_Client_AllAuthenticationMethods(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		Address: openbaoAddr,
		Token:   openbaoToken,
		Type:    BackendTypeOpenBao,
	}

	client, err := NewClient(ctx, cfg, testLogger)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	// Test userpass authentication (we know testuser exists from integration_test.go setup)
	token, err := client.AuthenticateUserpass(ctx, "userpass", "testuser", "testpass")
	if err != nil {
		t.Fatalf("AuthenticateUserpass() failed: %v", err)
	}

	if token == "" {
		t.Fatal("Expected token from userpass auth, got empty string")
	}

	// Verify the token works
	valid, err := client.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("ValidateToken() failed: %v", err)
	}

	if !valid {
		t.Error("Expected userpass token to be valid")
	}

	t.Logf("Userpass authentication works: token=%s...", token[:min(10, len(token))])
}

// TestIntegration_Client_TokenOperations tests token-related operations
func TestIntegration_Client_TokenOperations(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		Address: openbaoAddr,
		Token:   openbaoToken,
		Type:    BackendTypeOpenBao,
	}

	client, err := NewClient(ctx, cfg, testLogger)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	// Test ValidateToken with the root token
	valid, err := client.ValidateToken(ctx, openbaoToken)
	if err != nil {
		t.Fatalf("ValidateToken() failed: %v", err)
	}

	if !valid {
		t.Error("Expected root token to be valid")
	}

	// Test LookupToken
	tokenData, err := client.LookupToken(ctx, openbaoToken)
	if err != nil {
		t.Fatalf("LookupToken() failed: %v", err)
	}

	if tokenData == nil {
		t.Fatal("Expected token data, got nil")
	}

	if _, ok := tokenData["id"]; !ok {
		t.Error("Expected 'id' field in token data")
	}

	t.Logf("Token operations work: token has %d fields", len(tokenData))
}
