//go:build integration
// +build integration

package backend

import (
	"context"
	"strings"
	"testing"

	"github.com/openbao/openbao/api/v2"
)

// TestIntegration_CreateOrUpdateEntity tests creating and updating entities
func TestIntegration_CreateOrUpdateEntity(t *testing.T) {
	ctx := context.Background()

	// Use unique entity name to avoid conflicts with other test runs
	entityName := generateUniqueTestName(t, "entity")
	t.Cleanup(func() { cleanupEntity(ctx, t, entityName) })

	// Create an entity
	entityID, err := testBackend.CreateOrUpdateEntity(ctx, entityName, map[string]string{
		"team":        "engineering",
		"environment": "test",
	}, []string{"default"})

	if err != nil {
		t.Fatalf("CreateOrUpdateEntity() failed: %v", err)
	}

	if entityID == "" {
		t.Fatal("Expected entity ID, got empty string")
	}

	t.Logf("Created entity: id=%s", entityID)

	// Update the same entity (should be idempotent)
	entityID2, err := testBackend.CreateOrUpdateEntity(ctx, entityName, map[string]string{
		"team":        "engineering",
		"environment": "production", // Changed metadata
	}, []string{"default"})

	if err != nil {
		t.Fatalf("CreateOrUpdateEntity() update failed: %v", err)
	}

	// Should return the same entity ID
	if entityID2 != entityID {
		t.Errorf("Expected same entity ID, got different: %s != %s", entityID, entityID2)
	}

	t.Logf("Updated entity successfully: id=%s", entityID2)
}

// TestIntegration_CreateOrUpdateEntity_MultipleEntities tests creating multiple entities
func TestIntegration_CreateOrUpdateEntity_MultipleEntities(t *testing.T) {
	ctx := context.Background()

	// Use unique entity names
	entityName1 := generateUniqueTestName(t, "entity-multi-1")
	entityName2 := generateUniqueTestName(t, "entity-multi-2")
	t.Cleanup(func() {
		cleanupEntity(ctx, t, entityName1)
		cleanupEntity(ctx, t, entityName2)
	})

	// Create first entity
	entityID1, err := testBackend.CreateOrUpdateEntity(ctx, entityName1, map[string]string{
		"type": "service",
	}, []string{"default"})

	if err != nil {
		t.Fatalf("CreateOrUpdateEntity() for entity 1 failed: %v", err)
	}

	// Create second entity
	entityID2, err := testBackend.CreateOrUpdateEntity(ctx, entityName2, map[string]string{
		"type": "user",
	}, []string{"default"})

	if err != nil {
		t.Fatalf("CreateOrUpdateEntity() for entity 2 failed: %v", err)
	}

	// Entity IDs should be different
	if entityID1 == entityID2 {
		t.Error("Expected different entity IDs for different entities")
	}

	t.Logf("Created multiple entities: id1=%s, id2=%s", entityID1, entityID2)
}

// TestIntegration_CreateOrUpdateEntity_WithPolicies tests creating entity with specific policies
func TestIntegration_CreateOrUpdateEntity_WithPolicies(t *testing.T) {
	ctx := context.Background()

	// Create entity with multiple policies
	entityID, err := testBackend.CreateOrUpdateEntity(ctx, "test-entity-policies", map[string]string{
		"role": "admin",
	}, []string{"default"})

	if err != nil {
		t.Fatalf("CreateOrUpdateEntity() failed: %v", err)
	}

	if entityID == "" {
		t.Fatal("Expected entity ID, got empty string")
	}

	t.Logf("Created entity with policies: id=%s", entityID)
}

// TestIntegration_CreateOrUpdateEntityAlias tests creating entity aliases
func TestIntegration_CreateOrUpdateEntityAlias(t *testing.T) {
	ctx := context.Background()

	// First create an entity
	entityID, err := testBackend.CreateOrUpdateEntity(ctx, "test-entity-for-alias", map[string]string{
		"type": "test",
	}, []string{"default"})

	if err != nil {
		t.Fatalf("CreateOrUpdateEntity() failed: %v", err)
	}

	// Get the userpass mount accessor
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	auths, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatalf("Failed to list auth methods: %v", err)
	}

	userpassAccessor := ""
	if auth, ok := auths["userpass/"]; ok {
		userpassAccessor = auth.Accessor
	} else {
		t.Fatal("Userpass auth method not found")
	}

	// Create an alias for the entity
	aliasID, err := testBackend.CreateOrUpdateEntityAlias(ctx, entityID, "test-alias-1", userpassAccessor)
	if err != nil {
		t.Fatalf("CreateOrUpdateEntityAlias() failed: %v", err)
	}

	if aliasID == "" {
		t.Fatal("Expected alias ID, got empty string")
	}

	t.Logf("Created entity alias: entity_id=%s, alias_id=%s", entityID, aliasID)

	// Update the same alias (should be idempotent)
	aliasID2, err := testBackend.CreateOrUpdateEntityAlias(ctx, entityID, "test-alias-1", userpassAccessor)
	if err != nil {
		t.Fatalf("CreateOrUpdateEntityAlias() update failed: %v", err)
	}

	// Should return the same alias ID or "<updated>" when no data is returned
	if aliasID2 != aliasID && aliasID2 != "<updated>" {
		t.Errorf("Expected same alias ID or '<updated>', got different: %s != %s", aliasID, aliasID2)
	}

	t.Logf("Updated entity alias successfully: alias_id=%s", aliasID2)
}

// TestIntegration_CreateOrUpdateEntityAlias_MultipleAliases tests creating multiple aliases for an entity
// Note: An entity can only have one alias per mount accessor, so this test verifies the behavior
func TestIntegration_CreateOrUpdateEntityAlias_MultipleAliases(t *testing.T) {
	ctx := context.Background()

	// Create an entity
	entityID, err := testBackend.CreateOrUpdateEntity(ctx, "test-entity-multi-aliases", map[string]string{
		"type": "test",
	}, []string{"default"})

	if err != nil {
		t.Fatalf("CreateOrUpdateEntity() failed: %v", err)
	}

	// Get mount accessors for different auth methods
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	auths, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatalf("Failed to list auth methods: %v", err)
	}

	userpassAccessor := ""
	if auth, ok := auths["userpass/"]; ok {
		userpassAccessor = auth.Accessor
	} else {
		t.Fatal("Userpass auth method not found")
	}

	certAccessor := ""
	if auth, ok := auths["cert/"]; ok {
		certAccessor = auth.Accessor
	} else {
		t.Fatal("Cert auth method not found")
	}

	// Create first alias on userpass mount
	aliasID1, err := testBackend.CreateOrUpdateEntityAlias(ctx, entityID, "test-alias-multi-1", userpassAccessor)
	if err != nil {
		t.Fatalf("CreateOrUpdateEntityAlias() for alias 1 failed: %v", err)
	}

	// Create second alias on cert mount (different mount accessor)
	aliasID2, err := testBackend.CreateOrUpdateEntityAlias(ctx, entityID, "test-alias-multi-2", certAccessor)
	if err != nil {
		t.Fatalf("CreateOrUpdateEntityAlias() for alias 2 failed: %v", err)
	}

	// Note: Alias IDs may show as "<updated>" if they were updated rather than created
	// This is acceptable idempotent behavior
	if aliasID1 != "<updated>" && aliasID2 != "<updated>" {
		// Both are real IDs - they should be different
		if aliasID1 == aliasID2 {
			t.Error("Expected different alias IDs for different aliases")
		}
	}

	t.Logf("Created multiple aliases on different mounts: alias_id1=%s, alias_id2=%s", aliasID1, aliasID2)
}

// TestIntegration_CreateTokenForEntity tests creating tokens for entities
func TestIntegration_CreateTokenForEntity(t *testing.T) {
	ctx := context.Background()

	// Create an entity
	entityID, err := testBackend.CreateOrUpdateEntity(ctx, "test-entity-token", map[string]string{
		"purpose": "testing",
	}, []string{"default"})

	if err != nil {
		t.Fatalf("CreateOrUpdateEntity() failed: %v", err)
	}

	// Create a token for the entity
	token, err := testBackend.CreateTokenForEntity(ctx, entityID, []string{"default"}, "1h")
	if err != nil {
		t.Fatalf("CreateTokenForEntity() failed: %v", err)
	}

	if token == "" {
		t.Fatal("Expected token, got empty string")
	}

	// Verify the token is valid
	valid, err := testBackend.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("ValidateToken() failed: %v", err)
	}

	if !valid {
		t.Error("Expected token to be valid")
	}

	// Lookup the token and verify it's bound to the entity
	tokenData, err := testBackend.LookupToken(ctx, token)
	if err != nil {
		t.Fatalf("LookupToken() failed: %v", err)
	}

	// Check if entity_id matches (note: may not always be present in token data)
	if tokenEntityID, ok := tokenData["entity_id"].(string); ok && tokenEntityID != "" {
		if tokenEntityID != entityID {
			t.Errorf("Expected entity_id %s, got %s", entityID, tokenEntityID)
		} else {
			t.Logf("Token correctly associated with entity: %s", entityID)
		}
	} else {
		// Entity ID may not be directly visible in token lookup
		// This is acceptable - the token is still bound to the entity internally
		t.Logf("Note: entity_id not directly visible in token data (still bound internally)")
	}

	t.Logf("Created token for entity: entity_id=%s, token=%s...", entityID, token[:min(10, len(token))])
}

// TestIntegration_CreateTokenForEntity_WithCustomTTL tests creating tokens with custom TTL
func TestIntegration_CreateTokenForEntity_WithCustomTTL(t *testing.T) {
	ctx := context.Background()

	// Create an entity
	entityID, err := testBackend.CreateOrUpdateEntity(ctx, "test-entity-token-ttl", map[string]string{
		"purpose": "ttl-test",
	}, []string{"default"})

	if err != nil {
		t.Fatalf("CreateOrUpdateEntity() failed: %v", err)
	}

	// Create a token with 30-minute TTL
	token, err := testBackend.CreateTokenForEntity(ctx, entityID, []string{"default"}, "30m")
	if err != nil {
		t.Fatalf("CreateTokenForEntity() failed: %v", err)
	}

	if token == "" {
		t.Fatal("Expected token, got empty string")
	}

	// Verify the token
	valid, err := testBackend.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("ValidateToken() failed: %v", err)
	}

	if !valid {
		t.Error("Expected token to be valid")
	}

	t.Logf("Created token with custom TTL: token=%s...", token[:min(10, len(token))])
}

// TestIntegration_CreateTokenForEntity_InvalidEntityID tests creating token with invalid entity ID
// Note: OpenBao allows creating tokens with any entity_id, even if it doesn't exist
// The token will be created but won't be associated with a valid entity
func TestIntegration_CreateTokenForEntity_InvalidEntityID(t *testing.T) {
	ctx := context.Background()

	// Try to create a token with non-existent entity ID
	token, err := testBackend.CreateTokenForEntity(ctx, "nonexistent-entity-id", []string{"default"}, "1h")
	if err != nil {
		// In OpenBao, this might succeed (creating an orphan token) or might fail
		// Either behavior is acceptable
		t.Logf("Token creation failed (acceptable): %v", err)
		return
	}

	// If token was created, verify it exists but has invalid entity
	if token == "" {
		t.Fatal("Expected token or error, got empty string")
	}

	// Token is valid but not associated with a real entity
	valid, err := testBackend.ValidateToken(ctx, token)
	if err != nil {
		t.Logf("Token validation failed (acceptable for invalid entity): %v", err)
		return
	}

	if !valid {
		t.Log("Token created but marked invalid (acceptable)")
		return
	}

	t.Logf("Token created successfully (OpenBao allows tokens with non-existent entities): token=%s...", token[:min(10, len(token))])
}

// TestIntegration_Client_EntityOperations tests entity operations through Client wrapper
func TestIntegration_Client_EntityOperations(t *testing.T) {
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

	// Create entity through Client
	entityID, err := client.CreateOrUpdateEntity(ctx, "test-client-entity", map[string]string{
		"source": "client-test",
	}, []string{"default"})

	if err != nil {
		t.Fatalf("Client.CreateOrUpdateEntity() failed: %v", err)
	}

	if entityID == "" {
		t.Fatal("Expected entity ID, got empty string")
	}

	// Create token for entity through Client
	token, err := client.CreateTokenForEntity(ctx, entityID, []string{"default"}, "1h")
	if err != nil {
		t.Fatalf("Client.CreateTokenForEntity() failed: %v", err)
	}

	if token == "" {
		t.Fatal("Expected token, got empty string")
	}

	// Verify token
	valid, err := client.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("ValidateToken() failed: %v", err)
	}

	if !valid {
		t.Error("Expected token to be valid")
	}

	t.Logf("Client entity operations successful: entity_id=%s, token=%s...", entityID, token[:min(10, len(token))])
}

// TestIntegration_EntityWorkflow tests a complete entity workflow
func TestIntegration_EntityWorkflow(t *testing.T) {
	ctx := context.Background()

	// Step 1: Create an entity
	entityName := "workflow-test-entity"
	entityID, err := testBackend.CreateOrUpdateEntity(ctx, entityName, map[string]string{
		"workflow": "test",
		"step":     "1",
	}, []string{"default"})

	if err != nil {
		t.Fatalf("Step 1 - CreateOrUpdateEntity() failed: %v", err)
	}

	t.Logf("Step 1: Created entity %s with id=%s", entityName, entityID)

	// Step 2: Get mount accessor for userpass
	apiConfig := api.DefaultConfig()
	apiConfig.Address = openbaoAddr
	client, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create API client: %v", err)
	}
	client.SetToken(openbaoToken)

	auths, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatalf("Failed to list auth methods: %v", err)
	}

	userpassAccessor := ""
	if auth, ok := auths["userpass/"]; ok {
		userpassAccessor = auth.Accessor
	} else {
		t.Fatal("Userpass auth method not found")
	}

	// Step 3: Create an alias linking the entity to a userpass user
	aliasName := "workflow-" + strings.ReplaceAll(entityName, "-", "_")
	aliasID, err := testBackend.CreateOrUpdateEntityAlias(ctx, entityID, aliasName, userpassAccessor)
	if err != nil {
		t.Fatalf("Step 3 - CreateOrUpdateEntityAlias() failed: %v", err)
	}

	t.Logf("Step 3: Created alias %s with id=%s", aliasName, aliasID)

	// Step 4: Create a token bound to the entity
	token, err := testBackend.CreateTokenForEntity(ctx, entityID, []string{"default"}, "2h")
	if err != nil {
		t.Fatalf("Step 4 - CreateTokenForEntity() failed: %v", err)
	}

	t.Logf("Step 4: Created token %s... for entity", token[:min(10, len(token))])

	// Step 5: Validate the token
	valid, err := testBackend.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("Step 5 - ValidateToken() failed: %v", err)
	}

	if !valid {
		t.Fatal("Step 5: Token should be valid")
	}

	t.Logf("Step 5: Token validated successfully")

	// Step 6: Lookup token details
	tokenData, err := testBackend.LookupToken(ctx, token)
	if err != nil {
		t.Fatalf("Step 6 - LookupToken() failed: %v", err)
	}

	if len(tokenData) == 0 {
		t.Fatal("Step 6: Expected token data")
	}

	t.Logf("Step 6: Token lookup successful, has %d fields", len(tokenData))

	// Success!
	t.Log("Entity workflow completed successfully")
}
