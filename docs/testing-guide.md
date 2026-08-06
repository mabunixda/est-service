# Integration Testing Guide

## Overview

This project uses a **hybrid approach** for integration testing that balances speed with isolation:

- **Shared setup**: Infrastructure (PKI mounts, auth methods) is created once in `TestMain`
- **Per-test isolation**: Each test creates resources with unique names and cleans them up

This provides fast test execution while preventing state pollution between tests.

## Test Architecture

### TestMain (Runs Once)

Located in `pkg/backend/integration_test.go`, this function runs before all tests and:

1. Connects to OpenBao (requires `BAO_ADDR` and `BAO_TOKEN` env vars)
2. Creates a shared PKI mount (`pki-backend-test`)
3. Enables auth methods (userpass, cert, approle)
4. Creates base test users and roles
5. Stores configuration in global variables

### Individual Tests

Each test should:

1. Use `generateUniqueTestName()` to create unique resource names
2. Register cleanup with `t.Cleanup()`
3. Create test-specific resources
4. Clean up resources after test completes

## Writing Integration Tests

### Basic Pattern

```go
func TestIntegration_MyFeature(t *testing.T) {
    ctx := context.Background()
    
    // 1. Generate unique name
    entityName := generateUniqueTestName(t, "entity")
    
    // 2. Register cleanup
    t.Cleanup(func() { cleanupEntity(ctx, t, entityName) })
    
    // 3. Create test resources
    entityID, err := testBackend.CreateOrUpdateEntity(ctx, entityName, ...)
    if err != nil {
        t.Fatalf("Failed: %v", err)
    }
    
    // 4. Run your test assertions
    assert(...)
    
    // Cleanup happens automatically via t.Cleanup()
}
```

### Available Helper Functions

#### Generate Unique Names

```go
// Creates name like "entity-TestName-123456"
name := generateUniqueTestName(t, "entity")
```

#### Cleanup Functions

```go
// Cleanup an entity
t.Cleanup(func() { cleanupEntity(ctx, t, entityName) })

// Cleanup an AppRole role  
t.Cleanup(func() { cleanupAppRole(ctx, t, "approle", roleName) })

// Cleanup a userpass user
t.Cleanup(func() { cleanupUser(ctx, t, "userpass", username) })
```

### Multiple Resources

```go
func TestIntegration_MultipleResources(t *testing.T) {
    ctx := context.Background()
    
    // Create multiple unique names
    entity1 := generateUniqueTestName(t, "entity-1")
    entity2 := generateUniqueTestName(t, "entity-2")
    
    // Register all cleanups
    t.Cleanup(func() {
        cleanupEntity(ctx, t, entity1)
        cleanupEntity(ctx, t, entity2)
    })
    
    // Rest of test...
}
```

## Running Integration Tests

### Locally

```bash
# 1. Clean environment
./test/scripts/cleanup.sh

# 2. Start OpenBao
export BACKEND_TOKEN=temp-token
./test/scripts/start_bao.sh

# 3. Get token from output
export BAO_TOKEN=<token-from-output>
export BAO_ADDR='https://127.0.0.1:8200'
export BAO_SKIP_VERIFY=true

# 4. Run tests
make test-integration
```

### In CI

GitHub Actions automatically:
1. Starts OpenBao in dev mode
2. Sets required environment variables
3. Runs `make test-integration`

## Best Practices

### ✅ DO

- **Use unique names** for all test resources
- **Register cleanup** with `t.Cleanup()` immediately after creating resources
- **Use the shared infrastructure** (PKI mount, auth methods) from `TestMain`
- **Make tests independent** - don't rely on execution order
- **Test idempotency** - call functions multiple times to verify they're safe

### ❌ DON'T

- **Don't use hardcoded names** like `"test-entity-1"` - generates conflicts
- **Don't skip cleanup** - pollutes state for future test runs
- **Don't create new PKI mounts** per test - use the shared mount
- **Don't rely on test execution order** - tests may run in parallel
- **Don't disable auth methods** - they're shared across tests

## Debugging Failed Tests

### Check for State Pollution

```bash
# List all entities
bao list identity/entity/name

# List AppRole roles
bao list auth/approle/role

# List userpass users
bao list auth/userpass/users
```

### Clean Manually

If tests leave resources behind:

```bash
# Delete an entity
bao delete identity/entity/name/<entity-name>

# Delete an AppRole role
bao delete auth/approle/role/<role-name>

# Delete a userpass user
bao delete auth/userpass/users/<username>
```

### Run Single Test

```bash
# Run specific test with verbose output
go test -v -tags=integration ./pkg/backend -run TestIntegration_MyFeature
```

## Common Issues

### "already exists" Errors

**Cause**: Resource names not unique  
**Fix**: Use `generateUniqueTestName()` instead of hardcoded names

### Flaky Tests

**Cause**: Tests interfering with each other  
**Fix**: Add proper cleanup with `t.Cleanup()`

### "mount already in use" Errors

**Cause**: Test trying to create its own PKI mount  
**Fix**: Use the shared `pkiMount` variable from TestMain

### Tests Pass Individually But Fail Together

**Cause**: Missing cleanup causing state pollution  
**Fix**: Add `t.Cleanup()` for all created resources

## Example: Complete Test

```go
func TestIntegration_CompleteWorkflow(t *testing.T) {
    ctx := context.Background()
    
    // Step 1: Create unique entity
    entityName := generateUniqueTestName(t, "workflow-entity")
    t.Cleanup(func() { cleanupEntity(ctx, t, entityName) })
    
    entityID, err := testBackend.CreateOrUpdateEntity(ctx, entityName, 
        map[string]string{"type": "test"}, []string{"default"})
    if err != nil {
        t.Fatalf("CreateOrUpdateEntity failed: %v", err)
    }
    
    // Step 2: Create unique AppRole
    roleName := generateUniqueTestName(t, "workflow-role")
    t.Cleanup(func() { cleanupAppRole(ctx, t, "approle", roleName) })
    
    client := getAPIClient(t) // helper to get API client
    roleID, secretID := setupAppRole(t, ctx, client, roleName)
    
    // Step 3: Test authentication
    token, err := testBackend.AuthenticateAppRole(ctx, "approle", roleID, secretID)
    if err != nil {
        t.Fatalf("AuthenticateAppRole failed: %v", err)
    }
    
    // Step 4: Validate token
    valid, err := testBackend.ValidateToken(ctx, token)
    if err != nil {
        t.Fatalf("ValidateToken failed: %v", err)
    }
    
    if !valid {
        t.Error("Expected token to be valid")
    }
    
    t.Log("Complete workflow successful!")
    
    // Cleanup happens automatically
}
```

## Migration Guide

### Converting Old Tests

**Before** (hardcoded names):
```go
func TestOld(t *testing.T) {
    entityID, _ := testBackend.CreateOrUpdateEntity(ctx, "test-entity", ...)
    // No cleanup
}
```

**After** (unique names + cleanup):
```go
func TestNew(t *testing.T) {
    entityName := generateUniqueTestName(t, "entity")
    t.Cleanup(func() { cleanupEntity(ctx, t, entityName) })
    entityID, _ := testBackend.CreateOrUpdateEntity(ctx, entityName, ...)
}
```

## Contributing

When adding new integration tests:

1. Follow the pattern shown in this guide
2. Use unique resource names
3. Always register cleanup
4. Test locally with multiple runs to verify no state pollution
5. Ensure tests pass in CI

## Questions?

- Check existing tests in `pkg/backend/*_integration_test.go` for examples
- Look at helper functions in `pkg/backend/integration_test.go`
- Ask in team chat or create an issue
