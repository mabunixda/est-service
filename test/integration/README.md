# Integration Tests

This directory contains integration tests for the EST service that require a running OpenBAO instance.

## Overview

The integration tests validate the full end-to-end functionality of the EST service including:
- Certificate enrollment (simple and re-enroll)
- Multiple authentication methods (basic auth, bearer token, client certificates)
- CSR validation and policy enforcement
- Label-based certificate policies
- Error handling and edge cases

## Prerequisites

### 1. Running OpenBao Instance

You need a running OpenBAO instance. The tests are designed to work with either:
- **OpenBao** (recommended for open-source deployments)
- **OpenBao** (OSS or Enterprise)

### 2. Environment Variables

Set the following environment variables to configure the connection:

```bash
# OpenBao configuration (preferred)
export BAO_ADDR=https://localhost:8200
export BAO_TOKEN=<your-root-or-admin-token>

# OR OpenBao configuration
export BAO_ADDR=https://localhost:8200
export BAO_TOKEN=<your-root-or-admin-token>

# Optional: Skip TLS verification (for dev/test only)
export BAO_SKIP_VERIFY=true
```

## Quick Start

### Option 1: Using Docker Compose (Recommended)

The easiest way to run integration tests is using the provided Docker Compose setup:

```bash
# Start OpenBao in dev mode
docker-compose -f test/integration/docker-compose.yml up -d

# Export environment variables
export BAO_ADDR=https://localhost:8200
export BAO_TOKEN=root
export BAO_ADDR=https://localhost:8200
export BAO_TOKEN=root
export BAO_SKIP_VERIFY=true

# Run integration tests
make test-integration

# Cleanup when done
docker-compose -f test/integration/docker-compose.yml down
```

### Option 2: Using Existing Instance

If you already have OpenBao running:

```bash
# Set connection details
export BAO_ADDR=<your-instance-url>
export BAO_TOKEN=<your-token>
export BAO_SKIP_VERIFY=true  # if using self-signed certs

# Run integration tests
make test-integration
```

### Option 3: Manual OpenBao Setup

```bash
# Start OpenBao in dev mode
openbao server -dev -dev-root-token-id=root

# In another terminal, set environment
export BAO_ADDR=https://127.0.0.1:8200
export BAO_TOKEN=root
export BAO_SKIP_VERIFY=true

# Run tests
make test-integration
```

## Test Structure

### Test Suites

1. **`test/integration/`** - High-level EST service integration tests
   - Uses PKI mount: `pki-test`
   - Tests full EST protocol endpoints
   - Validates authentication flows

2. **`pkg/backend/`** - Backend/client integration tests
   - Uses PKI mount: `pki-backend-test` 
   - Tests OpenBao API client operations
   - Validates authentication methods (userpass, AppRole, cert, LDAP)
   - Tests entity and alias management
   - Tests Transit key generation (for server-side key generation)
   - All tests are tagged with `//go:build integration`

### Backend Integration Tests

The `pkg/backend/` directory contains low-level integration tests for the OpenBao client:

- **`client_integration_test.go`**: Tests `NewClient()`, `NewClientWithBackend()`, token operations
- **`approle_integration_test.go`**: Tests AppRole authentication (requires AppRole auth method)
- **`entity_integration_test.go`**: Tests entity and entity alias management
- **`ldap_integration_test.go`**: Tests LDAP authentication (requires LDAP server - skipped if not configured)
- **`transit_integration_test.go`**: Tests Transit key generation (requires Transit secrets engine)
- **`integration_test.go`**: Tests PKI operations (CA certificate, CSR signing, etc.)

#### LDAP Testing (Optional)

LDAP tests are skipped by default. To enable them, set these environment variables:

```bash
export LDAP_URL=ldap://localhost:389
export LDAP_BIND_DN=cn=admin,dc=example,dc=com
export LDAP_BIND_PASS=adminpassword
export LDAP_USER_DN=ou=users,dc=example,dc=com
export LDAP_TEST_USER=testuser
export LDAP_TEST_PASS=testpass
```

### PKI Mount Configuration

The tests use separate PKI mounts to avoid conflicts:

| Test Suite | PKI Mount | Purpose |
|---|---|---|
| `test/integration/` | `pki-test` | EST service endpoint tests |
| `pkg/backend/` | `pki-backend-test` | Backend API tests |

You can override the PKI mount path using:
```bash
export PKI_MOUNT_PATH=my-custom-pki-mount
```

## Running Tests

### Run All Integration Tests

```bash
make test-integration
```

This runs integration tests in both `test/integration/` and `pkg/backend/`.

### Run Specific Test Suite

```bash
# Only EST service integration tests
go test -v -tags=integration ./test/integration

# Only backend integration tests
go test -v -tags=integration ./pkg/backend
```

### Run Specific Test

```bash
# Run a single test
go test -v -tags=integration -run TestBasicAuth ./test/integration

# Run tests matching a pattern
go test -v -tags=integration -run "TestCert.*" ./test/integration
```

### Run Tests with Coverage

```bash
go test -v -tags=integration -coverprofile=coverage_integration.out ./test/integration ./pkg/backend
go tool cover -html=coverage_integration.out
```

## Test Initialization

The integration tests automatically initialize the OpenBao instance with:

### PKI Configuration
- Enables PKI secrets engine
- Generates root CA certificate
- Creates test roles with allowed domains
- Configures CA and CRL URLs

### Authentication Methods
- **Userpass**: Test users for basic authentication
  - Username: `testuser` / `est-device`
  - Passwords configured per test
- **Token**: Direct token authentication
- **Certificate**: Client certificate authentication
- **AppRole**: Machine-to-machine authentication (tested in backend tests)
  - Dynamically created roles for each test
- **LDAP**: LDAP directory authentication (optional, requires LDAP server)

### Idempotency

The test initialization is **idempotent** - it can be run multiple times safely:
- Checks if PKI mounts exist before creating
- Checks if CA exists before generating
- Updates roles and users instead of failing on duplicates
- Safe to run tests repeatedly without manual cleanup

## Test Data

The tests use the following configuration:

### PKI Settings
- **CA Common Name**: `Test Root CA` (backend tests) or `EST Test CA` (service tests)
- **CA TTL**: 87600h (10 years)
- **Key Type**: RSA 2048-bit
- **Allowed Domains**: `example.com`, `test.local`, `*.example.org`

### Test Users
- **testuser**: Standard test user
- **est-device**: Device enrollment user

### Test Roles
- **test-role**: General purpose role
  - Allowed domains: `example.com`, `test.local`
  - Max TTL: 720h
- **short-ttl**: Short-lived certificates
  - Max TTL: 1h

## Troubleshooting

### Tests Fail with "connection refused"

Ensure OpenBao is running and accessible:
```bash
curl -k $BAO_ADDR/v1/sys/health
```

### Tests Fail with "permission denied"

Ensure your token has sufficient permissions:
```bash
# Check token info
bao token lookup
# or
openbao token lookup
```

The token needs capabilities to:
- Mount PKI secrets engines
- Generate root CAs
- Create roles and policies
- Enable authentication methods

### Tests Fail with "mount already exists"

This is usually not a problem - the tests are idempotent. However, if you want to start fresh:

```bash
# Unmount test PKI engines
bao secrets disable pki-test
bao secrets disable pki-backend-test

# Or via OpenBao
openbao secrets disable pki-test
openbao secrets disable pki-backend-test
```

### PKI CA Issues

If the CA isn't being created properly:

```bash
# Check if mount exists
bao secrets list

# Check if CA exists
bao read pki-test/cert/ca

# Manually create CA if needed
bao write pki-test/root/generate/internal \
  common_name="EST Test CA" \
  ttl=87600h
```

### JSON Unmarshal Errors

If you see errors like "json: cannot unmarshal number into Go value":
- This was fixed by using `/cert/ca` endpoint instead of `/ca`
- Ensure you're running the latest version of the code
- The `/cert/ca` endpoint returns JSON with PEM certificate
- The `/ca` endpoint returns raw DER format

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      openbao:
        image: openbao/openbao:latest
        env:
          OPENBAO_DEV_ROOT_TOKEN_ID: root
          OPENBAO_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
        ports:
          - 8200:8200
    
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Run Integration Tests
        env:
          BAO_ADDR: http://localhost:8200
          BAO_TOKEN: root
          BAO_ADDR: http://localhost:8200
          BAO_TOKEN: root
        run: make test-integration
```

## Best Practices

### For Test Development

1. **Use idempotent initialization**: Don't assume clean state
2. **Clean up resources**: Although not critical due to dev mode
3. **Use unique identifiers**: For parallel test safety
4. **Test both success and failure**: paths

### For CI/CD

1. **Use ephemeral instances**: Dev mode or containers
2. **Set appropriate timeouts**: Default is 2 minutes
3. **Run unit tests first**: Integration tests are slower
4. **Cache Go modules**: To speed up builds

## Environment Variables Reference

| Variable | Purpose | Default | Required |
|---|---|---|---|
| `BAO_ADDR` | OpenBao server URL | - | Yes (or BAO_ADDR) |
| `BAO_TOKEN` | OpenBao auth token | - | Yes (or BAO_TOKEN) |
| `BAO_ADDR` | OpenBao server URL | - | Yes (or BAO_ADDR) |
| `BAO_TOKEN` | OpenBao auth token | - | Yes (or BAO_TOKEN) |
| `BAO_SKIP_VERIFY` | Skip TLS verification | `false` | No |
| `PKI_MOUNT_PATH` | Custom PKI mount path | `pki-backend-test` | No |
| `BACKEND_TYPE` | Force backend type | Auto-detect | No |

## Additional Resources

- [OpenBao Documentation](https://openbao.org/docs/)
- [OpenBao PKI Secrets Engine](https://developer.hashicorp.com/bao/docs/secrets/pki)
- [EST Protocol RFC 7030](https://datatracker.ietf.org/doc/html/rfc7030)
- [Project README](../../README.md)
