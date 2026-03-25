# EST Service Test Scripts

Integration test scripts for the EST service. These scripts test the EST protocol implementation against a running EST service with OpenBao backend.

**✅ Portable:** All scripts work on macOS, Linux, BSD, and Alpine Linux (no GNU-specific dependencies).

## Prerequisites

- **Backend**: OpenBao (`bao`) or OpenBao CLI installed
- **Tools**: `openssl`, `curl`, `jq`, `base64` (standard versions)
- **Optional**: `estclient` (for estclient-based tests)
- **Running Backend**: OpenBao server running and accessible (can be started with included scripts)
- **Running EST Service**: EST service running and accessible

## Quick Start (Certificate Authentication)

For testing certificate authentication (recommended), use the certificate enrollment test:

```bash
# Run certificate authentication enrollment test
./test_enrollment_cert.sh
```

This test will:
1. Use an existing backend configuration or set up a new one
2. Perform complete certificate enrollment lifecycle:
   - Get CA certificates
   - Enroll initial certificate with HTTP Basic Auth
   - Verify certificate validity
   - Re-enroll using the certificate for authentication
   - Test certificate chain validation
3. Clean up test artifacts

**Features tested:**
- `/cacerts` endpoint
- `/simpleenroll` endpoint with HTTP Basic Auth
- `/simplereenroll` endpoint with certificate authentication
- CSR generation with matching subject and SANs
- Certificate chain validation
- Proper PKCS#7 parsing

## Manual Setup

### Option A: Start Local OpenBao with TLS (For Certificate Authentication)

Certificate authentication requires TLS between EST service and OpenBao. Use the included script:

```bash
# Start OpenBao with TLS enabled
./start_bao_with_tls.sh

# This creates:
# - OpenBao CA certificate
# - OpenBao server TLS certificate
# - OpenBao configuration with TLS
# - Initialized and unsealed OpenBao instance

# Stop OpenBao when done
./stop_bao.sh
```

### Option B: Use Existing Backend

If you have an existing OpenBao instance:

```bash
export BACKEND_TYPE=bao          # or openbao
export BACKEND_ADDR=https://localhost:8200  # Use HTTPS for cert auth
export BACKEND_TOKEN=your-token
export PKI_PATH=pki
```

### Setup Backend (PKI + Authentication)

After starting OpenBao or configuring your backend connection:

```bash
# Use default configuration
./setup_backend.sh

# Enable certificate authentication (required for cert auth tests)
export ENABLE_CERT_AUTH=true
./setup_backend.sh
```

This script will:
- Configure PKI backend with a root CA
- Create a PKI role for EST enrollment
- Setup userpass authentication
- Setup TLS client certificate authentication (if ENABLE_CERT_AUTH=true)
- Generate test certificates (client cert, server cert, etc.)

**Portability Note:** This script uses pure shell for certificate parsing (no GNU-specific tools like `csplit` with extended syntax).

### Start EST Service

Configure and start the EST service pointing to your backend:

```bash
# Edit configs/est-service.yaml with your backend settings
# Then start the service
./bin/est-service -config configs/est-service.yaml
```

### Run Tests

```bash
# Test basic enrollment flow (username/password auth)
./test_enrollment.sh

# Test certificate enrollment (recommended - tests full lifecycle)
./test_enrollment_cert.sh

# Verify service health
./verify_est_service.sh

# Run all tests
./run_all.sh
```

**All scripts are portable** and work on:
- ✅ macOS (tested)
- ✅ Linux (tested)
- ✅ BSD (compatible)
- ✅ Alpine/Busybox (compatible)

## Configuration

All scripts source `config.sh` for shared configuration. This file includes:
- Environment variable defaults
- Portable helper functions (e.g., `base64_decode` that works on both macOS and Linux)
- Common utility functions

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EST_SERVICE_ADDR` | `https://127.0.0.1:8443` | EST service address |
| `BACKEND_TYPE` | `openbao` | Backend type: `openbao` or  |
| `BACKEND_ADDR` | `https://127.0.0.1:8200` | Backend server address |
| `BACKEND_TOKEN` | `root` | Backend authentication token |
| `PKI_PATH` | `pki` | PKI mount path in backend |
| `EST_USERNAME` | `est-device` | Test user for HTTP Basic Auth |
| `EST_PASSWORD` | `device-secret-123` | Test password for HTTP Basic Auth |

### Quick Start

```bash
# Start test instance
./run_test_instance.sh
```

### Run Tests with estclient

Using [estclient](https://github.com/globalsign/est/):

```bash
# Install the estclient
go install github.com/globalsign/est/cmd/estclient@latest

# Test enrollment with username/password authentication
./estclient_user.sh

# Test enrollment with TLS client certificate authentication
./estclient_certs.sh
```

### Custom Configuration

```bash
export BACKEND_TYPE=bao
export BACKEND_ADDR=https://bao.example.com:8200
export BACKEND_TOKEN=s.xxxxxxxxxxxxxx
export EST_SERVICE_ADDR=https://est.example.com:8443
export PKI_PATH=est-pki

./setup_backend.sh
./test_enrollment.sh
```

## Test Scripts

### config.sh

Shared configuration and portable utility functions:
- Environment variable defaults
- `base64_decode()` - Portable base64 decoding (works on macOS `-D` and Linux `-d`)
- Color output functions
- Common validation functions

### setup_backend.sh

Prepares the OpenBao backend for EST testing:
- Creates PKI mount and root CA
- Configures PKI role for EST enrollment
- Sets up authentication methods (userpass, cert auth)
- Uses portable shell for all operations (no GNU-specific tools)

### test_enrollment.sh

Basic enrollment test using HTTP Basic Auth:
- Tests `/cacerts` endpoint
- Tests `/simpleenroll` with username/password
- Validates certificate issuance

### test_enrollment_cert.sh

**Complete certificate lifecycle test** - Most comprehensive test:
1. Get CA certificates (`/cacerts`)
2. Initial enrollment with HTTP Basic Auth (`/simpleenroll`)
3. Certificate validation
4. Re-enrollment with certificate auth (`/simplereenroll`)
5. Proper CSR generation (matching subject and SANs from issued cert)
6. Chain validation

**Key feature:** Dynamically extracts subject and SANs from issued certificate to avoid hardcoding mismatches.

### verify_est_service.sh

Health and endpoint verification:
- Tests `/health` endpoint
- Tests `/ready` endpoint
- Validates service availability

### estclient_user.sh

Uses `estclient` tool for enrollment with HTTP Basic Auth:
- Requires `estclient` binary installed
- Tests username/password authentication

### estclient_certs.sh

Uses `estclient` tool for certificate-based enrollment:
- Requires `estclient` binary installed
- Tests TLS client certificate authentication

### start_bao_with_tls.sh

Starts a local OpenBao instance with TLS enabled:
- Generates OpenBao CA and server certificates
- Configures OpenBao with TLS
- Initializes and unseals OpenBao
- Required for certificate authentication tests

### stop_bao.sh

Stops the running OpenBao instance started by `start_bao_with_tls.sh`.

### run_all.sh

Runs all test scripts in sequence for comprehensive validation.

## Portability Improvements

Recent updates ensure all scripts work across platforms:

1. **base64 decoding**: `base64_decode()` function handles both macOS (`-D`) and Linux (`-d`) flags
2. **Certificate parsing**: Pure shell implementation instead of GNU `csplit` with extended syntax
3. **CSR generation**: Dynamic subject/SAN extraction from issued certificates (no hardcoding)
4. **Tool detection**: Graceful fallbacks when optional tools are unavailable

## Troubleshooting

### Common Issues

**"csplit: *}: bad repetition count"** (FIXED)
- This error occurred on macOS/BSD with old scripts
- Now resolved with portable shell loop implementation

**"base64: invalid option" (FIXED)**
- Different flags between macOS and Linux
- Now resolved with `base64_decode()` wrapper function

**"HTTP 400: Subject and SubjectAltName must match"** (FIXED)
- Occurred during re-enrollment with hardcoded CSR fields
- Now resolved by extracting actual subject/SANs from issued certificate

### Debug Mode

Enable debug output in any script:
```bash
set -x
./test_enrollment_cert.sh
```

### Manual Testing

Test individual endpoints:
```bash
# Get CA certs
curl -k https://localhost:8443/.well-known/est/cacerts

# Check health
curl -k https://localhost:8443/health

# Test enrollment (requires valid CSR)
curl -k -X POST \
  -H "Content-Type: application/pkcs10" \
  -u "username:password" \
  --data-binary @device.csr.der \
  https://localhost:8443/.well-known/est/simpleenroll
```