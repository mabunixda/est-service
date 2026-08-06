# EST Service

[![CI](https://github.com/mabunixda/est-service/actions/workflows/ci.yml/badge.svg)](https://github.com/mabunixda/est-service/actions/workflows/ci.yml)
[![Security](https://github.com/mabunixda/est-service/actions/workflows/security.yml/badge.svg)](https://github.com/mabunixda/est-service/actions/workflows/security.yml)
[![CodeQL](https://github.com/mabunixda/est-service/actions/workflows/codeql.yml/badge.svg)](https://github.com/mabunixda/est-service/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/mabunixda/est-service)](https://goreportcard.com/report/github.com/mabunixda/est-service)
[![License](https://img.shields.io/github/license/mabunixda/est-service)](LICENSE)

A production-ready EST (Enrollment over Secure Transport) service implementing RFC 7030, with support for both OpenBao and OpenBao as PKI backends.

## Features

### RFC 7030 Compliance

**Mandatory Endpoints (100% Complete):**
- **`/cacerts`** - CA certificate distribution (PKCS#7)
- **`/simpleenroll`** - Initial certificate enrollment  
- **`/simplereenroll`** - Certificate renewal with existing credentials

**Optional Endpoints (67% Complete):**
- **`/csrattrs`** ✅ - CSR attribute requirements (RFC 7030 §4.5.2)
- **`/serverkeygen`** ✅ - Server-side key generation (RFC 7030 §4.4)
- **`/fullcmc`** ⏸️ - Full CMC support (deferred - low priority)

**Protocol Features:**
- Full base64 transfer encoding support
- PKCS#7 response formatting
- PKCS#10 CSR validation
- Multipart responses for server-generated keys

### Multi-Backend Support
- **OpenBao** - Open source OpenBao fork
- **OpenBao** - Both OSS and Enterprise editions
- Backend auto-detection and abstraction
- Seamless backend switching

### Flexible Authentication
- **HTTP Basic Auth** - Username/password via OpenBao userpass or AppRole (role_id/secret_id)
- **Bearer Token** - Direct OpenBao tokens
- **TLS Client Certificates** - Mutual TLS authentication
- Per-request authentication with backend passthrough

### Production Ready
- **TLS Enforced by Default** - HTTPS required (developer mode available for testing)
- **Health & Readiness Probes** - Kubernetes-compatible endpoints
- **Prometheus Metrics** - Request rates, latencies, error counts
- **Structured Logging** - JSON/text formats with configurable levels
- **Rate Limiting** - Configurable per-endpoint throttling
- **Graceful Shutdown** - Clean connection draining
- **Observability** - Request tracing and audit logging

### Advanced Features
- **Label-based Policies** - Route requests to different PKI roles/mounts via labels
- **TTL Override** - Per-request certificate lifetime configuration
- **CSR Validation** - Size limits, format validation, SAN support
- **Custom Extensions** - Support for certificate extensions
- **Verbatim Signing** - Direct CSR signing without policy modification
- **Server-Side Key Generation** - Secure keypair generation for constrained devices (IoT)
- **CSR Attributes** - Dynamic attribute requirements for client CSR generation
- **Configurable Defaults** - Secure-by-default configuration with optional overrides

## Quick Start

### Prerequisites
- Go 1.21 or higher
- OpenBao instance
- TLS certificates (or use developer mode)

### Installation

**From Source:**
```bash
git clone https://github.com/mabunixda/est-service.git
cd est-service
make build
```

**Pre-built Binaries:**
```bash
# Download from GitHub releases
curl -LO https://github.com/mabunixda/est-service/releases/latest/download/est-service_linux_amd64.tar.gz
tar xzf est-service_linux_amd64.tar.gz
```

**Docker:**
```bash
docker pull ghcr.io/mabunixda/est-service:latest
```

### Local Development Setup

```bash
# 1. Start OpenBao with TLS (for cert auth testing)
./test/scripts/start_openbao_with_tls.sh

# 2. Configure PKI backend
Create a configuration file (see [configs/](configs/) for examples):

```yaml
# Production configuration example
server:
  listen_address: "0.0.0.0:8443"
  tls:
    cert_file: "/etc/est/server.crt"
    key_file: "/etc/est/server.key"
  rate_limit:
    enabled: true
    requests_per_second: 100

backend:
  address: "https://openbao.example.com:8200"
  # Choose one authentication method:
  token: "${BAO_TOKEN}"                    # Token auth
  # OR
  client_cert: "/etc/est/client.crt"         # Certificate auth
  client_key: "/etc/est/client.key"
  
  # Optional TLS verification
  ca_cert: "/etc/est/openbao-ca.crt"
  tls_skip_verify: false

est:
  default_mount: "pki"
  
  # Optional: CSR Attributes endpoint
  csr_attrs:
    enabled: true
    challenge_password: true
  
  # Optional: Server-side key generation for IoT devices
  server_key_gen:
    enabled: true
    use_auth_token: true  # Recommended for security
  
  # Label-based routing (optional)
  labels:
    device:
      type: "role"
      value: "device-cert"
      ttl: "720h"
    server:
      type: "role"
      value: "server-cert"
      ttl: "8760h"
```

### Kubernetes

```bash
# Using Kustomize
kubectl apply -k deployments/kubernetes/

# Or download manifests
curl -LO https://github.com/mabunixda/est-service/releases/latest/download/kubernetes-manifests.tar.gz
tar xzf kubernetes-manifests.tar.gz
kubectl apply -k .
```

See [deployments/kubernetes/README.md](deployments/kubernetes/README.md) for details.

### Systemd Service

```bash
# Install binary
sudo cp est-service /usr/local/bin/
sudo chmod +x /usr/local/bin/est-service

# Create service file
sudo tee /etc/systemd/system/est-service.service << EOF
[Unit]
Description=EST Service
After=network.target

[Service]
Type=simple
User=est
ExecStart=/usr/local/bin/est-service -config /etc/est/config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now est-service
```

## Documentation

### Configuration & Setup
- [Configuration Examples](configs/) - Sample configurations for various scenarios
- [Security Guide](SECURITY.md) - Security best practices and hardening (when created)
- [Kubernetes Deployment](deployments/kubernetes/README.md) - Complete K8s deployment guide

### API Documentation
- [API Reference](api/README.md) - OpenAPI/Swagger specifications and examples
- [RFC 7030](https://tools.ietf.org/html/rfc7030) - EST Protocol specification

### Testing
- [Test Scripts](test/scripts/README.md) - Integration testing guide
- **Integration tests work on macOS, Linux, BSD, and Alpine** (portable shell implementation)

### Unit Tests

```bash
# Run all unit tests (fast, no Docker)
make test

# Unit tests only
make test-unit

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

**Test Coverage**: Run `make test-coverage` to view the current coverage report.
- Coverage varies by package; see the report for details
- Integration tests for PKI operations

### Integration Tests

Integration tests verify PKI operations and authentication against real OpenBao instances in Docker.

**Prerequisites**: Docker Desktop must be running

```bash
# Run integration tests (requires Docker)
make test-integration

# Run all tests (unit + integration)
make test-all

# Generate coverage report
make test-coverage
```

**Integration Test Coverage**:
- PKI operations (GetCACertificate, SignCSR, GetCAChain, etc.)
- Authentication methods (Userpass, Token validation, Certificate auth)
- Error scenarios (invalid roles, domains, credentials)
- Token management (Clone, Lookup, Validate)
- Optional endpoints (csrattrs, serverkeygen)

### End-to-End Testing

**Portable test scripts** (work on macOS, Linux, BSD, Alpine):

```bash
# Complete enrollment test (HTTP Basic Auth)
./test/scripts/test_enrollment.sh

# Certificate authentication test
./test/scripts/test_enrollment_cert.sh

# Verify service health
./test/scripts/verify_est_service.sh

# All integration tests
cd test/scripts && ./run_all.sh
```

See [test/scripts/README.md](test/scripts/README.md) for detailed testing guide.

## Performance

The EST service is designed for high throughput:

- **Concurrent Requests**: Handles thousands of concurrent enrollment requests
- **Rate Limiting**: Configurable per-endpoint throttling
- **Connection Pooling**: Persistent connections to backend
- **Caching**: CA certificate caching to reduce backend load
- **Metrics**: Prometheus metrics for monitoring and alerting

## Security

### Production Deployment Checklist

- [ ] TLS enabled with valid certificates
- [ ] `developer_mode: false` (or omitted)
- [ ] Backend connection uses HTTPS
- [ ] Backend TLS verification enabled (`tls_skip_verify: false`)
- [ ] Rate limiting configured
- [ ] Authentication methods properly configured
- [ ] Secrets stored in environment variables or secret management
- [ ] Network policies restrict backend access
- [ ] Monitoring and alerting configured
- [ ] Regular security scans enabled
- [ ] `/serverkeygen` only enabled for IoT/constrained devices if needed
- [ ] `use_auth_token: true` when using serverkeygen (secure default)

See production security best practices in configuration files.

## Monitoring

### Health Endpoints

```bash
# Health check (returns 200 if healthy)
curl http://localhost:8443/health

# Readiness check (returns 200 if ready to serve)
curl http://localhost:8443/ready
```

### Metrics

Prometheus metrics available at `/metrics`:

#### Core HTTP Metrics
- `est_requests_total` - Total HTTP requests (labels: method, path, status_code)
- `est_request_duration_seconds` - HTTP request duration histogram (in seconds)
- `est_errors_total` - Total errors (labels: method, path, status_code)
- `est_connections_active` - Active connections gauge
- `est_rate_limit_total` - Rate-limited requests counter

#### EST Protocol Metrics
- `est_cacerts_total` - CA certificate requests
- `est_enrollment_total` - Certificate enrollment requests
- `est_reenrollment_total` - Certificate re-enrollment requests

#### Authentication Metrics
- `est_auth_success_total` - Successful authentications (label: method)
- `est_auth_failure_total` - Failed authentications (label: method)

#### Certificate Metrics
- `est_certificates_issued_total` - Certificates issued (labels: operation, ttl)
- `est_certificates_rejected_total` - Certificate rejections (label: operation)
- `est_server_cert_expiry_days` - Days until server TLS cert expires (gauge)

#### Backend Metrics
- `est_backend_requests_total` - Backend API requests (labels: operation, status_code)
- `est_backend_request_duration_seconds` - Backend request duration histogram (in seconds)

### Example Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: 'est-service'
    static_configs:
      - targets: ['est-service:8443']
    metrics_path: '/metrics'
```

## Troubleshooting

### Common Issues

**"TLS must be enabled in production mode"**
- Solution: Either enable TLS with `server.tls.cert_file` and `server.tls.key_file`, or use `developer_mode: true` for local testing only

**"backend authentication required"**
- Solution: Configure either `backend.token`/`backend.token_file` OR `backend.client_cert`/`backend.client_key`

**"no authentication available"**
- Solution: Ensure request includes one of: HTTP Basic Auth header, `Authorization: Bearer <token>` header, or TLS client certificate

**Certificate enrollment fails with 401**
- Check authentication credentials
- Verify backend userpass/token is valid
- Check EST service logs for detailed error

### Debug Logging

```yaml
observability:
  logging:
    level: "debug"  # Enable verbose logging
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development setup
- Code style guidelines
- Testing requirements
- Pull request process
- Commit message conventions

## License

This project is licensed under the Mozilla Public License 2.0 (MPL-2.0) - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [RFC 7030](https://tools.ietf.org/html/rfc7030) - Enrollment over Secure Transport
- [OpenBao](https://www.openbaoproject.io/) - Secrets management
- [OpenBao](https://openbao.org/) - Open source OpenBao fork

## Trademarks

"HashiCorp" and "OpenBao" are trademarks or registered trademarks of HashiCorp, Inc. in the United States and other countries. "OpenBao" is a trademark of the Linux Foundation. This project is not affiliated with, endorsed by, or sponsored by HashiCorp, Inc. or the Linux Foundation.

## Support

- **Issues**: [GitHub Issues](https://github.com/mabunixda/est-service/issues)
- **Discussions**: [GitHub Discussions](https://github.com/mabunixda/est-service/discussions)
- **Documentation**: See [api/README.md](api/README.md) and [test/scripts/README.md](test/scripts/README.md)

## Additional Documentation

- [API Documentation](api/README.md) - OpenAPI spec and request examples
- [Kubernetes Deployment](deployments/kubernetes/README.md) - Complete K8s guide
- [Test Scripts Guide](test/scripts/README.md) - Integration testing
- [Configuration Examples](configs/) - Sample configurations

## Project Structure

```
├── cmd/est-service/      # Main application
├── pkg/
│   ├── auth/             # Authentication manager
│   ├── backend/          # Backend client
│   ├── est/              # EST protocol
│   ├── handlers/         # EST endpoints
│   └── server/           # HTTP server
├── configs/              # Config examples
├── scripts/              # Dev/test scripts
└── test/                 # Test suite
```

## API Endpoints

| Endpoint | Method | Auth | RFC 7030 | Description |
|----------|--------|------|----------|-------------|
| `/.well-known/est/cacerts` | GET | No | Mandatory | Get CA certificates |
| `/.well-known/est/simpleenroll` | POST | Yes | Mandatory | Enroll certificate |
| `/.well-known/est/simplereenroll` | POST | Yes | Mandatory | Renew certificate |
| `/.well-known/est/csrattrs` | GET | No | Optional | Get CSR attribute requirements |
| `/.well-known/est/serverkeygen` | POST | Yes | Optional | Server-side key generation |
| `/health` | GET | No | - | Health check |
| `/ready` | GET | No | - | Readiness probe |
| `/metrics` | GET | No | - | Prometheus metrics |

## Testing

```bash
# Unit tests (fast, no Docker required)
make test

# Integration tests with real backend
cd test/scripts
./setup_backend.sh    # Setup OpenBao
./test_enrollment.sh  # Test enrollment flow
./run_all.sh          # Run all tests

# Unit tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

**Test Coverage:** 
- handlers package: 71.5% coverage
- `/csrattrs` endpoint: 88% coverage  
- `/serverkeygen` endpoint: 81.17% coverage
- Integration tests for PKI operations, authentication, and error scenarios

See [test/scripts/README.md](test/scripts/README.md) for comprehensive testing guide.
