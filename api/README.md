# EST Service API Documentation

This directory contains the OpenAPI/Swagger specification for the EST Service.

## Viewing the Documentation

### Option 1: Swagger UI (Online)

Visit the [Swagger Editor](https://editor.swagger.io/) and paste the contents of `openapi.yaml`.

### Option 2: Local Swagger UI

```bash
# Using Docker
docker run -p 8080:8080 -e SWAGGER_JSON=/openapi.yaml -v $(pwd)/openapi.yaml:/openapi.yaml swaggerapi/swagger-ui

# Then visit http://localhost:8080
```

### Option 3: Redoc (Alternative viewer)

```bash
# Using npx
npx @redocly/cli preview-docs openapi.yaml

# Or with Docker
docker run -p 8080:80 -e SPEC_URL=openapi.yaml -v $(pwd)/openapi.yaml:/usr/share/nginx/html/openapi.yaml redocly/redoc
```

## API Overview

The EST Service implements [RFC 7030](https://datatracker.ietf.org/doc/html/rfc7030) - Enrollment over Secure Transport.

### Endpoints

#### EST Protocol (RFC 7030)

**Mandatory Endpoints:**
- `GET /.well-known/est/cacerts` - Retrieve CA certificates (PKCS#7)
- `POST /.well-known/est/simpleenroll` - Enroll for a new certificate
- `POST /.well-known/est/simplereenroll` - Re-enroll an existing certificate

**Optional Endpoints:**
- `GET /.well-known/est/csrattrs` - Get CSR attribute requirements (RFC 7030 §4.5.2)
- `POST /.well-known/est/serverkeygen` - Server-side key generation (RFC 7030 §4.4)

#### Operational

- `GET /health` - Health check endpoint
- `GET /ready` - Readiness probe (checks backend connectivity)
- `GET /metrics` - Prometheus metrics

### Authentication

The service supports these authentication methods:

1. **HTTP Basic Auth**: Mapped to backend userpass or AppRole authentication
2. **TLS Client Certificates**: Mapped to backend cert authentication
3. **Bearer Token**: Direct backend token authentication
4. **AppRole via Basic Auth**: Basic username/password mapped to role_id/secret_id

### Content Types

- **Request (Enrollment)**: `application/pkcs10` (PKCS#10 CSR in DER format)
- **Response (Certificate)**: `application/pkcs7-mime` (PKCS#7 certs-only)
- **Response (ServerKeyGen)**: `multipart/mixed` with:
  - PKCS#7 certificate (application/pkcs7-mime)
  - PKCS#8 encrypted private key (application/pkcs8)
- **Response (CSR Attrs)**: `application/csrattrs` (ASN.1 DER encoded)
- **Encoding**: All responses use base64 with `Content-Transfer-Encoding: base64`

### Example Requests

#### Get CA Certificates

```bash
curl -k https://localhost:8443/.well-known/est/cacerts
```

#### Simple Enrollment (with Basic Auth)

```bash
# Generate CSR
openssl req -new -newkey rsa:2048 -nodes \
  -keyout device.key -out device.csr \
  -subj "/CN=device001"

# Convert to DER
openssl req -in device.csr -outform DER -out device.csr.der

# Enroll
curl -k -X POST \
  -H "Content-Type: application/pkcs10" \
  -u "username:password" \
  --data-binary @device.csr.der \
  https://localhost:8443/.well-known/est/simpleenroll \
  -o device.p7

# Extract certificate
openssl pkcs7 -inform DER -in device.p7 -print_certs -out device.crt
```

#### Simple Enrollment (with Bearer Token)

```bash
curl -k -X POST \
  -H "Content-Type: application/pkcs10" \
  -H "Authorization: Bearer <your-token>" \
  --data-binary @device.csr.der \
  https://localhost:8443/.well-known/est/simpleenroll
```

#### Re-enrollment (with Client Certificate)

```bash
curl -k -X POST \
  -H "Content-Type: application/pkcs10" \
  --cert device.crt --key device.key \
  --data-binary @new.csr.der \
  https://localhost:8443/.well-known/est/simplereenroll
```

#### Get CSR Attributes

```bash
# Get required CSR attributes
curl -k https://localhost:8443/.well-known/est/csrattrs \
  -o csrattrs.der

# Decode attributes (if needed)
openssl asn1parse -inform DER -in csrattrs.der
```

#### Server-Side Key Generation

```bash
# Generate CSR without private key
openssl req -new -newkey rsa:2048 -nodes \
  -keyout temp.key -out device.csr \
  -subj "/CN=device001"
rm temp.key  # We don't need this - server will generate

# Request server-side key generation
curl -k -X POST \
  -H "Content-Type: application/pkcs10" \
  -u "username:password" \
  --data-binary @device.csr.der \
  https://localhost:8443/.well-known/est/serverkeygen \
  -o response.multipart

# Response is multipart/mixed with certificate and private key
# See RFC 7030 §4.4 for multipart parsing
```

## Metrics

The service exposes Prometheus metrics on `/metrics`:

### Available Metrics

**Core HTTP Metrics:**
- `est_requests_total` - Total HTTP requests (by method, path, status)
- `est_request_duration_seconds` - Request duration histogram
- `est_errors_total` - Total errors
- `est_connections_active` - Active connections
- `est_rate_limit_total` - Rate-limited requests

**EST Protocol Metrics:**
- `est_cacerts_total` - CA certs requests
- `est_enrollment_total` - Enrollment requests
- `est_reenrollment_total` - Re-enrollment requests
- `est_csrattrs_total` - CSR attributes requests
- `est_serverkeygen_total` - Server key generation requests

**Authentication Metrics:**
- `est_auth_success_total` - Successful authentications (by method)
- `est_auth_failure_total` - Failed authentications (by method)

**Certificate Metrics:**
- `est_certificates_issued_total` - Certificates issued (by operation, ttl)
- `est_certificates_rejected_total` - Certificate rejections (by operation)
- `est_server_cert_expiry_days` - Days until server TLS cert expires

**Backend Metrics:**
- `est_backend_requests_total` - Backend API requests (by operation, status)
- `est_backend_request_duration_seconds` - Backend request duration histogram

### OpenTelemetry

The service supports OpenTelemetry with both Prometheus (pull) and OTLP (push) exporters.

Configure in `config.yaml`:

```yaml
observability:
  metrics:
    enabled: true
    prometheus_port: 9090      # Prometheus scraping
    otlp_endpoint: "localhost:4318"  # Optional: OTLP collector
```

## Rate Limiting

Per-IP rate limiting is enforced:

- Default: 100 requests/second per IP
- Burst: 200 requests
- Returns HTTP 429 (Too Many Requests) when exceeded

## TLS Configuration

TLS is required by default. For development only:

```yaml
developer_mode: true  # Disables TLS requirement (NOT for production)
```

## Error Responses

**Standard HTTP Status Codes:**
- `400 Bad Request` - Invalid CSR format, validation failed, or missing required attributes
- `401 Unauthorized` - Authentication required or credentials invalid
- `403 Forbidden` - Authorization failed (valid auth, insufficient permissions)
- `404 Not Found` - Endpoint not found or disabled
- `413 Payload Too Large` - CSR exceeds size limit
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Backend error or internal failure
- `503 Service Unavailable` - Service not ready (backend unreachable)

**EST-Specific Error Scenarios:**
- CSR signature verification failure → 400
- Unsupported key algorithm → 400
- Subject/SAN mismatch in re-enrollment → 400
- Backend PKI role not found → 403
- Backend policy violation → 403

## Security

### Production Checklist

- [ ] TLS enabled with valid certificates
- [ ] `developer_mode: false`
- [ ] Rate limiting enabled
- [ ] Backend TLS verification enabled
- [ ] Strong authentication configured
- [ ] Audit logging enabled (via backend)
- [ ] Metrics secured (firewall rules)
- [ ] `/serverkeygen` only enabled if needed for constrained devices
- [ ] `use_auth_token: true` when serverkeygen is enabled
- [ ] CSR size limits configured appropriately

See configuration examples in the [configs/](../configs/) directory.

## Support

For issues and questions:
- GitHub Issues: https://github.com/mabunixda/est-service/issues
- RFC 7030: https://datatracker.ietf.org/doc/html/rfc7030
