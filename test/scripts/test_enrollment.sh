#!/usr/bin/env bash
# EST Service Enrollment Test Script
# Tests certificate enrollment via the EST service
# Adapted from OpenBao est_curl.sh for standalone est-service

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

SKIP_CLEANUP=${SKIP_CLEANUP:-}
cd "$TEST_DIR"

log_section "EST Service Enrollment Test"

log_info "EST Service: $EST_SERVICE_ADDR"
log_info "Backend: $BACKEND_TYPE at $BACKEND_ADDR"
log_info "Test directory: $TEST_DIR"

# Step 1: Get CA certificates (unauthenticated)
log_section "Step 1: Get CA Certificates"

log_info "Requesting CA certificates from EST service..."
HTTP_CODE=$(curl -sk -o cacerts.b64 -w "%{http_code}" \
    "$EST_SERVICE_ADDR/.well-known/est/cacerts")

if [ "$HTTP_CODE" = "200" ]; then
    log_success "✓ CA certificates retrieved (HTTP $HTTP_CODE)"
else
    log_error "✗ Failed to get CA certificates (HTTP $HTTP_CODE)"
    exit 1
fi

log_info "Decoding CA certificates..."
base64_decode cacerts.b64 cacerts.p7
if openssl pkcs7 -inform DER -in cacerts.p7 -print_certs -out cacerts.pem 2>/dev/null; then
    log_success "✓ CA certificates decoded successfully"
    openssl x509 -in cacerts.pem -text -noout | grep -E "(Subject:|Issuer:)"
else
    log_error "✗ Failed to decode CA certificates"
    exit 1
fi

# Step 2: Generate device key and CSR
log_section "Step 2: Generate Device Key and CSR"

log_info "Generating device private key..."
openssl genrsa -out device.key 2048 2>/dev/null
log_success "✓ Device private key generated"

log_info "Generating CSR..."
openssl req -new -key device.key -out device.csr \
    -subj "/CN=my-device.example.com/O=My Org/C=US" 2>/dev/null
openssl req -in device.csr -outform DER -out device.csr.der
log_success "✓ CSR generated"

# Step 3: Enroll certificate (HTTP Basic Auth)
log_section "Step 3: Enroll Certificate"

log_info "Enrolling certificate with HTTP Basic Auth (user: $EST_USERNAME)..."
HTTP_CODE=$(curl -sk -o cert.b64 -w "%{http_code}" -X POST \
    -u "$EST_USERNAME:$EST_PASSWORD" \
    -H "Content-Type: application/pkcs10" \
    --data-binary "@device.csr.der" \
    "$EST_SERVICE_ADDR/.well-known/est/simpleenroll")

if [ "$HTTP_CODE" = "200" ]; then
    log_success "✓ Certificate enrolled (HTTP $HTTP_CODE)"
else
    log_error "✗ Enrollment failed (HTTP $HTTP_CODE)"
    cat cert.b64 2>/dev/null || echo "(no response)"
    exit 1
fi

log_info "Decoding enrolled certificate..."
base64_decode cert.b64 cert.p7
if openssl pkcs7 -inform DER -in cert.p7 -print_certs -out device.pem 2>/dev/null; then
    log_success "✓ Certificate decoded successfully"
    openssl x509 -in device.pem -text -noout | grep -E "(Subject:|Serial Number:|Not Before|Not After)"
else
    log_error "✗ Failed to decode certificate"
    exit 1
fi

# Step 4: Verify certificate
log_section "Step 4: Verify Certificate"

log_info "Verifying certificate against CA..."
if openssl verify -CAfile cacerts.pem device.pem; then
    log_success "✓ Certificate verification successful"
else
    log_error "✗ Certificate verification failed"
    exit 1
fi

log_info "Verifying key matches certificate..."
KEY_MODULUS=$(openssl rsa -noout -modulus -in device.key 2>/dev/null | openssl md5)
CERT_MODULUS=$(openssl x509 -noout -modulus -in device.pem | openssl md5)

if [ "$KEY_MODULUS" = "$CERT_MODULUS" ]; then
    log_success "✓ Private key matches certificate"
    echo "  Modulus MD5: $KEY_MODULUS"
else
    log_error "✗ Private key does not match certificate"
    echo "  Key:  $KEY_MODULUS"
    echo "  Cert: $CERT_MODULUS"
    exit 1
fi

# Step 5: Re-enrollment
log_section "Step 5: Certificate Re-enrollment"

log_info "Generating new CSR for re-enrollment..."
openssl req -new -key device.key -out device-renew.csr \
    -subj "/CN=my-device.example.com/O=My Org Renewed/C=US" 2>/dev/null
openssl req -in device-renew.csr -outform DER -out device-renew.csr.der
log_success "✓ Renewal CSR generated"

log_info "Re-enrolling certificate with client cert + HTTP Basic Auth..."
HTTP_CODE=$(curl -sk -o reenrolled-cert.b64 -w "%{http_code}" -X POST \
    -u "$EST_USERNAME:$EST_PASSWORD" \
    -H "Content-Type: application/pkcs10" \
    --data-binary "@device-renew.csr.der" \
    "$EST_SERVICE_ADDR/.well-known/est/simplereenroll")

if [ "$HTTP_CODE" = "200" ]; then
    log_success "✓ Certificate re-enrolled (HTTP $HTTP_CODE)"
else
    log_error "✗ Re-enrollment failed (HTTP $HTTP_CODE)"
    cat reenrolled-cert.b64 2>/dev/null || echo "(no response)"
    exit 1
fi

log_info "Decoding re-enrolled certificate..."
base64_decode reenrolled-cert.b64 reenrolled-cert.p7
if openssl pkcs7 -inform DER -in reenrolled-cert.p7 -print_certs -out reenrolled-cert.pem 2>/dev/null; then
    log_success "✓ Re-enrolled certificate decoded successfully"
    openssl x509 -in reenrolled-cert.pem -text -noout | grep -E "(Subject:|Serial Number:|Not Before|Not After)"
else
    log_error "✗ Failed to decode re-enrolled certificate"
    exit 1
fi

log_info "Verifying re-enrolled certificate..."
if openssl verify -CAfile cacerts.pem reenrolled-cert.pem; then
    log_success "✓ Re-enrolled certificate verification successful"
else
    log_error "✗ Re-enrolled certificate verification failed"
    exit 1
fi

log_section "All Tests Passed!"
log_success "✓ CA certificate retrieval"
log_success "✓ Initial enrollment (simpleenroll)"
log_success "✓ Certificate verification"
log_success "✓ Certificate re-enrollment (simplereenroll)"

echo ""
log_info "Test artifacts saved in: $TEST_DIR"
echo "  - cacerts.pem: CA certificate chain"
echo "  - device.key: Device private key"
echo "  - device.pem: Initial enrolled certificate"
echo "  - reenrolled-cert.pem: Re-enrolled certificate"
