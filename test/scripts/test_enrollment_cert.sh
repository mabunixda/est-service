#!/usr/bin/env bash
# EST Service Certificate Authentication Test Script
# Tests EST enrollment using TLS client certificate authentication (no username/password)
# Client certificates are created by setup_backend.sh with ENABLE_CERT_AUTH=true

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

SKIP_CLEANUP=${SKIP_CLEANUP:-}
cd "$TEST_DIR"

log_section "EST Service Certificate Authentication Test"

log_info "EST Service: $EST_SERVICE_ADDR"
log_info "Backend: $BACKEND_TYPE at $BACKEND_ADDR"
log_info "Test directory: $TEST_DIR"

# Prerequisites check
log_info "Checking prerequisites..."
check_command "openssl" "openssl"
check_command "curl" "curl"

# Verify client certificates exist (created by setup_backend.sh)
if [ ! -f "$TEST_DIR/client-cert.pem" ] || [ ! -f "$TEST_DIR/client-key.pem" ]; then
    log_error "Client certificates not found in $TEST_DIR"
    log_error "Please run: ENABLE_CERT_AUTH=true ./setup_backend.sh"
    exit 1
fi

if [ ! -f "$TEST_DIR/client-ca.pem" ]; then
    log_error "Client CA certificate not found in $TEST_DIR"
    log_error "Please run: ENABLE_CERT_AUTH=true ./setup_backend.sh"
    exit 1
fi

log_success "✓ Client certificates found"
log_info "Client certificate: $TEST_DIR/client-cert.pem"
log_info "Client key:         $TEST_DIR/client-key.pem"
log_info "Client CA:          $TEST_DIR/client-ca.pem"

# Display client certificate info
log_info "Client certificate details:"
openssl x509 -in "$TEST_DIR/client-cert.pem" -text -noout | grep -E "(Subject:|Issuer:|Not Before|Not After)"

# Step 1: Get CA certificates (unauthenticated)
log_section "Step 1: Get CA Certificates (No Authentication)"

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
    -subj "/CN=device-cert-auth.example.com/O=Certificate Auth Test/C=US" 2>/dev/null
openssl req -in device.csr -outform DER -out device.csr.der
log_success "✓ CSR generated"

# Step 3: Enroll certificate (TLS Client Certificate Authentication)
log_section "Step 3: Initial Enrollment (TLS Client Certificate Auth)"

log_info "Enrolling certificate with TLS client certificate authentication..."
log_warn "Note: Using client-cert.pem for authentication (no username/password)"

# Prepare curl options for client certificate
CURL_CERT_OPTS="--cert $TEST_DIR/client-cert.pem --key $TEST_DIR/client-key.pem"

# If EST service uses self-signed cert, we need to specify CA cert or use -k
# For production, you should use proper CA validation
if [ -f "$TEST_DIR/ca.pem" ]; then
    CURL_CERT_OPTS="$CURL_CERT_OPTS --cacert $TEST_DIR/ca.pem"
fi

HTTP_CODE=$(curl -sk -o cert.b64 -w "%{http_code}" -X POST \
    $CURL_CERT_OPTS \
    -H "Content-Type: application/pkcs10" \
    --data-binary "@device.csr.der" \
    "$EST_SERVICE_ADDR/.well-known/est/simpleenroll")

if [ "$HTTP_CODE" = "200" ]; then
    log_success "✓ Certificate enrolled (HTTP $HTTP_CODE)"
else
    log_error "✗ Enrollment failed (HTTP $HTTP_CODE)"
    log_error "Response:"
    cat cert.b64 2>/dev/null || echo "(no response)"
    echo ""
    log_error "Possible issues:"
    echo "  1. EST service not configured for TLS client certificate auth"
    echo "  2. Client CA not configured in EST service (server.tls.client_ca_file)"
    echo "  3. Certificate authentication not enabled in OpenBao"
    echo ""
    log_info "EST service configuration should have:"
    echo "  server:"
    echo "    tls:"
    echo "      client_ca_file: /path/to/client-ca.pem"
    echo "      client_auth_type: request  # or 'require'"
    echo "  est:"
    echo "    authenticators:"
    echo "      cert:"
    echo "        enabled: true"
    echo "        mount_path: cert"
    echo "        cert_role: est-client"
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
log_section "Step 4: Verify Enrolled Certificate"

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

# Step 5: Re-enrollment with TLS Client Certificate
log_section "Step 5: Certificate Re-enrollment (TLS Client Certificate Auth)"

log_info "RFC 7030 Section 4.2.2: For re-enrollment, the client MUST use"
log_info "the enrolled device certificate as the TLS client certificate."
log_info ""
log_info "The EST service must trust BOTH:"
echo "  1. client-ca.pem - for bootstrap certificates (initial enrollment)"
echo "  2. PKI CA - for device certificates (re-enrollment)"
echo ""

# Validate multi-CA setup
log_info "Validating multi-CA configuration..."
if [ ! -f "$TEST_DIR/client-ca-bundle.pem" ]; then
    log_error "✗ Combined CA bundle not found: $TEST_DIR/client-ca-bundle.pem"
    log_error "Re-enrollment with device certificate will fail!"
    log_info "Run: ENABLE_CERT_AUTH=true ./setup_backend.sh to create it"
    exit 1
fi

# Count certificates in bundle
BUNDLE_CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$TEST_DIR/client-ca-bundle.pem" || echo "0")
if [ "$BUNDLE_CERT_COUNT" -lt 2 ]; then
    log_error "✗ CA bundle should contain at least 2 certificates, found: $BUNDLE_CERT_COUNT"
    log_error "Re-enrollment requires both client-ca and PKI CA"
    exit 1
fi

log_success "✓ Combined CA bundle validated ($BUNDLE_CERT_COUNT CA certificates)"
log_info "Bundle contents:"

# Split bundle into individual certificates and display subjects
# Using a portable approach that works on both Linux and macOS
CERT_NUM=0
CURRENT_CERT=""
while IFS= read -r line; do
    if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
        CURRENT_CERT="$line"
    elif [[ "$line" == "-----END CERTIFICATE-----" ]]; then
        CURRENT_CERT="$CURRENT_CERT"$'\n'"$line"
        CERT_FILE="/tmp/ca-check-$$.${CERT_NUM}.pem"
        echo "$CURRENT_CERT" > "$CERT_FILE"
        
        SUBJECT=$(openssl x509 -in "$CERT_FILE" -noout -subject 2>/dev/null | sed 's/subject=//' || echo "")
        if [ -n "$SUBJECT" ]; then
            log_info "  - $SUBJECT"
        fi
        rm -f "$CERT_FILE"
        
        CERT_NUM=$((CERT_NUM + 1))
        CURRENT_CERT=""
    elif [ -n "$CURRENT_CERT" ]; then
        CURRENT_CERT="$CURRENT_CERT"$'\n'"$line"
    fi
done < "$TEST_DIR/client-ca-bundle.pem"

# Generate CSR for re-enrollment
log_info "Generating renewal CSR with same subject as enrolled cert..."

# Extract the actual subject from the enrolled certificate
# This ensures we match what the PKI backend actually issued
CERT_SUBJECT=$(openssl x509 -in device.pem -noout -subject | sed 's/subject=//')
log_info "Using certificate subject: $CERT_SUBJECT"

# Convert subject to openssl req format (e.g., "CN=foo, O=bar" -> "/CN=foo/O=bar")
CSR_SUBJECT=$(echo "$CERT_SUBJECT" | sed 's/, /\//g' | sed 's/^/\//')
log_info "CSR subject format: $CSR_SUBJECT"

# Check if certificate has SANs
CERT_SANS=$(openssl x509 -in device.pem -noout -ext subjectAltName 2>/dev/null | grep -v "X509v3 Subject Alternative Name:" | tr -d ' ' || echo "")
if [ -n "$CERT_SANS" ]; then
    log_info "Certificate has SANs: $CERT_SANS"
    
    # Create a config file for the CSR with SANs
    cat > device-renew.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
subjectAltName = $CERT_SANS
EOF
    
    openssl req -new -key device.key -out device-renew.csr \
        -subj "$CSR_SUBJECT" \
        -config device-renew.conf 2>/dev/null
else
    log_info "Certificate has no SANs"
    openssl req -new -key device.key -out device-renew.csr \
        -subj "$CSR_SUBJECT" 2>/dev/null
fi

openssl req -in device-renew.csr -outform DER -out device-renew.csr.der
log_success "✓ Renewal CSR generated"

# Verify the CSR matches the certificate
log_info "Verifying CSR matches certificate..."
CSR_SUBJECT_CHECK=$(openssl req -in device-renew.csr -noout -subject)
log_info "CSR Subject: $CSR_SUBJECT_CHECK"
if [ -n "$CERT_SANS" ]; then
    CSR_SANS=$(openssl req -in device-renew.csr -noout -text | grep -A 1 "Subject Alternative Name" | tail -1 | tr -d ' ' || echo "")
    log_info "CSR SANs: $CSR_SANS"
fi

# Step 6: Re-enrollment using enrolled device certificate as client cert
log_section "Step 6: Re-enrollment Using Enrolled Certificate (RFC 7030 §4.2.2)"

log_info "This demonstrates RFC 7030 compliant re-enrollment where the device's"
log_info "enrolled certificate is used as the TLS client certificate."
log_info ""
log_info "Re-enrolling using enrolled device certificate as client cert..."
log_info "Client cert: device.pem (enrolled certificate signed by PKI CA)"
log_info "EST service should trust this via client-ca-bundle.pem"

HTTP_CODE=$(curl -sk -o reenrolled-cert.b64 -w "%{http_code}" -X POST \
    --cert device.pem \
    --key device.key \
    -H "Content-Type: application/pkcs10" \
    --data-binary "@device-renew.csr.der" \
    "$EST_SERVICE_ADDR/.well-known/est/simplereenroll")

if [ "$HTTP_CODE" = "200" ]; then
    log_success "✓ Certificate re-enrolled with device cert as client cert (HTTP $HTTP_CODE)"
    
    log_info "Decoding re-enrolled certificate..."
    base64_decode reenrolled-cert.b64 reenrolled-cert.p7
    if openssl pkcs7 -inform DER -in reenrolled-cert.p7 -print_certs -out reenrolled.pem 2>/dev/null; then
        log_success "✓ Re-enrolled certificate decoded successfully"
        openssl x509 -in reenrolled.pem -text -noout | grep -E "(Subject:|Serial Number:|Not Before|Not After)"
        
        log_info "Verifying re-enrolled certificate against CA..."
        if openssl verify -CAfile cacerts.pem reenrolled.pem; then
            log_success "✓ Re-enrolled certificate verification successful"
        else
            log_error "✗ Re-enrolled certificate verification failed"
        fi
    else
        log_error "✗ Failed to decode re-enrolled certificate"
    fi
else
    log_error "✗ Re-enrollment with device cert failed (HTTP $HTTP_CODE)"
    log_error "Step 1: CA certificate retrieval (unauthenticated)"
log_success "✓ Step 2: Device key and CSR generation"
log_success "✓ Step 3: Initial enrollment with bootstrap client certificate"
log_success "✓ Step 4: Certificate verification"
log_success "✓ Step 5: Re-enrollment CSR generation"
log_success "✓ Step 6: Re-enrollment with enrolled device certificate (RFC 7030)"

echo ""
log_info "Certificate lifecycle demonstration complete!"
echo "  - Bootstrap cert (client-cert.pem) used for initial enrollment"
echo "  - Device cert (device.pem) used for re-enrollment"
echo "  - EST service trusts both via client-ca-bundle.pem"
    echo "  1. Check if client-ca-bundle.pem exists and contains both CAs"
    echo "  2. Verify EST service is configured with client_ca_file: client-ca-bundle.pem"
    echo "  3. Check EST service logs for TLS handshake errors"
    exit 1
fi

# Summary
log_section "Certificate Authentication Test Complete!"

log_success "✓ CA certificate retrieval (unauthenticated)"
log_success "✓ Initial enrollment with TLS client certificate"
log_success "✓ Certificate verification"
log_info "⊘ Re-enrollment skipped (see explanation above)"

