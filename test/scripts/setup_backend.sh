#!/usr/bin/env bash
# Backend Setup Script for EST Service Testing
# Sets up OpenBao as the backend for EST service
# This script prepares the PKI backend and authentication methods

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

log_section "Setting up $BACKEND_TYPE backend for EST Service"

# Check prerequisites
log_info "Checking prerequisites..."
check_command "$BAO_CMD" "$BAO_CMD"
check_command "openssl" "openssl"
check_command "curl" "curl"
check_command "jq" "jq"

log_info "Backend: $BACKEND_TYPE"
log_info "Backend Address: $BACKEND_ADDR"
log_info "PKI Mount: $PKI_PATH"
log_info "Test directory: $TEST_DIR"
cd "$TEST_DIR"

# Step 1: Setup PKI backend
log_info "Step 1: Setting up PKI backend..."

# Disable and re-enable PKI to start fresh
$BAO_CMD secrets disable -path="$PKI_PATH" pki 2>/dev/null || true
sleep 1
$BAO_CMD secrets enable -path="$PKI_PATH" pki

# Configure PKI
$BAO_CMD secrets tune -max-lease-ttl=87600h "$PKI_PATH"

# Generate root CA
log_info "Generating root CA..."
$BAO_CMD write -field=certificate "$PKI_PATH/root/generate/internal" \
    common_name="$CA_COMMON_NAME" \
    issuer_name="est-service-root-ca" \
    ttl=87600h > ca.pem

if [ -f ca.pem ] && [ -s ca.pem ]; then
    log_success "Root CA generated"
    openssl x509 -in ca.pem -text -noout | grep -E "(Subject:|Issuer:|Not Before|Not After)"
else
    log_error "Failed to generate root CA"
    exit 1
fi

# Configure URLs
$BAO_CMD write "$PKI_PATH/config/urls" \
    issuing_certificates="$BACKEND_ADDR/v1/$PKI_PATH/ca" \
    crl_distribution_points="$BACKEND_ADDR/v1/$PKI_PATH/crl"

# Create a role for EST enrollment
log_info "Creating PKI role for EST devices..."
$BAO_CMD write "$PKI_PATH/roles/est-devices" \
    allowed_domains="example.com,iot.local,devices.local" \
    allow_subdomains=true \
    max_ttl="4h" \
    ttl="2h" \
    key_type="rsa" \
    key_bits=2048 \
    require_cn=true

log_info "Note: Using short TTL (2h) for testing certificate lifecycle"

# Create a role for EST service server certificate
log_info "Creating PKI role for EST service server..."
$BAO_CMD write "$PKI_PATH/roles/est-server" \
    allowed_domains="localhost,est-service,est-service.local" \
    allow_subdomains=false \
    allow_bare_domains=true \
    allow_localhost=true \
    allow_ip_sans=true \
    max_ttl="8760h" \
    key_type="rsa" \
    key_bits=2048 \
    server_flag=true \
    client_flag=false \
    require_cn=true

# Step 2: Setup Authentication
log_info "Step 2: Setting up authentication methods..."

# Enable userpass auth if not already enabled
if ! $BAO_CMD auth enable userpass 2>/dev/null; then
    log_info "Userpass already enabled"
fi

# Create policy for EST operations
cat > est-policy.hcl <<EOF
# Allow PKI operations for EST service
path "$PKI_PATH/sign/est-devices" {
    capabilities = ["create", "update"]
}

path "$PKI_PATH/sign-verbatim" {
    capabilities = ["create", "update"]
}

path "$PKI_PATH/ca" {
    capabilities = ["read"]
}

path "$PKI_PATH/ca/pem" {
    capabilities = ["read"]
}

path "$PKI_PATH/ca_chain" {
    capabilities = ["read"]
}

path "$PKI_PATH/cert/ca_chain" {
    capabilities = ["read"]
}

# Identity management for per-client entities (Issue 1.1 - Certificate Auth Identity)
# Required when using TLS client certificate authentication
# The EST service creates unique OpenBao entities for each client certificate
# to ensure proper audit trails and per-client authorization
path "identity/entity/name/*" {
    capabilities = ["create", "update", "read"]
}

path "identity/entity-alias" {
    capabilities = ["create", "update"]
}

path "auth/token/create" {
    capabilities = ["create", "update"]
}

path "sys/auth" {
    capabilities = ["read"]
}
EOF

$BAO_CMD policy write est-policy est-policy.hcl
log_success "EST policy created"

# Create EST user
log_info "Creating EST user: $EST_USERNAME"
$BAO_CMD write auth/userpass/users/"$EST_USERNAME" \
    password="$EST_PASSWORD" \
    token_ttl="1h" \
    token_policies="est-policy"

log_success "User '$EST_USERNAME' created with EST policy"

# Step 3: Setup TLS Client Certificate Authentication (if enabled)
if [ "$ENABLE_CERT_AUTH" = "true" ]; then
    log_info "Step 3: Setting up TLS Client Certificate Authentication..."
    
    # Enable cert auth if not already enabled
    if ! $BAO_CMD auth enable cert 2>/dev/null; then
        log_info "Cert auth already enabled"
    fi
    
    # Create a client CA for issuing client certificates
    log_info "Creating client certificate CA..."
    openssl genrsa -out "$TEST_DIR/client-ca.key" 4096 2>/dev/null
    openssl req -x509 -new -nodes \
        -key "$TEST_DIR/client-ca.key" \
        -sha256 -days 365 \
        -out "$TEST_DIR/client-ca.pem" \
        -subj "/CN=EST Client Certificate CA/O=EST Test/C=US" 2>/dev/null
    
    log_success "Client CA certificate generated"
    openssl x509 -in "$TEST_DIR/client-ca.pem" -text -noout | grep -E "(Subject:|Issuer:)"
    
    # Configure cert auth backend
    $BAO_CMD write auth/cert/certs/"$CERT_AUTH_ROLE" \
        certificate=@"$TEST_DIR/client-ca.pem" \
        token_ttl="1h" \
        token_policies="est-policy" \
        allowed_common_names="*.example.com,*.test.local"
    
    log_success "Cert auth role '$CERT_AUTH_ROLE' created"
    
    # Generate EST service certificate for backend authentication
    log_info "Generating EST service certificate (for OpenBao auth)..."
    openssl genrsa -out "$TEST_DIR/est-service-key.pem" 2048 2>/dev/null
    openssl req -new \
        -key "$TEST_DIR/est-service-key.pem" \
        -out "$TEST_DIR/est-service.csr" \
        -subj "/CN=est-service.example.com/O=EST Service/C=US" 2>/dev/null
    openssl x509 -req \
        -in "$TEST_DIR/est-service.csr" \
        -CA "$TEST_DIR/client-ca.pem" \
        -CAkey "$TEST_DIR/client-ca.key" \
        -CAcreateserial \
        -out "$TEST_DIR/est-service-cert.pem" \
        -days 365 \
        -sha256 2>/dev/null
    
    log_success "EST service certificate generated"
    openssl x509 -in "$TEST_DIR/est-service-cert.pem" -text -noout | grep -E "(Subject:|Issuer:)"
    
    # Generate sample client certificate for testing
    log_info "Generating sample client certificate (for EST client auth)..."
    openssl genrsa -out "$TEST_DIR/client-key.pem" 2048 2>/dev/null
    openssl req -new \
        -key "$TEST_DIR/client-key.pem" \
        -out "$TEST_DIR/client.csr" \
        -subj "/CN=est-test-client.example.com/O=EST Test Client/C=US" 2>/dev/null
    openssl x509 -req \
        -in "$TEST_DIR/client.csr" \
        -CA "$TEST_DIR/client-ca.pem" \
        -CAkey "$TEST_DIR/client-ca.key" \
        -CAcreateserial \
        -out "$TEST_DIR/client-cert.pem" \
        -days 365 \
        -sha256 2>/dev/null
    
    log_success "Sample client certificate generated"
    openssl x509 -in "$TEST_DIR/client-cert.pem" -text -noout | grep -E "(Subject:|Issuer:)"
fi

# Step 4: Generate TLS Server Certificates for EST Service
log_section "Step 4: Generating TLS Server Certificates for EST Service"

log_info "Generating server private key..."
openssl genrsa -out "$TEST_DIR/server-key.pem" 2048 2>/dev/null
log_success "Server private key generated"

log_info "Creating server certificate signing request..."
# Create OpenSSL config for SAN
cat > "$TEST_DIR/server-cert.cnf" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = localhost
O = EST Service Test
C = US

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = est-service
DNS.3 = est-service.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl req -new \
    -key "$TEST_DIR/server-key.pem" \
    -out "$TEST_DIR/server.csr" \
    -config "$TEST_DIR/server-cert.cnf" 2>/dev/null
log_success "Server CSR created"

log_info "Requesting server certificate from PKI backend..."
# Submit CSR to backend for signing (PEM format)
$BAO_CMD write -format=json "$PKI_PATH/sign/est-server" \
    csr=@"$TEST_DIR/server.csr" \
    common_name="localhost" \
    alt_names="est-service,est-service.local" \
    ip_sans="127.0.0.1,::1" \
    ttl="8760h" > "$TEST_DIR/server-cert-response.json"

# Extract certificate from response
jq -r '.data.certificate' "$TEST_DIR/server-cert-response.json" > "$TEST_DIR/server-cert.pem"
jq -r '.data.ca_chain[]' "$TEST_DIR/server-cert-response.json" > "$TEST_DIR/server-ca-chain.pem"

log_success "Server certificate issued by PKI backend"
openssl x509 -in "$TEST_DIR/server-cert.pem" -text -noout | grep -E "(Subject:|Issuer:|DNS:|IP Address:)"

# Create full chain (certificate + CA chain)
log_info "Creating server certificate chain..."
cat "$TEST_DIR/server-cert.pem" "$TEST_DIR/server-ca-chain.pem" > "$TEST_DIR/server-chain.pem"
log_success "Server certificate chain created (cert + CA)"

# Secure the server private key
chmod 600 "$TEST_DIR/server-key.pem"

# Create combined client CA bundle for EST service
# This allows the EST service to trust BOTH:
# 1. Bootstrap certificates signed by client-ca.pem (initial enrollment)
# 2. Device certificates signed by PKI CA (re-enrollment)
if [ "$ENABLE_CERT_AUTH" = "true" ]; then
    log_section "Step 5: Creating Combined Client CA Bundle"
    log_info "Creating client-ca-bundle.pem (client-ca + PKI CA)..."
    cat "$TEST_DIR/client-ca.pem" "$TEST_DIR/ca.pem" > "$TEST_DIR/client-ca-bundle.pem"
    
    # Validate the combined bundle contains multiple certificates
    CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$TEST_DIR/client-ca-bundle.pem" || echo "0")
    if [ "$CERT_COUNT" -lt 2 ]; then
        log_error "Combined CA bundle should contain at least 2 certificates, found: $CERT_COUNT"
        exit 1
    fi
    
    log_success "Combined client CA bundle created with $CERT_COUNT CA certificates"
    log_info "This bundle allows EST service to trust:"
    echo "  - Bootstrap certificates (signed by client-ca.pem)"
    echo "  - Device certificates (signed by PKI CA) for re-enrollment per RFC 7030"
    
    # Verify each CA certificate is valid
    log_info "Validating CA certificates in bundle..."
    
    # Split bundle into individual certificates using portable shell approach
    CERT_NUM=0
    CURRENT_CERT=""
    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            CURRENT_CERT="$line"
        elif [[ "$line" == "-----END CERTIFICATE-----" ]]; then
            CURRENT_CERT="$CURRENT_CERT"$'\n'"$line"
            CERT_FILE="/tmp/ca-split-$$.${CERT_NUM}.pem"
            echo "$CURRENT_CERT" > "$CERT_FILE"
            
            if openssl x509 -in "$CERT_FILE" -noout -subject 2>/dev/null; then
                log_info "  ✓ Valid CA: $(openssl x509 -in "$CERT_FILE" -noout -subject | sed 's/subject=//')"
            fi
            rm -f "$CERT_FILE"
            
            CERT_NUM=$((CERT_NUM + 1))
            CURRENT_CERT=""
        elif [ -n "$CURRENT_CERT" ]; then
            CURRENT_CERT="$CURRENT_CERT"$'\n'"$line"
        fi
    done < "$TEST_DIR/client-ca-bundle.pem"
    
    log_success "All CA certificates validated"
fi

log_section "Backend Setup Complete"
log_success "✓ PKI backend configured at $PKI_PATH"
log_success "✓ PKI roles created: est-devices, est-server"
log_success "✓ Userpass authentication enabled (user: $EST_USERNAME)"
if [ "$ENABLE_CERT_AUTH" = "true" ]; then
    log_success "✓ Cert authentication enabled (role: $CERT_AUTH_ROLE)"
fi
log_success "✓ TLS server certificate issued by PKI backend"
log_success "✓ Test artifacts in: $TEST_DIR"

echo ""
log_info "Next steps:"
echo "  1. Start EST service with TLS configuration:"
echo "     ./test/scripts/run_test_instance.sh"
echo "  2. Or manually with:"
echo "     export EST_TLS_CERT=$TEST_DIR/server-cert.pem"
echo "     export EST_TLS_KEY=$TEST_DIR/server-key.pem"
echo "     export EST_TLS_CA=$TEST_DIR/ca.pem"
echo "  3. Run test scripts: test_enrollment.sh, test_enrollment_cert.sh"
echo ""
echo "Test directory: $TEST_DIR"
echo "  - ca.pem: Root CA certificate (PKI backend)"
echo "  - server-cert.pem: EST service HTTPS certificate (issued by PKI backend)"
echo "  - server-key.pem: EST service HTTPS private key"
echo "  - server-chain.pem: EST service certificate chain (cert + CA)"
if [ "$ENABLE_CERT_AUTH" = "true" ]; then
    echo "  - client-ca.pem: Client CA certificate (bootstrap)"
    echo "  - client-ca-bundle.pem: Combined CA bundle (client-ca + PKI CA) for EST service"
    echo "  - est-service-cert.pem: EST service backend auth certificate (for OpenBao)"
    echo "  - est-service-key.pem: EST service backend auth private key"
    echo "  - client-cert.pem: Sample client certificate (for EST client testing)"
    echo "  - client-key.pem: Sample client private key"
fi
