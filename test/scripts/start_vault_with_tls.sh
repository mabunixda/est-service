#!/usr/bin/env bash
# Start Vault/OpenBao with TLS for Certificate Authentication Testing
# This script creates TLS certificates and starts a local Vault/OpenBao instance with TLS enabled

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

log_section "Starting $BACKEND_TYPE with TLS"

# Configuration
VAULT_DATA_DIR="${TEST_DIR}/vault-data"
VAULT_CONFIG_FILE="${TEST_DIR}/vault-config.hcl"
VAULT_PID_FILE="${TEST_DIR}/vault.pid"
VAULT_TLS_CERT="${TEST_DIR}/vault-server-cert.pem"
VAULT_TLS_KEY="${TEST_DIR}/vault-server-key.pem"
VAULT_CA_CERT="${TEST_DIR}/vault-ca.pem"
VAULT_CA_KEY="${TEST_DIR}/vault-ca.key"

# TLS Configuration
VAULT_LISTEN_ADDR="${VAULT_LISTEN_ADDR:-127.0.0.1:8200}"
VAULT_TLS_MIN_VERSION="${VAULT_TLS_MIN_VERSION:-tls12}"

# Check prerequisites
log_info "Checking prerequisites..."
check_command "$BAO_CMD" "$BAO_CMD"
check_command "openssl" "openssl"
check_command "jq" "jq"

# Stop any existing Vault/OpenBao instance
if [ -f "$VAULT_PID_FILE" ]; then
    OLD_PID=$(cat "$VAULT_PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        log_warn "Stopping existing $BACKEND_TYPE instance (PID: $OLD_PID)..."
        kill "$OLD_PID" 2>/dev/null || true
        sleep 2
    fi
    rm -f "$VAULT_PID_FILE"
fi

if [ -z "$BACKEND_TOKEN"]; then
    if [ ! -f "${TEST_DIR}/vault-root-token.txt"]; then
        log_error "You need to defined BACKEND_TOKEN env var!"
        exit 1
    fi
    export BACKEND_TOKEN=$(cat "${TEST_DIR}/vault-root-token.txt")
fi

# Create data directory
mkdir -p "$VAULT_DATA_DIR"

log_section "Step 1: Generating TLS Certificates"

# Generate CA certificate
log_info "Creating Vault CA certificate..."
openssl genrsa -out "$VAULT_CA_KEY" 4096 2>/dev/null
openssl req -x509 -new -nodes \
    -key "$VAULT_CA_KEY" \
    -sha256 -days 365 \
    -out "$VAULT_CA_CERT" \
    -subj "/CN=Vault Test CA/O=EST Test/C=US" 2>/dev/null

log_success "Vault CA certificate generated"
openssl x509 -in "$VAULT_CA_CERT" -text -noout | grep -E "(Subject:|Issuer:|Not After)"

# Generate server certificate
log_info "Creating Vault server certificate..."
openssl genrsa -out "$VAULT_TLS_KEY" 2048 2>/dev/null

# Create certificate request with SANs
cat > "${TEST_DIR}/vault-server.cnf" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = localhost
O = EST Test
C = US

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = vault
IP.1 = 127.0.0.1
EOF

openssl req -new \
    -key "$VAULT_TLS_KEY" \
    -out "${TEST_DIR}/vault-server.csr" \
    -config "${TEST_DIR}/vault-server.cnf" 2>/dev/null

openssl x509 -req \
    -in "${TEST_DIR}/vault-server.csr" \
    -CA "$VAULT_CA_CERT" \
    -CAkey "$VAULT_CA_KEY" \
    -CAcreateserial \
    -out "$VAULT_TLS_CERT" \
    -days 365 \
    -sha256 \
    -extensions v3_req \
    -extfile "${TEST_DIR}/vault-server.cnf" 2>/dev/null

log_success "Vault server certificate generated"
openssl x509 -in "$VAULT_TLS_CERT" -text -noout | grep -E "(Subject:|Issuer:|DNS:|IP Address:)"

log_section "Step 2: Creating Vault Configuration"


# Create Vault configuration file
cat > "$VAULT_CONFIG_FILE" <<EOF
storage "file" {
  path = "$VAULT_DATA_DIR"
}

listener "tcp" {
  address     = "$VAULT_LISTEN_ADDR"
  tls_cert_file = "$VAULT_TLS_CERT"
  tls_key_file  = "$VAULT_TLS_KEY"
  tls_min_version = "$VAULT_TLS_MIN_VERSION"
  tls_require_and_verify_client_cert = false
}

audit "file" "file_audit" {
  description = "Default audit device"
  options = {
    file_path = "${TEST_DIR}/vault-audit.log"
    log_raw = "false"
  }
}

api_addr = "https://$VAULT_LISTEN_ADDR"
ui = true
EOF

log_success "Vault configuration created: $VAULT_CONFIG_FILE"
log_info "Configuration:"
cat "$VAULT_CONFIG_FILE" | sed 's/^/  /'

log_section "Step 3: Starting Vault Server"

# Update environment variables for HTTPS
export VAULT_ADDR="https://$VAULT_LISTEN_ADDR"
export VAULT_CACERT="$VAULT_CA_CERT"
export VAULT_SKIP_VERIFY="false"

log_info "Starting $BACKEND_TYPE server..."
nohup $BAO_CMD server -config="$VAULT_CONFIG_FILE" > "${TEST_DIR}/vault-server.log" 2>&1 &
VAULT_PID=$!
echo $VAULT_PID > "$VAULT_PID_FILE"

log_info "Waiting for $BACKEND_TYPE to start (PID: $VAULT_PID)..."
sleep 3

# Check if process is still running
if ! kill -0 $VAULT_PID 2>/dev/null; then
    log_error "$BACKEND_TYPE failed to start!"
    log_error "Log output:"
    cat "${TEST_DIR}/vault-server.log"
    exit 1
fi

# Wait for Vault to be ready
log_info "Waiting for $BACKEND_TYPE API to be ready..."
MAX_ATTEMPTS=30
ATTEMPT=0
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    if curl -s -k --cacert "$VAULT_CA_CERT" "https://$VAULT_LISTEN_ADDR/v1/sys/health" > /dev/null 2>&1; then
        break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    sleep 1
done

if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
    log_error "$BACKEND_TYPE API did not become ready in time"
    log_error "Log output:"
    tail -20 "${TEST_DIR}/vault-server.log"
    kill $VAULT_PID 2>/dev/null || true
    exit 1
fi

log_success "$BACKEND_TYPE server started successfully"

log_section "Step 4: Initializing Vault"

# Check if already initialized
if $BAO_CMD status > /dev/null 2>&1; then
    log_info "$BACKEND_TYPE is already initialized"
else
    log_info "Initializing $BACKEND_TYPE..."
    INIT_OUTPUT=$($BAO_CMD operator init -key-shares=1 -key-threshold=1 -format=json)
    
    UNSEAL_KEY=$(echo "$INIT_OUTPUT" | jq -r '.unseal_keys_b64[0]')
    ROOT_TOKEN=$(echo "$INIT_OUTPUT" | jq -r '.root_token')
    
    # Save keys for reference
    echo "$UNSEAL_KEY" > "${TEST_DIR}/vault-unseal-key.txt"
    echo "$ROOT_TOKEN" > "${TEST_DIR}/vault-root-token.txt"
    
    log_success "$BACKEND_TYPE initialized"
    log_info "Unseal key saved to: ${TEST_DIR}/vault-unseal-key.txt"
    log_info "Root token saved to: ${TEST_DIR}/vault-root-token.txt"
fi

log_section "Step 5: Unsealing Vault"

# Read unseal key if needed
if [ -f "${TEST_DIR}/vault-unseal-key.txt" ]; then
    UNSEAL_KEY=$(cat "${TEST_DIR}/vault-unseal-key.txt")
fi

if [ -f "${TEST_DIR}/vault-root-token.txt" ]; then
    ROOT_TOKEN=$(cat "${TEST_DIR}/vault-root-token.txt")
fi

# Unseal
SEALED=$($BAO_CMD status -format=json | jq -r '.sealed')
if [ "$SEALED" = "true" ]; then
    log_info "Unsealing $BACKEND_TYPE..."
    $BAO_CMD operator unseal "$UNSEAL_KEY" > /dev/null
    log_success "$BACKEND_TYPE unsealed"
else
    log_info "$BACKEND_TYPE is already unsealed"
fi

# Set token
export VAULT_TOKEN="$ROOT_TOKEN"

log_section "Vault Setup Complete"
log_success "$BACKEND_TYPE is running with TLS enabled!"
echo ""
log_info "Configuration Details:"
echo "  Address:      https://$VAULT_LISTEN_ADDR"
echo "  Root Token:   $ROOT_TOKEN"
echo "  CA Cert:      $VAULT_CA_CERT"
echo "  Server Cert:  $VAULT_TLS_CERT"
echo "  Server Key:   $VAULT_TLS_KEY"
echo "  PID:          $VAULT_PID"
echo "  PID File:     $VAULT_PID_FILE"
echo "  Log File:     ${TEST_DIR}/vault-server.log"
echo ""
log_info "Environment Variables:"
echo "  export VAULT_ADDR='https://$VAULT_LISTEN_ADDR'"
echo "  export VAULT_TOKEN='$ROOT_TOKEN'"
echo "  export VAULT_CACERT='$VAULT_CA_CERT'"
echo "  export VAULT_SKIP_VERIFY='false'"
echo ""
log_info "To stop $BACKEND_TYPE:"
echo "  kill $VAULT_PID"
echo "  # or"
echo "  kill \$(cat $VAULT_PID_FILE)"
echo ""
log_warn "Note: Run setup_backend.sh next to configure PKI and authentication"
