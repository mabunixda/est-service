#!/usr/bin/env bash
# Start Bao/OpenBao with TLS for Certificate Authentication Testing
# This script creates TLS certificates and starts a local Bao/OpenBao instance with TLS enabled

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

log_section "Starting $BACKEND_TYPE with TLS"

# Configuration
BAO_DATA_DIR="${TEST_DIR}/bao-data"
BAO_CONFIG_FILE="${TEST_DIR}/bao-config.hcl"
BAO_PID_FILE="${TEST_DIR}/bao.pid"
BAO_TLS_CERT="${TEST_DIR}/bao-server-cert.pem"
BAO_TLS_KEY="${TEST_DIR}/bao-server-key.pem"
BAO_CA_CERT="${TEST_DIR}/bao-ca.pem"
BAO_CA_KEY="${TEST_DIR}/bao-ca.key"

# TLS Configuration
BAO_LISTEN_ADDR="${BAO_LISTEN_ADDR:-127.0.0.1:8200}"
BAO_TLS_MIN_VERSION="${BAO_TLS_MIN_VERSION:-tls12}"

# Check prerequisites
log_info "Checking prerequisites..."
check_command "$BAO_CMD" "$BAO_CMD"
check_command "openssl" "openssl"
check_command "jq" "jq"

# Stop any existing Bao/OpenBao instance
if [ -f "$BAO_PID_FILE" ]; then
    OLD_PID=$(cat "$BAO_PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        log_warn "Stopping existing $BACKEND_TYPE instance (PID: $OLD_PID)..."
        kill "$OLD_PID" 2>/dev/null || true
        sleep 2
    fi
    rm -f "$BAO_PID_FILE"
fi

# Create data directory
mkdir -p "$BAO_DATA_DIR"

log_section "Step 1: Generating TLS Certificates"

# Generate CA certificate
log_info "Creating Bao CA certificate..."
openssl genrsa -out "$BAO_CA_KEY" 4096 2>/dev/null
openssl req -x509 -new -nodes \
    -key "$BAO_CA_KEY" \
    -sha256 -days 365 \
    -out "$BAO_CA_CERT" \
    -subj "/CN=Bao Test CA/O=EST Test/C=US" 2>/dev/null

log_success "Bao CA certificate generated"
openssl x509 -in "$BAO_CA_CERT" -text -noout | grep -E "(Subject:|Issuer:|Not After)"

# Generate server certificate
log_info "Creating Bao server certificate..."
openssl genrsa -out "$BAO_TLS_KEY" 2048 2>/dev/null

# Create certificate request with SANs
cat > "${TEST_DIR}/bao-server.cnf" <<EOF
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
DNS.2 = bao
IP.1 = 127.0.0.1
EOF

openssl req -new \
    -key "$BAO_TLS_KEY" \
    -out "${TEST_DIR}/bao-server.csr" \
    -config "${TEST_DIR}/bao-server.cnf" 2>/dev/null

openssl x509 -req \
    -in "${TEST_DIR}/bao-server.csr" \
    -CA "$BAO_CA_CERT" \
    -CAkey "$BAO_CA_KEY" \
    -CAcreateserial \
    -out "$BAO_TLS_CERT" \
    -days 365 \
    -sha256 \
    -extensions v3_req \
    -extfile "${TEST_DIR}/bao-server.cnf" 2>/dev/null

log_success "Bao server certificate generated"
openssl x509 -in "$BAO_TLS_CERT" -text -noout | grep -E "(Subject:|Issuer:|DNS:|IP Address:)"

log_section "Step 2: Creating Bao Configuration"


# Create Bao configuration file
cat > "$BAO_CONFIG_FILE" <<EOF
storage "file" {
  path = "$BAO_DATA_DIR"
}

listener "tcp" {
  address     = "$BAO_LISTEN_ADDR"
  tls_cert_file = "$BAO_TLS_CERT"
  tls_key_file  = "$BAO_TLS_KEY"
  tls_min_version = "$BAO_TLS_MIN_VERSION"
  tls_require_and_verify_client_cert = false
}

audit "file" "file_audit" {
  description = "Default audit device"
  options = {
    file_path = "${TEST_DIR}/bao-audit.log"
    log_raw = "false"
  }
}

api_addr = "https://$BAO_LISTEN_ADDR"
ui = true
EOF

log_success "Bao configuration created: $BAO_CONFIG_FILE"
log_info "Configuration:"
cat "$BAO_CONFIG_FILE" | sed 's/^/  /'

log_section "Step 3: Starting Bao Server"

# Update environment variables for HTTPS
export BAO_ADDR="https://$BAO_LISTEN_ADDR"
export BAO_CACERT="$BAO_CA_CERT"
export BAO_SKIP_VERIFY="false"

log_info "Starting $BACKEND_TYPE server..."
nohup $BAO_CMD server -config="$BAO_CONFIG_FILE" > "${TEST_DIR}/bao-server.log" 2>&1 &
BAO_PID=$!
echo $BAO_PID > "$BAO_PID_FILE"

log_info "Waiting for $BACKEND_TYPE to start (PID: $BAO_PID)..."
sleep 3

# Check if process is still running
if ! kill -0 $BAO_PID 2>/dev/null; then
    log_error "$BACKEND_TYPE failed to start!"
    log_error "Log output:"
    cat "${TEST_DIR}/bao-server.log"
    exit 1
fi

# Wait for Bao to be ready
log_info "Waiting for $BACKEND_TYPE API to be ready..."
MAX_ATTEMPTS=30
ATTEMPT=0
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    if curl -s -k --cacert "$BAO_CA_CERT" "https://$BAO_LISTEN_ADDR/v1/sys/health" > /dev/null 2>&1; then
        break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    sleep 1
done

if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
    log_error "$BACKEND_TYPE API did not become ready in time"
    log_error "Log output:"
    tail -20 "${TEST_DIR}/bao-server.log"
    kill $BAO_PID 2>/dev/null || true
    exit 1
fi

log_success "$BACKEND_TYPE server started successfully"

log_section "Step 4: Initializing Bao"

# Check if already initialized
if $BAO_CMD status > /dev/null 2>&1; then
    log_info "$BACKEND_TYPE is already initialized"
else
    log_info "Initializing $BACKEND_TYPE..."
    INIT_OUTPUT=$($BAO_CMD operator init -key-shares=1 -key-threshold=1 -format=json)
    
    UNSEAL_KEY=$(echo "$INIT_OUTPUT" | jq -r '.unseal_keys_b64[0]')
    ROOT_TOKEN=$(echo "$INIT_OUTPUT" | jq -r '.root_token')
    
    # Save keys for reference
    echo "$UNSEAL_KEY" > "${TEST_DIR}/bao-unseal-key.txt"
    echo "$ROOT_TOKEN" > "${TEST_DIR}/bao-root-token.txt"
    
    log_success "$BACKEND_TYPE initialized"
    log_info "Unseal key saved to: ${TEST_DIR}/bao-unseal-key.txt"
    log_info "Root token saved to: ${TEST_DIR}/bao-root-token.txt"
fi

log_section "Step 5: Unsealing Bao"

# Read unseal key if needed
if [ -f "${TEST_DIR}/bao-unseal-key.txt" ]; then
    UNSEAL_KEY=$(cat "${TEST_DIR}/bao-unseal-key.txt")
fi

if [ -f "${TEST_DIR}/bao-root-token.txt" ]; then
    ROOT_TOKEN=$(cat "${TEST_DIR}/bao-root-token.txt")
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
export BAO_TOKEN="$ROOT_TOKEN"

log_section "Bao Setup Complete"
log_success "$BACKEND_TYPE is running with TLS enabled!"
echo ""
log_info "Configuration Details:"
echo "  Address:      https://$BAO_LISTEN_ADDR"
echo "  Root Token:   $ROOT_TOKEN"
echo "  CA Cert:      $BAO_CA_CERT"
echo "  Server Cert:  $BAO_TLS_CERT"
echo "  Server Key:   $BAO_TLS_KEY"
echo "  PID:          $BAO_PID"
echo "  PID File:     $BAO_PID_FILE"
echo "  Log File:     ${TEST_DIR}/bao-server.log"
echo ""
log_info "Environment Variables:"
echo "  export BAO_ADDR='https://$BAO_LISTEN_ADDR'"
echo "  export BAO_TOKEN='$ROOT_TOKEN'"
echo "  export BAO_CACERT='$BAO_CA_CERT'"
echo "  export BAO_SKIP_VERIFY='false'"
echo ""
log_info "To stop $BACKEND_TYPE:"
echo "  kill $BAO_PID"
echo "  # or"
echo "  kill \$(cat $BAO_PID_FILE)"
echo ""
log_warn "Note: Run setup_backend.sh next to configure PKI and authentication"
