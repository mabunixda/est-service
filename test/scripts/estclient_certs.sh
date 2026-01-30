#!/usr/bin/env bash
# EST Client Test Script
# This script uses estclient with certificate-based authentication
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

check_command "estclient" "estclient"

SKIP_CLEANUP=${SKIP_CLEANUP:-}
WORK_DIR="$(mktemp -d)"
cd "$WORK_DIR"

log_section "EST estclient Test (Certificate Authentication)"
log_info "EST Service: $EST_SERVICE_ADDR"
log_info "Work directory: $WORK_DIR"
log_info "Client cert directory: $TEST_DIR"
log_warn "Note: Certificate-based authentication requires HTTPS with TLS client certificates"
log_warn "This script uses client certificates created by the cert auth engine at auth/cert"

# Check if HTTP (not HTTPS)
if [[ "$EST_SERVICE_ADDR" == http://* ]]; then
    EST_SERVICE_SKIP_VERIFY="true"
fi

# Verify that client certificates exist (created by setup_backend.sh)
if [ ! -f "$TEST_DIR/client-cert.pem" ] || [ ! -f "$TEST_DIR/client-key.pem" ]; then
    log_error "Client certificates not found in $TEST_DIR"
    log_error "Please run setup_backend.sh with ENABLE_CERT_AUTH=true first"
    exit 1
fi

log_info "Using client certificate: $TEST_DIR/client-cert.pem"
log_info "Using client key: $TEST_DIR/client-key.pem"

# Cleanup function
cleanup() {
    if [ -n "${SKIP_CLEANUP:-}" ]; then
        log_warn "Skipping cleanup of work directory: $WORK_DIR"
        return
    fi
    log_info "Cleaning up work directory: $WORK_DIR"
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Extract host:port from EST_SERVICE_ADDR
EST_SERVER=$(echo $EST_SERVICE_ADDR | sed -E 's|^https?://||' | sed 's|/.*$||')
INSECURE_FLAG=""
if [ "$EST_SERVICE_SKIP_VERIFY" = "true" ]; then
    INSECURE_FLAG="-insecure"
fi

log_info "Fetching CA certificates (bootstrap)..."
estclient cacerts \
        -server $EST_SERVER $INSECURE_FLAG  \
        -rootout -out anchor.pem
log_success "Bootstrap CA certificate retrieved"

log_info "Fetching full CA certificate chain..."
estclient cacerts \
        -server $EST_SERVER $INSECURE_FLAG  \
        -explicit anchor.pem \
        -out cacerts.pem
log_success "CA certificate chain retrieved"

log_info "Generating device key and CSR..."
openssl genrsa 4096 > est_device.key 2>/dev/null
estclient csr \
    -key est_device.key \
    -cn "device-$(date +%s).example.com" \
    -org 'My Org' \
    -country 'US' \
    -out est_device.csr
log_success "Device key and CSR generated"

log_info "Preparing client certificate chain for authentication..."
cat "$TEST_DIR/client-cert.pem" "$TEST_DIR/client-ca.pem" > client_certs.pem

log_info "Initial enrollment with certificate authentication..."
estclient enroll \
    -server $EST_SERVER $INSECURE_FLAG  \
    -explicit anchor.pem \
    -csr est_device.csr \
    -out est_device.pem \
    -key "$TEST_DIR/client-key.pem" \
    -certs client_certs.pem
log_success "Certificate enrolled"

log_info "Enrolled certificate details:"
openssl x509 -in est_device.pem -text -noout | grep -E "(Subject:|Issuer:)"

log_info "Verifying certificate..."
if openssl verify -CAfile cacerts.pem est_device.pem 2>/dev/null; then
    log_success "Certificate verification successful"
else
    log_error "Certificate verification failed"
    exit 1
fi

log_info "Key modulus check:"
KEY_MODULUS=$(openssl rsa -noout -modulus -in est_device.key 2>/dev/null | openssl md5)
CERT_MODULUS=$(openssl x509 -noout -modulus -in est_device.pem | openssl md5)
log_info "Key:  $KEY_MODULUS"
log_info "Cert: $CERT_MODULUS"

if [ "$KEY_MODULUS" = "$CERT_MODULUS" ]; then
    log_success "Private key matches certificate"
else
    log_error "Private key does not match certificate!"
    exit 1
fi

log_section "Certificate Re-enrollment"
log_info "Preparing certificate chain for re-enrollment..."
rm -f est_certs.pem
cat est_device.pem cacerts.pem >> est_certs.pem

log_info "Re-enrolling with TLS client certificate..."
estclient reenroll \
        -server $EST_SERVER $INSECURE_FLAG \
        -explicit anchor.pem \
        -key est_device.key \
        -certs est_certs.pem \
        -out est_newcert.pem
log_success "Certificate re-enrolled with TLS client cert"

log_info "Re-enrolled certificate key modulus check:"
KEY_MODULUS=$(openssl rsa -noout -modulus -in est_device.key 2>/dev/null | openssl md5)
NEWCERT_MODULUS=$(openssl x509 -noout -modulus -in est_newcert.pem | openssl md5)
log_info "Key:     $KEY_MODULUS"
log_info "NewCert: $NEWCERT_MODULUS"

if [ "$KEY_MODULUS" = "$NEWCERT_MODULUS" ]; then
    log_success "Private key matches re-enrolled certificate"
else
    log_error "Private key does not match re-enrolled certificate!"
    exit 1
fi

log_section "All Tests Completed Successfully"
log_success "EST service certificate-based flow is working!"
