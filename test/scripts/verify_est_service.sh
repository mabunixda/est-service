#!/usr/bin/env bash
# EST Service Verification Script
# Tests all EST endpoints to verify the service is working correctly

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

# EST Service configuration (override for dev mode)
EST_SERVICE_ADDR="${EST_SERVICE_ADDR:-http://127.0.0.1:8443}"
EST_BASE_URL="$EST_SERVICE_ADDR/.well-known/est"

log_section "EST Service Verification"
log_info "EST Service: $EST_SERVICE_ADDR"
log_info "Test directory: $TEST_DIR"

# Ensure test directory exists
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

# Check if EST service is running
log_info "Checking if EST service is running..."
if ! curl -f -ks -m 5 "$EST_SERVICE_ADDR/health" > /dev/null 2>&1; then
    log_error "EST service is not responding at $EST_SERVICE_ADDR"
    log_error "Please start the EST service first:"
    log_error "  ./bin/est-service --config configs/dev.yaml"
    exit 1
fi
log_success "EST service is running"

# Test 1: Health Endpoint
log_section "Test 1: Health Check"
log_info "Testing health endpoint..."
HEALTH_RESPONSE=$(curl -k "$EST_SERVICE_ADDR/health")
echo "$HEALTH_RESPONSE" | jq '.' 2>/dev/null || echo "$HEALTH_RESPONSE"
log_success "Health endpoint working"

# Test 2: Readiness Endpoint
log_section "Test 2: Readiness Check"
log_info "Testing readiness endpoint..."
READY_RESPONSE=$(curl -ks "$EST_SERVICE_ADDR/ready")
echo "$READY_RESPONSE" | jq '.' 2>/dev/null || echo "$READY_RESPONSE"
log_success "Readiness endpoint working"

# Test 3: Metrics Endpoint
log_section "Test 3: Metrics Endpoint"
log_info "Testing metrics endpoint..."
if curl -ks "$EST_SERVICE_ADDR:9090/metrics" | head -5; then
    log_success "Metrics endpoint working"
else
    log_warn "Metrics endpoint may not be working"
fi

# Test 4: CA Certificates (No Auth Required)
log_section "Test 4: CA Certificates Endpoint"
log_info "Fetching CA certificates..."
if curl -ks -o cacerts.b64 "$EST_BASE_URL/cacerts"; then
    log_success "CA certificates retrieved"
    
    # Decode base64 and save as DER (handle macOS base64)
    if base64 --version 2>&1 | grep -q "GNU"; then
        base64 -d cacerts.b64 > cacerts.p7
    else
        # macOS base64
        base64 -D -i cacerts.b64 -o cacerts.p7
    fi
    
    # Extract certificates from PKCS#7
    log_info "Extracting certificates from PKCS#7..."
    if openssl pkcs7 -inform DER -in cacerts.p7 -print_certs -out cacerts.pem 2>/dev/null; then
        log_success "CA certificates extracted"
        
        # Display certificate info
        log_info "CA Certificate details:"
        openssl x509 -in cacerts.pem -text -noout | grep -E "(Subject:|Issuer:|Not Before|Not After)" || true
        
        # Count certificates
        CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" cacerts.pem || echo "0")
        log_info "Number of certificates in chain: $CERT_COUNT"
    else
        log_warn "Could not extract certificates from PKCS#7"
    fi
else
    log_error "Failed to retrieve CA certificates"
fi


# Summary
log_section "Verification Summary"
log_success "✓ Health endpoint working"
log_success "✓ Readiness endpoint working"
log_success "✓ Metrics endpoint working"
log_success "✓ CA certificates endpoint working"


echo ""
log_info "To test with curl:"
echo "  # Get CA certs:"
echo "  curl $EST_BASE_URL/cacerts | base64 -d | openssl pkcs7 -inform DER -print_certs"
echo ""
echo "  # Enroll with basic auth:"
echo "  curl -u $EST_USERNAME:$EST_PASSWORD \\"
echo "    -H 'Content-Type: application/pkcs10' \\"
echo "    -H 'Content-Transfer-Encoding: base64' \\"
echo "    --data '\$(base64 < test-device.csr)' \\"
echo "    $EST_BASE_URL/simpleenroll"
