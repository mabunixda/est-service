#!/usr/bin/env bash
# EST Service Test Configuration
# Shared configuration for all test scripts

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=========================================${NC}"
}

# EST Service Configuration
EST_SERVICE_ADDR="${EST_SERVICE_ADDR:-https://127.0.0.1:8443}"
EST_SERVICE_SKIP_VERIFY="${EST_SERVICE_SKIP_VERIFY:-true}"

# Backend Configuration (OpenBao)
BACKEND_TYPE="openbao"
BACKEND_ADDR="${BACKEND_ADDR:-https://127.0.0.1:8200}"
BACKEND_TOKEN="${BACKEND_TOKEN:-}"
export BAO_ADDR="$BACKEND_ADDR"
export BAO_TOKEN="$BACKEND_TOKEN"
export BAO_SKIP_VERIFY="true"

# PKI Configuration
PKI_PATH="${PKI_PATH:-pki}"
CA_COMMON_NAME="${CA_COMMON_NAME:-EST Test CA}"

# EST Authentication Configuration
EST_USERNAME="${EST_USERNAME:-est-device}"
EST_PASSWORD="${EST_PASSWORD:-device-secret-123}"
ENABLE_CERT_AUTH="${ENABLE_CERT_AUTH:-true}"
CERT_AUTH_ROLE="${CERT_AUTH_ROLE:-est-client}"

# Test Directory
if [ -z "$TMPDIR" ]; then
    if [ -d "/tmp" ]; then
        TMPDIR="/tmp"
    else
        TMPDIR="$(mktemp -d)"
    fi
fi

TEST_DIR="${TEST_DIR:-${TMPDIR}/est-est-service}"
SKIP_SETUP_CLEANUP="${SKIP_SETUP_CLEANUP:-}"

# Cleanup function
cleanup() {
    if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
        return
    fi
    if [ -n "${SKIP_SETUP_CLEANUP}" ]; then
        log_info "Skipping cleanup of test directory: $TEST_DIR"
        return
    fi
    echo -e "${YELLOW}Cleaning up test directory: $TEST_DIR${NC}"
    rm -rf "$TEST_DIR"
}

trap cleanup EXIT

# Check if a command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 is not installed. Please install it first."
        echo "  macOS: brew install $2"
        echo "  Linux: apt-get install $2 or yum install $2"
        exit 1
    fi
}

# Portable base64 decode function
# Usage: base64_decode input_file output_file
base64_decode() {
    local input_file="$1"
    local output_file="$2"
    
    # Try macOS style first (-D flag)
    if base64 -D -i "$input_file" -o "$output_file" 2>/dev/null; then
        return 0
    fi
    
    # Try Linux style (-d flag)
    if base64 -d -i "$input_file" -o "$output_file" 2>/dev/null; then
        return 0
    fi
    
    # Fallback: Try without -i and -o flags (older base64 versions)
    if base64 -d < "$input_file" > "$output_file" 2>/dev/null; then
        return 0
    fi
    
    # Last resort: macOS without -i/-o
    if base64 -D < "$input_file" > "$output_file" 2>/dev/null; then
        return 0
    fi
    
    log_error "Failed to decode base64 file: $input_file"
    return 1
}

# Detect which backend CLI to use

mkdir -p "$TEST_DIR"


BAO_CMD="bao"
