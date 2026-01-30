#!/usr/bin/env bash
# Stop Vault/OpenBao Server
# This script stops a running Vault/OpenBao instance started by start_vault_with_tls.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

VAULT_PID_FILE="${TEST_DIR}/vault.pid"

log_section "Stopping $BACKEND_TYPE"

if [ ! -f "$VAULT_PID_FILE" ]; then
    log_warn "PID file not found: $VAULT_PID_FILE"
    log_info "No $BACKEND_TYPE instance to stop"
    exit 0
fi

VAULT_PID=$(cat "$VAULT_PID_FILE")

if ! kill -0 "$VAULT_PID" 2>/dev/null; then
    log_warn "$BACKEND_TYPE process (PID: $VAULT_PID) is not running"
    rm -f "$VAULT_PID_FILE"
    exit 0
fi

log_info "Stopping $BACKEND_TYPE (PID: $VAULT_PID)..."
kill "$VAULT_PID" 2>/dev/null || true

# Wait for process to stop
WAIT_COUNT=0
while kill -0 "$VAULT_PID" 2>/dev/null && [ $WAIT_COUNT -lt 10 ]; do
    sleep 1
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

if kill -0 "$VAULT_PID" 2>/dev/null; then
    log_warn "Process did not stop gracefully, forcing..."
    kill -9 "$VAULT_PID" 2>/dev/null || true
    sleep 1
fi

rm -f "$VAULT_PID_FILE"
log_success "$BACKEND_TYPE stopped"

# Optionally clean up data
if [ "${CLEANUP_DATA:-}" = "true" ]; then
    log_info "Cleaning up Vault data directory..."
    rm -rf "${TEST_DIR}/vault-data"
    log_success "Data cleaned up"
fi
