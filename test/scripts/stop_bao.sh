#!/usr/bin/env bash
# Stop OpenBao Server
# This script stops a running OpenBao instance started by start_bao.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

BAO_PID_FILE="${TEST_DIR}/bao.pid"

log_section "Stopping $BACKEND_TYPE"

if [ ! -f "$BAO_PID_FILE" ]; then
    log_warn "PID file not found: $BAO_PID_FILE"
    log_info "No $BACKEND_TYPE instance to stop"
    exit 0
fi

BAO_PID=$(cat "$BAO_PID_FILE")

if ! kill -0 "$BAO_PID" 2>/dev/null; then
    log_warn "$BACKEND_TYPE process (PID: $BAO_PID) is not running"
    rm -f "$BAO_PID_FILE"
    exit 0
fi

log_info "Stopping $BACKEND_TYPE (PID: $BAO_PID)..."
kill "$BAO_PID" 2>/dev/null || true

# Wait for process to stop
WAIT_COUNT=0
while kill -0 "$BAO_PID" 2>/dev/null && [ $WAIT_COUNT -lt 10 ]; do
    sleep 1
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

if kill -0 "$BAO_PID" 2>/dev/null; then
    log_warn "Process did not stop gracefully, forcing..."
    kill -9 "$BAO_PID" 2>/dev/null || true
    sleep 1
fi

rm -f "$BAO_PID_FILE"
log_success "$BACKEND_TYPE stopped"

# Optionally clean up data
if [ "${CLEANUP_DATA:-}" = "true" ]; then
    log_info "Cleaning up OpenBao data directory..."
    rm -rf "${TEST_DIR}/bao-data"
    log_success "Data cleaned up"
fi
