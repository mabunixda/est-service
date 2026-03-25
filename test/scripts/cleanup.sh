#!/bin/bash
# cleanup.sh - Complete cleanup and reset of test environment
# 
# This script:
# - Stops all est-service processes
# - Stops all OpenBao containers and processes
# - Cleans up temporary files and storage
# - Resets the test environment to a clean state

set -e


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

log_section "EST Service - Environment Cleanup"

$SCRIPT_DIR/stop_bao.sh
rm -rf "${TEST_DIR}/"


log_success "Cleanup Complete!"
