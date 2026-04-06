#!/bin/bash
#
# check-coverage.sh - Verify test coverage meets minimum threshold

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Configuration
MIN_COVERAGE="${1:-80}"

# Run coverage and check threshold
check_coverage() {
    local project_root
    project_root=$(find_project_root)
    cd "$project_root" || die "Project root not found"

    cmd_exists pytest || die "pytest not found"

    info "Running coverage (min: ${MIN_COVERAGE}%)"

    # Run pytest with coverage and capture output
    local output
    output=$(pytest --cov=src --cov-report=term-missing 2>&1 || true)

    # Extract coverage percentage
    local coverage
    coverage=$(echo "$output" | grep -oP 'TOTAL.*\K\d+%' | tr -d '%' || echo "0")

    # Compare
    if [[ "$coverage" -ge "$MIN_COVERAGE" ]]; then
        info "Coverage: ${coverage}% ✓"
        return 0
    else
        error "Coverage: ${coverage}% < ${MIN_COVERAGE}%"
        return 1
    fi
}

check_coverage
