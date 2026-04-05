#!/bin/bash
#
# Script: check-coverage.sh
# Description: Verify test coverage meets minimum threshold
# Usage: check-coverage.sh [minimum_coverage]
#

set -euo pipefail

# Constants
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DEFAULT_MIN_COVERAGE=80

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Configuration
MIN_COVERAGE="${1:-${DEFAULT_MIN_COVERAGE}}"
PYTHON_CMD="${PYTHON_CMD:-python3}"

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"

    case "${level}" in
        ERROR)
            echo -e "${RED}✗ ${message}${NC}" >&2
            ;;
        SUCCESS)
            echo -e "${GREEN}✓ ${message}${NC}"
            ;;
        WARNING)
            echo -e "${YELLOW}⚠ ${message}${NC}"
            ;;
        INFO)
            echo -e "${BLUE}ℹ ${message}${NC}"
            ;;
    esac
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Find project root
find_project_root() {
    local current_dir
    current_dir="$(pwd)"

    while [[ "${current_dir}" != "/" ]]; do
        if [[ -f "${current_dir}/pyproject.toml" ]] || [[ -f "${current_dir}/setup.py" ]]; then
            echo "${current_dir}"
            return 0
        fi
        current_dir="$(dirname "${current_dir}")"
    done

    echo "$(pwd)"
}

# Run coverage
run_coverage() {
    local project_root
    project_root=$(find_project_root)

    log "INFO" "Running tests with coverage..."

    cd "${project_root}"

    if ! command_exists pytest; then
        log "ERROR" "pytest not found. Install with: pip install pytest pytest-cov"
        return 1
    fi

    # Run pytest with coverage
    if pytest --cov=. --cov-report=term-missing --cov-report=html --cov-report=json -v; then
        log "SUCCESS" "Tests completed"
    else
        log "ERROR" "Tests failed"
        return 1
    fi
}

# Check coverage threshold
check_threshold() {
    local project_root
    project_root=$(find_project_root)

    cd "${project_root}"

    # Check if coverage.json exists
    if [[ ! -f "coverage.json" ]]; then
        log "WARNING" "coverage.json not found. Run tests with coverage first."
        return 1
    fi

    # Extract total coverage percentage
    local coverage
    coverage=$(${PYTHON_CMD} -c "
import json
with open('coverage.json') as f:
    data = json.load(f)
    print(f\"{data['totals']['percent_covered']:.2f}\")
" 2>/dev/null)

    if [[ -z "${coverage}" ]]; then
        log "ERROR" "Failed to extract coverage data"
        return 1
    fi

    log "INFO" "Current coverage: ${coverage}%"
    log "INFO" "Minimum required: ${MIN_COVERAGE}%"

    # Compare coverage
    local coverage_int
    coverage_int=$(echo "${coverage}" | cut -d. -f1)

    if [[ "${coverage_int}" -ge "${MIN_COVERAGE}" ]]; then
        log "SUCCESS" "Coverage meets minimum threshold! 🎉"
        return 0
    else
        local diff=$((MIN_COVERAGE - coverage_int))
        log "ERROR" "Coverage is ${diff}% below minimum threshold"
        log "INFO" "Add more tests to increase coverage"
        return 1
    fi
}

# Show coverage report
show_report() {
    local project_root
    project_root=$(find_project_root)

    cd "${project_root}"

    if [[ -f "htmlcov/index.html" ]]; then
        log "INFO" "HTML coverage report: ${project_root}/htmlcov/index.html"
        log "INFO" "Open with: open htmlcov/index.html (macOS) or xdg-open htmlcov/index.html (Linux)"
    fi
}

# Main function
main() {
    log "INFO" "Checking test coverage..."
    log "INFO" "Minimum coverage threshold: ${MIN_COVERAGE}%"

    local exit_code=0

    # Run coverage
    if ! run_coverage; then
        exit_code=1
    fi

    # Check threshold
    if ! check_threshold; then
        exit_code=1
    fi

    # Show report location
    show_report

    if [[ "${exit_code}" -eq 0 ]]; then
        log "SUCCESS" "Coverage check passed! ✓"
    else
        log "ERROR" "Coverage check failed! ❌"
    fi

    exit "${exit_code}"
}

# Run main function
main "$@"
