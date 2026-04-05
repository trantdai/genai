#!/bin/bash
#
# Script: validate-dependencies.sh
# Description: Check for security vulnerabilities in dependencies
# Usage: validate-dependencies.sh
#

set -euo pipefail

# Constants
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Configuration
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

# Check with pip-audit
check_pip_audit() {
    log "INFO" "Running pip-audit..."

    if ! command_exists pip-audit; then
        log "WARNING" "pip-audit not found. Install with: pip install pip-audit"
        return 0
    fi

    if pip-audit --desc --format json > pip-audit-report.json 2>/dev/null; then
        log "SUCCESS" "pip-audit: No vulnerabilities found"
        return 0
    else
        log "ERROR" "pip-audit found vulnerabilities"
        pip-audit --desc
        return 1
    fi
}

# Check with Safety
check_safety() {
    log "INFO" "Running Safety..."

    if ! command_exists safety; then
        log "WARNING" "Safety not found. Install with: pip install safety"
        return 0
    fi

    if safety check --json > safety-report.json 2>/dev/null; then
        log "SUCCESS" "Safety: No vulnerabilities found"
        return 0
    else
        log "ERROR" "Safety found vulnerabilities"
        safety check
        return 1
    fi
}

# Check for outdated packages
check_outdated() {
    log "INFO" "Checking for outdated packages..."

    local outdated
    outdated=$("${PYTHON_CMD}" -m pip list --outdated --format=json 2>/dev/null)

    if [[ "${outdated}" == "[]" ]]; then
        log "SUCCESS" "All packages are up to date"
        return 0
    else
        log "WARNING" "Some packages are outdated:"
        "${PYTHON_CMD}" -m pip list --outdated
        return 0
    fi
}

# Validate requirements files
validate_requirements() {
    log "INFO" "Validating requirements files..."

    local project_root
    project_root=$(find_project_root)

    cd "${project_root}"

    local req_files=(
        "requirements.txt"
        "requirements-dev.txt"
        "requirements-test.txt"
    )

    for req_file in "${req_files[@]}"; do
        if [[ -f "${req_file}" ]]; then
            log "INFO" "Checking ${req_file}..."

            # Check for unpinned versions
            if grep -E "^[a-zA-Z0-9_-]+$" "${req_file}" 2>/dev/null; then
                log "WARNING" "Found unpinned dependencies in ${req_file}"
                log "INFO" "Consider pinning versions for reproducibility"
            fi

            # Check for exact pins (==)
            if grep -E "==" "${req_file}" 2>/dev/null; then
                log "WARNING" "Found exact version pins (==) in ${req_file}"
                log "INFO" "Consider using minimum version constraints (>=) for flexibility"
            fi
        fi
    done

    log "SUCCESS" "Requirements validation completed"
    return 0
}

# Check dependency conflicts
check_conflicts() {
    log "INFO" "Checking for dependency conflicts..."

    if "${PYTHON_CMD}" -m pip check 2>&1 | grep -q "No broken requirements"; then
        log "SUCCESS" "No dependency conflicts found"
        return 0
    else
        log "ERROR" "Dependency conflicts detected:"
        "${PYTHON_CMD}" -m pip check
        return 1
    fi
}

# Generate dependency report
generate_report() {
    local project_root
    project_root=$(find_project_root)

    local report_file="${project_root}/dependency-report.txt"

    log "INFO" "Generating dependency report..."

    cat > "${report_file}" <<EOF
Dependency Validation Report
============================
Generated: $(date)
Project: ${project_root}

Installed Packages:
-------------------
EOF

    "${PYTHON_CMD}" -m pip list >> "${report_file}"

    echo "" >> "${report_file}"
    echo "Dependency Tree:" >> "${report_file}"
    echo "----------------" >> "${report_file}"

    if command_exists pipdeptree; then
        pipdeptree >> "${report_file}"
    else
        echo "pipdeptree not installed" >> "${report_file}"
    fi

    log "SUCCESS" "Dependency report generated: ${report_file}"
}

# Main function
main() {
    log "INFO" "Starting dependency validation..."

    local exit_code=0

    # Run all checks
    check_pip_audit || exit_code=1
    check_safety || exit_code=1
    check_outdated || true  # Non-blocking
    validate_requirements || true  # Non-blocking
    check_conflicts || exit_code=1

    # Generate report
    generate_report

    echo ""
    if [[ "${exit_code}" -eq 0 ]]; then
        log "SUCCESS" "Dependency validation passed! ✓"
    else
        log "ERROR" "Dependency validation failed! ❌"
        log "INFO" "Review the issues above and update dependencies"
    fi

    exit "${exit_code}"
}

# Run main function
main "$@"
