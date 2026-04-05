#!/bin/bash
#
# Script: run-security-checks.sh
# Description: Run all security tools and checks
# Usage: run-security-checks.sh
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

# Run Bandit security linter
run_bandit() {
    log "INFO" "Running Bandit security linter..."

    if ! command_exists bandit; then
        log "WARNING" "Bandit not found. Install with: pip install bandit"
        return 0
    fi

    local project_root
    project_root=$(find_project_root)

    cd "${project_root}"

    if bandit -r . -f json -o bandit-report.json 2>/dev/null; then
        log "SUCCESS" "Bandit scan passed"
        return 0
    else
        log "ERROR" "Bandit found security issues"
        bandit -r . -f screen
        return 1
    fi
}

# Run Safety dependency checker
run_safety() {
    log "INFO" "Running Safety dependency checker..."

    if ! command_exists safety; then
        log "WARNING" "Safety not found. Install with: pip install safety"
        return 0
    fi

    local project_root
    project_root=$(find_project_root)

    cd "${project_root}"

    if safety check --json 2>/dev/null; then
        log "SUCCESS" "Safety check passed"
        return 0
    else
        log "ERROR" "Safety found vulnerable dependencies"
        safety check
        return 1
    fi
}

# Run pip-audit
run_pip_audit() {
    log "INFO" "Running pip-audit..."

    if ! command_exists pip-audit; then
        log "WARNING" "pip-audit not found. Install with: pip install pip-audit"
        return 0
    fi

    if pip-audit --desc 2>/dev/null; then
        log "SUCCESS" "pip-audit passed"
        return 0
    else
        log "ERROR" "pip-audit found vulnerabilities"
        return 1
    fi
}

# Run secret scanning
run_secret_scan() {
    log "INFO" "Running secret scan..."

    if [[ -f "${SCRIPT_DIR}/scan-secrets.sh" ]]; then
        if bash "${SCRIPT_DIR}/scan-secrets.sh"; then
            log "SUCCESS" "Secret scan passed"
            return 0
        else
            log "ERROR" "Secret scan found issues"
            return 1
        fi
    else
        log "WARNING" "Secret scanner not found"
        return 0
    fi
}

# Check for known vulnerable patterns
check_vulnerable_patterns() {
    log "INFO" "Checking for vulnerable code patterns..."

    local project_root
    project_root=$(find_project_root)

    cd "${project_root}"

    local issues_found=0

    # Check for eval() usage
    if git ls-files '*.py' | xargs grep -n "eval(" 2>/dev/null; then
        log "WARNING" "Found eval() usage - potential security risk"
        issues_found=1
    fi

    # Check for exec() usage
    if git ls-files '*.py' | xargs grep -n "exec(" 2>/dev/null; then
        log "WARNING" "Found exec() usage - potential security risk"
        issues_found=1
    fi

    # Check for pickle usage
    if git ls-files '*.py' | xargs grep -n "import pickle" 2>/dev/null; then
        log "WARNING" "Found pickle usage - ensure data source is trusted"
        issues_found=1
    fi

    # Check for shell=True in subprocess
    if git ls-files '*.py' | xargs grep -n "shell=True" 2>/dev/null; then
        log "WARNING" "Found shell=True in subprocess - potential command injection risk"
        issues_found=1
    fi

    # Check for hardcoded IPs
    if git ls-files '*.py' | xargs grep -nE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" 2>/dev/null | grep -v "127.0.0.1\|0.0.0.0"; then
        log "WARNING" "Found hardcoded IP addresses"
        issues_found=1
    fi

    if [[ "${issues_found}" -eq 0 ]]; then
        log "SUCCESS" "No vulnerable patterns found"
        return 0
    else
        log "WARNING" "Found potentially vulnerable patterns (non-blocking)"
        return 0
    fi
}

# Check SSL/TLS configuration
check_ssl_config() {
    log "INFO" "Checking SSL/TLS configuration..."

    local project_root
    project_root=$(find_project_root)

    cd "${project_root}"

    # Check for SSL verification disabled
    if git ls-files '*.py' | xargs grep -n "verify=False" 2>/dev/null; then
        log "WARNING" "Found SSL verification disabled"
        return 1
    fi

    log "SUCCESS" "SSL/TLS configuration looks good"
    return 0
}

# Generate security report
generate_report() {
    local project_root
    project_root=$(find_project_root)

    local report_file="${project_root}/security-report.txt"

    log "INFO" "Generating security report..."

    cat > "${report_file}" <<EOF
Security Scan Report
====================
Generated: $(date)
Project: ${project_root}

Summary:
--------
EOF

    if [[ -f "${project_root}/bandit-report.json" ]]; then
        echo "Bandit Report: ${project_root}/bandit-report.json" >> "${report_file}"
    fi

    log "SUCCESS" "Security report generated: ${report_file}"
}

# Main function
main() {
    log "INFO" "Starting comprehensive security checks..."

    local exit_code=0

    # Run all security checks
    run_bandit || exit_code=1
    run_safety || exit_code=1
    run_pip_audit || exit_code=1
    run_secret_scan || exit_code=1
    check_vulnerable_patterns || true  # Non-blocking
    check_ssl_config || true  # Non-blocking

    # Generate report
    generate_report

    echo ""
    if [[ "${exit_code}" -eq 0 ]]; then
        log "SUCCESS" "All security checks passed! 🔒"
    else
        log "ERROR" "Security checks failed! ❌"
        log "INFO" "Review the issues above and fix them"
    fi

    exit "${exit_code}"
}

# Run main function
main "$@"
