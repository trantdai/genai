#!/bin/bash
#
# Script: scan-secrets.sh
# Description: Comprehensive secret scanning for sensitive data
# Usage: scan-secrets.sh [--staged|--file <path>|--quick]
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
SCAN_MODE="${1:-all}"
TARGET_FILE="${2:-}"

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

# Secret patterns to detect
declare -A SECRET_PATTERNS=(
    ["AWS Access Key"]="AKIA[0-9A-Z]{16}"
    ["AWS Secret Key"]="[0-9a-zA-Z/+=]{40}"
    ["GitHub Token"]="ghp_[0-9a-zA-Z]{36}"
    ["GitHub OAuth"]="gho_[0-9a-zA-Z]{36}"
    ["Generic API Key"]="api[_-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{32,}['\"]"
    ["Generic Secret"]="secret['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]"
    ["Password"]="password['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    ["Private Key"]="-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ["JWT Token"]="eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+"
    ["Slack Token"]="xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,32}"
    ["Stripe Key"]="sk_live_[0-9a-zA-Z]{24,}"
    ["Google API Key"]="AIza[0-9A-Za-z-_]{35}"
    ["Heroku API Key"]="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    ["MailChimp API Key"]="[0-9a-f]{32}-us[0-9]{1,2}"
    ["Twilio API Key"]="SK[0-9a-fA-F]{32}"
    ["Database URL"]="(postgres|mysql|mongodb)://[^:]+:[^@]+@[^/]+"
)

# Files to exclude from scanning
readonly EXCLUDE_PATTERNS=(
    "*.lock"
    "*.log"
    "*.min.js"
    "*.min.css"
    "node_modules/*"
    ".git/*"
    "*.pyc"
    "__pycache__/*"
    ".venv/*"
    "venv/*"
    "dist/*"
    "build/*"
    "*.egg-info/*"
)

# Get files to scan
get_files_to_scan() {
    case "${SCAN_MODE}" in
        --staged)
            git diff --cached --name-only --diff-filter=ACM
            ;;
        --file)
            if [[ -n "${TARGET_FILE}" ]] && [[ -f "${TARGET_FILE}" ]]; then
                echo "${TARGET_FILE}"
            else
                log "ERROR" "File not found: ${TARGET_FILE}"
                return 1
            fi
            ;;
        --quick)
            git ls-files | head -n 100
            ;;
        *)
            git ls-files 2>/dev/null || find . -type f -not -path '*/\.*'
            ;;
    esac
}

# Check if file should be excluded
should_exclude() {
    local file="$1"

    for pattern in "${EXCLUDE_PATTERNS[@]}"; do
        if [[ "${file}" == ${pattern} ]]; then
            return 0
        fi
    done

    return 1
}

# Scan file for secrets
scan_file() {
    local file="$1"
    local found_secrets=0

    # Skip if file should be excluded
    if should_exclude "${file}"; then
        return 0
    fi

    # Skip if file doesn't exist or is not readable
    if [[ ! -f "${file}" ]] || [[ ! -r "${file}" ]]; then
        return 0
    fi

    # Skip binary files
    if file "${file}" 2>/dev/null | grep -q "binary"; then
        return 0
    fi

    # Scan for each pattern
    for pattern_name in "${!SECRET_PATTERNS[@]}"; do
        local pattern="${SECRET_PATTERNS[$pattern_name]}"

        if grep -nEi "${pattern}" "${file}" 2>/dev/null | while IFS=: read -r line_num match; do
            log "ERROR" "Potential ${pattern_name} found in ${file}:${line_num}"
            echo "  ${match}" | sed 's/^/  /'
            found_secrets=1
        done; then
            found_secrets=1
        fi
    done

    return "${found_secrets}"
}

# Use detect-secrets if available
use_detect_secrets() {
    if ! command_exists detect-secrets; then
        return 1
    fi

    log "INFO" "Running detect-secrets scan..."

    local files
    files=$(get_files_to_scan)

    if [[ -z "${files}" ]]; then
        log "INFO" "No files to scan"
        return 0
    fi

    local temp_file
    temp_file=$(mktemp)

    echo "${files}" | while read -r file; do
        if [[ -f "${file}" ]]; then
            detect-secrets scan "${file}" 2>/dev/null || true
        fi
    done > "${temp_file}"

    if grep -q "True" "${temp_file}"; then
        log "ERROR" "Secrets detected by detect-secrets"
        cat "${temp_file}"
        rm -f "${temp_file}"
        return 1
    fi

    rm -f "${temp_file}"
    return 0
}

# Use gitleaks if available
use_gitleaks() {
    if ! command_exists gitleaks; then
        return 1
    fi

    log "INFO" "Running gitleaks scan..."

    if gitleaks detect --no-git --verbose 2>&1 | grep -q "leaks found"; then
        log "ERROR" "Secrets detected by gitleaks"
        return 1
    fi

    return 0
}

# Use truffleHog if available
use_trufflehog() {
    if ! command_exists trufflehog; then
        return 1
    fi

    log "INFO" "Running truffleHog scan..."

    if trufflehog filesystem . --json 2>/dev/null | grep -q "Raw"; then
        log "ERROR" "Secrets detected by truffleHog"
        return 1
    fi

    return 0
}

# Main function
main() {
    log "INFO" "Starting secret scan..."
    log "INFO" "Scan mode: ${SCAN_MODE}"

    local exit_code=0
    local files
    files=$(get_files_to_scan)

    if [[ -z "${files}" ]]; then
        log "INFO" "No files to scan"
        exit 0
    fi

    local file_count
    file_count=$(echo "${files}" | wc -l | tr -d ' ')
    log "INFO" "Scanning ${file_count} file(s)..."

    # Try specialized tools first
    if use_detect_secrets; then
        log "SUCCESS" "detect-secrets scan passed"
    elif use_gitleaks; then
        log "SUCCESS" "gitleaks scan passed"
    elif use_trufflehog; then
        log "SUCCESS" "truffleHog scan passed"
    else
        # Fall back to pattern matching
        log "INFO" "Using pattern-based scanning..."

        while IFS= read -r file; do
            if ! scan_file "${file}"; then
                exit_code=1
            fi
        done <<< "${files}"
    fi

    if [[ "${exit_code}" -eq 0 ]]; then
        log "SUCCESS" "No secrets detected! ✓"
    else
        log "ERROR" "Secrets detected! ❌"
        log "INFO" "Remove secrets before committing"
        log "INFO" "Consider using environment variables or secret management tools"
    fi

    exit "${exit_code}"
}

# Run main function
main "$@"
