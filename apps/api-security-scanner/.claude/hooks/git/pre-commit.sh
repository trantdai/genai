#!/bin/bash
#
# Script: pre-commit.sh
# Description: Git pre-commit hook for Python projects
#              Runs formatting, linting, and secret scanning before commit
# Usage: Automatically executed by git before commit
#

set -euo pipefail

# Constants
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HOOK_NAME="pre-commit"
readonly LOG_FILE="${SCRIPT_DIR}/../.hook-logs/${HOOK_NAME}-$(date +%Y%m%d-%H%M%S).log"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration
SKIP_HOOKS="${SKIP_HOOKS:-false}"
SKIP_FORMAT="${SKIP_FORMAT:-false}"
SKIP_LINT="${SKIP_LINT:-false}"
SKIP_SECRETS="${SKIP_SECRETS:-false}"
PYTHON_CMD="${PYTHON_CMD:-python3}"

# Cleanup function
cleanup() {
    if [[ -f "${temp_file:-}" ]]; then
        rm -f "${temp_file}"
    fi
}

trap cleanup EXIT ERR

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    mkdir -p "$(dirname "${LOG_FILE}")"
    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}"

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

# Get list of staged Python files
get_staged_python_files() {
    git diff --cached --name-only --diff-filter=ACM | grep -E '\.py$' || true
}

# Run Black formatter
run_black() {
    log "INFO" "Running Black formatter..."

    local files
    files=$(get_staged_python_files)

    if [[ -z "${files}" ]]; then
        log "INFO" "No Python files to format"
        return 0
    fi

    if ! command_exists black; then
        log "WARNING" "Black not found, skipping formatting"
        return 0
    fi

    if echo "${files}" | xargs black --check --quiet 2>/dev/null; then
        log "SUCCESS" "All files are properly formatted"
        return 0
    else
        log "ERROR" "Files need formatting. Run: black ${files}"
        log "INFO" "Or auto-format with: black ${files} && git add ${files}"
        return 1
    fi
}

# Run Ruff linter
run_ruff() {
    log "INFO" "Running Ruff linter..."

    local files
    files=$(get_staged_python_files)

    if [[ -z "${files}" ]]; then
        log "INFO" "No Python files to lint"
        return 0
    fi

    if ! command_exists ruff; then
        log "WARNING" "Ruff not found, skipping linting"
        return 0
    fi

    if echo "${files}" | xargs ruff check --quiet 2>/dev/null; then
        log "SUCCESS" "All files passed linting"
        return 0
    else
        log "ERROR" "Linting errors found. Run: ruff check ${files}"
        log "INFO" "Or auto-fix with: ruff check --fix ${files}"
        return 1
    fi
}

# Run mypy type checking
run_mypy() {
    log "INFO" "Running mypy type checker..."

    local files
    files=$(get_staged_python_files)

    if [[ -z "${files}" ]]; then
        log "INFO" "No Python files to type check"
        return 0
    fi

    if ! command_exists mypy; then
        log "WARNING" "mypy not found, skipping type checking"
        return 0
    fi

    if echo "${files}" | xargs mypy --no-error-summary 2>/dev/null; then
        log "SUCCESS" "Type checking passed"
        return 0
    else
        log "ERROR" "Type checking errors found. Run: mypy ${files}"
        return 1
    fi
}

# Run secret scanning
run_secret_scan() {
    log "INFO" "Scanning for secrets..."

    if [[ -f "${SCRIPT_DIR}/../utils/scan-secrets.sh" ]]; then
        if bash "${SCRIPT_DIR}/../utils/scan-secrets.sh" --staged; then
            log "SUCCESS" "No secrets detected"
            return 0
        else
            log "ERROR" "Secrets detected in staged files!"
            log "INFO" "Remove secrets before committing"
            return 1
        fi
    else
        log "WARNING" "Secret scanner not found, skipping"
        return 0
    fi
}

# Check for trailing whitespace
check_whitespace() {
    log "INFO" "Checking for trailing whitespace..."

    local files
    files=$(git diff --cached --name-only --diff-filter=ACM)

    if [[ -z "${files}" ]]; then
        return 0
    fi

    local has_whitespace=false
    while IFS= read -r file; do
        if [[ -f "${file}" ]] && grep -q '[[:space:]]$' "${file}" 2>/dev/null; then
            log "WARNING" "Trailing whitespace found in: ${file}"
            has_whitespace=true
        fi
    done <<< "${files}"

    if [[ "${has_whitespace}" == "true" ]]; then
        log "INFO" "Run: git diff --check to see whitespace issues"
        return 1
    fi

    log "SUCCESS" "No trailing whitespace found"
    return 0
}

# Check for large files
check_file_size() {
    log "INFO" "Checking for large files..."

    local max_size=$((5 * 1024 * 1024)) # 5MB
    local files
    files=$(git diff --cached --name-only --diff-filter=ACM)

    if [[ -z "${files}" ]]; then
        return 0
    fi

    local has_large_files=false
    while IFS= read -r file; do
        if [[ -f "${file}" ]]; then
            local size
            size=$(stat -f%z "${file}" 2>/dev/null || stat -c%s "${file}" 2>/dev/null || echo 0)
            if [[ "${size}" -gt "${max_size}" ]]; then
                log "WARNING" "Large file detected ($(numfmt --to=iec "${size}" 2>/dev/null || echo "${size} bytes")): ${file}"
                has_large_files=true
            fi
        fi
    done <<< "${files}"

    if [[ "${has_large_files}" == "true" ]]; then
        log "INFO" "Consider using Git LFS for large files"
        return 1
    fi

    log "SUCCESS" "No large files detected"
    return 0
}

# Main function
main() {
    log "INFO" "Starting pre-commit hook..."
    log "INFO" "Log file: ${LOG_FILE}"

    # Check for skip flag
    if [[ "${SKIP_HOOKS}" == "true" ]]; then
        log "WARNING" "Hooks skipped via SKIP_HOOKS environment variable"
        log "WARNING" "Use with caution!"
        exit 0
    fi

    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log "ERROR" "Not in a git repository"
        exit 1
    fi

    # Check if there are staged files
    if ! git diff --cached --quiet; then
        log "INFO" "Found staged files to check"
    else
        log "INFO" "No staged files to check"
        exit 0
    fi

    local exit_code=0

    # Run formatting checks
    if [[ "${SKIP_FORMAT}" != "true" ]]; then
        if ! run_black; then
            exit_code=1
        fi
    else
        log "WARNING" "Formatting checks skipped"
    fi

    # Run linting
    if [[ "${SKIP_LINT}" != "true" ]]; then
        if ! run_ruff; then
            exit_code=1
        fi

        # Type checking is optional but recommended
        run_mypy || log "WARNING" "Type checking failed (non-blocking)"
    else
        log "WARNING" "Linting checks skipped"
    fi

    # Run secret scanning
    if [[ "${SKIP_SECRETS}" != "true" ]]; then
        if ! run_secret_scan; then
            exit_code=1
        fi
    else
        log "WARNING" "Secret scanning skipped"
    fi

    # Run additional checks
    check_whitespace || log "WARNING" "Whitespace issues found (non-blocking)"
    check_file_size || log "WARNING" "Large files found (non-blocking)"

    # Summary
    echo ""
    if [[ "${exit_code}" -eq 0 ]]; then
        log "SUCCESS" "All pre-commit checks passed! 🎉"
        log "INFO" "Proceeding with commit..."
    else
        log "ERROR" "Pre-commit checks failed! ❌"
        log "INFO" "Fix the issues above or skip with: SKIP_HOOKS=true git commit"
        echo ""
    fi

    exit "${exit_code}"
}

# Run main function
main "$@"
