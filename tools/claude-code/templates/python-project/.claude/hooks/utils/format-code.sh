#!/bin/bash
#
# Script: format-code.sh
# Description: Format all Python files in the project
# Usage: format-code.sh [directory]
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
TARGET_DIR="${1:-.}"
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

# Get Python files
get_python_files() {
    local dir="$1"

    find "${dir}" -type f -name "*.py" \
        -not -path "*/\.*" \
        -not -path "*/venv/*" \
        -not -path "*/.venv/*" \
        -not -path "*/node_modules/*" \
        -not -path "*/build/*" \
        -not -path "*/dist/*" \
        -not -path "*/__pycache__/*" \
        -not -path "*.egg-info/*"
}

# Run Black formatter
run_black() {
    log "INFO" "Running Black formatter..."

    if ! command_exists black; then
        log "ERROR" "Black not found. Install with: pip install black"
        return 1
    fi

    local files
    files=$(get_python_files "${TARGET_DIR}")

    if [[ -z "${files}" ]]; then
        log "INFO" "No Python files found"
        return 0
    fi

    local file_count
    file_count=$(echo "${files}" | wc -l | tr -d ' ')
    log "INFO" "Formatting ${file_count} file(s)..."

    if echo "${files}" | xargs black --line-length=100; then
        log "SUCCESS" "Black formatting completed"
        return 0
    else
        log "ERROR" "Black formatting failed"
        return 1
    fi
}

# Run isort
run_isort() {
    log "INFO" "Running isort..."

    if ! command_exists isort; then
        log "WARNING" "isort not found. Install with: pip install isort"
        return 0
    fi

    local files
    files=$(get_python_files "${TARGET_DIR}")

    if [[ -z "${files}" ]]; then
        log "INFO" "No Python files found"
        return 0
    fi

    if echo "${files}" | xargs isort --profile=black --line-length=100; then
        log "SUCCESS" "isort completed"
        return 0
    else
        log "ERROR" "isort failed"
        return 1
    fi
}

# Run Ruff auto-fix
run_ruff_fix() {
    log "INFO" "Running Ruff auto-fix..."

    if ! command_exists ruff; then
        log "WARNING" "Ruff not found. Install with: pip install ruff"
        return 0
    fi

    local files
    files=$(get_python_files "${TARGET_DIR}")

    if [[ -z "${files}" ]]; then
        log "INFO" "No Python files found"
        return 0
    fi

    if echo "${files}" | xargs ruff check --fix; then
        log "SUCCESS" "Ruff auto-fix completed"
        return 0
    else
        log "WARNING" "Ruff found issues that couldn't be auto-fixed"
        return 0
    fi
}

# Remove trailing whitespace
remove_trailing_whitespace() {
    log "INFO" "Removing trailing whitespace..."

    local files
    files=$(get_python_files "${TARGET_DIR}")

    if [[ -z "${files}" ]]; then
        log "INFO" "No Python files found"
        return 0
    fi

    while IFS= read -r file; do
        if [[ -f "${file}" ]]; then
            sed -i.bak 's/[[:space:]]*$//' "${file}" && rm -f "${file}.bak"
        fi
    done <<< "${files}"

    log "SUCCESS" "Trailing whitespace removed"
    return 0
}

# Fix line endings
fix_line_endings() {
    log "INFO" "Fixing line endings..."

    local files
    files=$(get_python_files "${TARGET_DIR}")

    if [[ -z "${files}" ]]; then
        log "INFO" "No Python files found"
        return 0
    fi

    while IFS= read -r file; do
        if [[ -f "${file}" ]]; then
            # Convert to Unix line endings
            sed -i.bak 's/\r$//' "${file}" && rm -f "${file}.bak"
        fi
    done <<< "${files}"

    log "SUCCESS" "Line endings fixed"
    return 0
}

# Show summary
show_summary() {
    local project_root
    project_root=$(find_project_root)

    log "INFO" "Formatting summary:"

    local total_files
    total_files=$(get_python_files "${TARGET_DIR}" | wc -l | tr -d ' ')

    echo ""
    echo "  Total files formatted: ${total_files}"
    echo "  Target directory: ${TARGET_DIR}"
    echo "  Project root: ${project_root}"
    echo ""
}

# Main function
main() {
    log "INFO" "Starting code formatting..."
    log "INFO" "Target directory: ${TARGET_DIR}"

    local exit_code=0

    # Run formatters
    run_black || exit_code=1
    run_isort || true  # Non-blocking
    run_ruff_fix || true  # Non-blocking
    remove_trailing_whitespace || true  # Non-blocking
    fix_line_endings || true  # Non-blocking

    # Show summary
    show_summary

    if [[ "${exit_code}" -eq 0 ]]; then
        log "SUCCESS" "Code formatting completed! ✨"
    else
        log "ERROR" "Code formatting failed! ❌"
    fi

    exit "${exit_code}"
}

# Run main function
main "$@"
