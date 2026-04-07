#!/bin/bash
#
# pre-commit.sh - Git pre-commit hook for Python projects

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../utils/common.sh"

# Configuration
SKIP_HOOKS="${SKIP_HOOKS:-false}"
MAX_FILE_SIZE=$((5 * 1024 * 1024))

# Scan for secrets (5 critical patterns)
scan_secrets() {
    local files="$1"
    echo "$files" | xargs grep -nE \
        'AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|-----BEGIN.*PRIVATE KEY-----|api[_-]?key.*['\''"][a-zA-Z0-9]{32,}['\''"]|password.*=.*['\''"](.+)['\''"]' \
        2>/dev/null && return 1 || return 0
}

# Check Black formatting
check_black() {
    [[ -z "$1" ]] && return 0
    cmd_exists black || { warn "Black not found"; return 0; }
    echo "$1" | xargs black --check --quiet 2>/dev/null || { error "Black formatting required"; return 1; }
}

# Check Ruff linting
check_ruff() {
    [[ -z "$1" ]] && return 0
    cmd_exists ruff || { warn "Ruff not found"; return 0; }
    echo "$1" | xargs ruff check --quiet 2>/dev/null || { error "Ruff linting failed"; return 1; }
}

# Check mypy type hints
check_mypy() {
    [[ -z "$1" ]] && return 0
    cmd_exists mypy || { warn "mypy not found"; return 0; }
    echo "$1" | xargs mypy --no-error-summary 2>/dev/null || warn "Type checking failed (non-blocking)"
}

# Check file sizes
check_file_sizes() {
    local files
    files=$(git diff --cached --name-only --diff-filter=ACM)
    [[ -z "$files" ]] && return 0

    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            local size
            size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo 0)
            [[ "$size" -gt "$MAX_FILE_SIZE" ]] && warn "Large file: $file ($((size / 1024 / 1024))MB)"
        fi
    done <<< "$files"
}

# Main
main() {
    [[ "$SKIP_HOOKS" == "true" ]] && { warn "Hooks skipped"; exit 0; }

    local py_files
    py_files=$(get_staged_python_files)
    [[ -z "$py_files" ]] && { info "No Python files to check"; exit 0; }

    local exit_code=0

    check_black "$py_files" || exit_code=1
    check_ruff "$py_files" || exit_code=1
    check_mypy "$py_files"
    scan_secrets "$py_files" || { error "Secrets detected"; exit_code=1; }
    check_file_sizes

    [[ "$exit_code" -eq 0 ]] && info "Pre-commit checks passed" || error "Pre-commit checks failed"
    exit "$exit_code"
}

main "$@"
