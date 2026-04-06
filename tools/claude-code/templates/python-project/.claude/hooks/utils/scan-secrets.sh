#!/bin/bash
#
# scan-secrets.sh - Scan for secrets in files

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Configuration
SCAN_MODE="${1:-all}"
TARGET_FILE="${2:-}"

# Top 5 critical secret patterns
PATTERNS=(
    'AKIA[0-9A-Z]{16}'                                # AWS keys
    'ghp_[0-9a-zA-Z]{36}'                             # GitHub tokens
    '-----BEGIN.*PRIVATE KEY-----'                    # Private keys
    'api[_-]?key.*['\''"][a-zA-Z0-9]{32,}['\''"]'     # API keys
    'password.*=.*['\''"](.+)['\''"]'                 # Passwords
)

# Get files to scan
get_files() {
    case "$SCAN_MODE" in
        --staged)
            git diff --cached --name-only --diff-filter=ACM
            ;;
        --file)
            [[ -n "$TARGET_FILE" ]] && [[ -f "$TARGET_FILE" ]] && echo "$TARGET_FILE"
            ;;
        *)
            git ls-files 2>/dev/null || find . -type f -not -path '*/\.*'
            ;;
    esac
}

# Scan files
scan_secrets() {
    local files
    files=$(get_files)
    [[ -z "$files" ]] && { info "No files to scan"; return 0; }

    # Combine patterns
    local combined_pattern
    combined_pattern=$(IFS='|'; echo "${PATTERNS[*]}")

    # Scan all files
    local found=0
    while IFS= read -r file; do
        # Skip binary, minified, and cache files
        [[ "$file" =~ \.(lock|log|pyc|min\.(js|css))$ ]] && continue
        [[ "$file" =~ (node_modules|__pycache__|\.venv|venv|dist|build) ]] && continue
        [[ ! -f "$file" ]] && continue

        if grep -nEi "$combined_pattern" "$file" 2>/dev/null; then
            error "Secret found in $file"
            found=1
        fi
    done <<< "$files"

    return $found
}

# Main
main() {
    info "Scanning for secrets (mode: $SCAN_MODE)"

    if scan_secrets; then
        info "No secrets detected ✓"
        exit 0
    else
        error "Secrets detected"
        info "Remove secrets before committing"
        exit 1
    fi
}

main "$@"
