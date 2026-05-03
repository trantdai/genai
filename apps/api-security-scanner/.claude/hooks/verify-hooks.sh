#!/bin/bash
#
# verify-hooks.sh - Verify hook system installation
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/utils/common.sh"

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Check and log result
check() {
    if "$@" &>/dev/null; then
        info "✓ $*"
        ((PASSED++))
    else
        error "✗ $*"
        ((FAILED++))
        return 1
    fi
}

warn_if_missing() {
    if "$@" &>/dev/null; then
        info "✓ $*"
        ((PASSED++))
    else
        warn "⚠ $*"
        ((WARNINGS++))
    fi
}

# Verify files exist and are executable
verify_file() {
    local file="$1"
    local name="$2"

    if [[ -f "$file" ]]; then
        if [[ -x "$file" ]]; then
            info "✓ $name"
            ((PASSED++))
        else
            error "✗ $name (not executable)"
            ((FAILED++))
        fi
    else
        error "✗ $name (missing)"
        ((FAILED++))
    fi
}

# Verify JSON syntax
verify_json() {
    local file="$1"
    local name="$2"

    if [[ -f "$file" ]] && python3 -m json.tool "$file" >/dev/null 2>&1; then
        info "✓ $name"
        ((PASSED++))
    else
        error "✗ $name"
        ((FAILED++))
    fi
}

main() {
    echo "Hook System Verification"
    echo "========================"

    # Directory structure
    check test -d "${SCRIPT_DIR}/git"
    check test -d "${SCRIPT_DIR}/claude"
    check test -d "${SCRIPT_DIR}/utils"

    # Git hooks
    verify_file "${SCRIPT_DIR}/git/pre-commit.sh" "pre-commit hook"
    verify_file "${SCRIPT_DIR}/git/pre-push.sh" "pre-push hook"
    verify_file "${SCRIPT_DIR}/git/post-checkout.sh" "post-checkout hook"
    verify_file "${SCRIPT_DIR}/git/post-merge.sh" "post-merge hook"
    verify_file "${SCRIPT_DIR}/git/commit-msg.sh" "commit-msg hook"

    # Utility scripts
    verify_file "${SCRIPT_DIR}/utils/common.sh" "common utilities"
    verify_file "${SCRIPT_DIR}/utils/check-coverage.sh" "coverage checker"
    verify_file "${SCRIPT_DIR}/utils/scan-secrets.sh" "secret scanner"

    # Claude hooks (JSON validation)
    verify_json "${SCRIPT_DIR}/claude/pre-tool-use.json" "pre-tool-use config"
    verify_json "${SCRIPT_DIR}/claude/post-tool-use.json" "post-tool-use config"
    verify_json "${SCRIPT_DIR}/claude/session-hooks.json" "session hooks config"

    # Required tools
    check cmd_exists python3
    check cmd_exists git

    # Optional tools (warnings only)
    warn_if_missing cmd_exists black
    warn_if_missing cmd_exists ruff
    warn_if_missing cmd_exists mypy
    warn_if_missing cmd_exists pytest

    # Summary
    echo ""
    echo "Results"
    echo "======="
    echo "Passed:   $PASSED"
    echo "Failed:   $FAILED"
    echo "Warnings: $WARNINGS"

    if [[ $FAILED -eq 0 ]]; then
        echo ""
        info "✓ All checks passed"
        return 0
    else
        echo ""
        error "✗ Some checks failed"
        return 1
    fi
}

main "$@"
