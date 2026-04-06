#!/bin/bash
#
# commit-msg.sh - Git commit-msg hook for Python projects

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../utils/common.sh"

# Configuration
SKIP_HOOKS="${SKIP_HOOKS:-false}"

# Validate conventional commit format
validate_commit() {
    local msg="$1"
    local subject
    subject=$(echo "$msg" | head -n 1)

    # Skip merge, revert, and fixup commits
    [[ "$subject" =~ ^(Merge|Revert|fixup|squash) ]] && return 0

    # Validate format: type(scope): description
    # Allowed types: feat|fix|docs|test|refactor|chore|perf|ci
    if echo "$subject" | grep -qE '^(feat|fix|docs|test|refactor|chore|perf|ci)(\(.+\))?: .{1,72}$'; then
        return 0
    else
        error "Invalid commit format"
        info "Expected: <type>(<scope>): <description>"
        info "Types: feat, fix, docs, test, refactor, chore, perf, ci"
        return 1
    fi
}

# Main
main() {
    local commit_msg_file="$1"

    [[ "$SKIP_HOOKS" == "true" ]] && exit 0
    [[ ! -f "$commit_msg_file" ]] && die "Commit message file not found"

    local message
    message=$(cat "$commit_msg_file")

    if validate_commit "$message"; then
        info "Commit message valid"
        exit 0
    else
        error "Commit message validation failed"
        info "Skip with: SKIP_HOOKS=true git commit"
        exit 1
    fi
}

main "$@"
