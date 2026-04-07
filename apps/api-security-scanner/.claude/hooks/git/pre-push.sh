#!/bin/bash
#
# pre-push.sh - Git pre-push hook for Python projects

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../utils/common.sh"

# Configuration
SKIP_HOOKS="${SKIP_HOOKS:-false}"
SKIP_TESTS="${SKIP_TESTS:-false}"
MIN_COVERAGE="${MIN_COVERAGE:-80}"

# Run tests with coverage
run_tests() {
    local project_root
    project_root=$(find_project_root)

    cmd_exists pytest || { warn "pytest not found"; return 0; }
    [[ ! -d "${project_root}/tests" ]] && [[ ! -d "${project_root}/test" ]] && { warn "No tests found"; return 0; }

    cd "${project_root}" || return 1
    pytest --cov=src --cov-report=term-missing --cov-fail-under="${MIN_COVERAGE}" -v --tb=short 2>&1 | tee /tmp/pytest_output.log || return 1
}

# Check coverage from pytest output
check_coverage() {
    [[ ! -f /tmp/pytest_output.log ]] && return 0

    local coverage
    coverage=$(grep -oP 'TOTAL.*\K\d+%' /tmp/pytest_output.log | tr -d '%' || echo "0")

    [[ "$coverage" -ge "$MIN_COVERAGE" ]] || { error "Coverage ${coverage}% < ${MIN_COVERAGE}%"; return 1; }
    info "Coverage: ${coverage}%"
}

# Scan for critical secrets
scan_secrets() {
    local staged_files
    staged_files=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.py$' || true)
    [[ -z "$staged_files" ]] && return 0

    echo "$staged_files" | xargs grep -nE \
        'AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|-----BEGIN.*PRIVATE KEY-----|api[_-]?key.*['\''"][a-zA-Z0-9]{32,}['\''"]|password.*=.*['\''"](.+)['\''"]' \
        2>/dev/null && { error "Secrets detected"; return 1; } || return 0
}

# Validate conventional commits (8 core types)
validate_commits() {
    local remote_ref="$1"
    local range

    if git rev-parse "${remote_ref}" >/dev/null 2>&1; then
        range="${remote_ref}..HEAD"
    else
        range="HEAD"
    fi

    local invalid=0
    while IFS= read -r commit; do
        local msg
        msg=$(git log --format=%B -n 1 "${commit}")
        echo "${msg}" | grep -qE '^(feat|fix|docs|test|refactor|chore|perf|ci)(\(.+\))?: .+' || {
            warn "Commit ${commit:0:7} non-conventional"
            ((invalid++))
        }
    done < <(git rev-list "${range}" 2>/dev/null || true)

    [[ "$invalid" -gt 0 ]] && warn "${invalid} non-conventional commits (non-blocking)"
    return 0
}

# Check branch
check_branch() {
    local local_ref="$1"
    [[ "$local_ref" =~ (main|master) ]] && warn "Pushing to ${local_ref}"
}

# Main
main() {
    [[ "$SKIP_HOOKS" == "true" ]] && { warn "Hooks skipped"; exit 0; }

    local local_ref local_sha remote_ref remote_sha
    while read -r local_ref local_sha remote_ref remote_sha; do
        check_branch "$local_ref"
        validate_commits "$remote_ref"
    done

    [[ "$SKIP_TESTS" == "true" ]] && { warn "Tests skipped"; exit 0; }

    local exit_code=0
    run_tests || exit_code=1
    check_coverage || exit_code=1
    scan_secrets || exit_code=1

    [[ "$exit_code" -eq 0 ]] && info "Pre-push checks passed" || error "Pre-push checks failed"
    exit "$exit_code"
}

main "$@"
