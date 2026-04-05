#!/bin/bash
#
# Script: pre-push.sh
# Description: Git pre-push hook for Python projects
#              Runs full test suite and coverage checks before push
# Usage: Automatically executed by git before push
#

set -euo pipefail

# Constants
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HOOK_NAME="pre-push"
readonly LOG_FILE="${SCRIPT_DIR}/../.hook-logs/${HOOK_NAME}-$(date +%Y%m%d-%H%M%S).log"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration
SKIP_HOOKS="${SKIP_HOOKS:-false}"
SKIP_TESTS="${SKIP_TESTS:-false}"
SKIP_COVERAGE="${SKIP_COVERAGE:-false}"
SKIP_SECURITY="${SKIP_SECURITY:-false}"
MIN_COVERAGE="${MIN_COVERAGE:-80}"
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

# Find project root (where pyproject.toml or setup.py exists)
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

# Run pytest with coverage
run_tests() {
    log "INFO" "Running test suite..."

    local project_root
    project_root=$(find_project_root)

    if ! command_exists pytest; then
        log "ERROR" "pytest not found. Install with: pip install pytest pytest-cov"
        return 1
    fi

    # Check if tests directory exists
    if [[ ! -d "${project_root}/tests" ]] && [[ ! -d "${project_root}/test" ]]; then
        log "WARNING" "No tests directory found, skipping tests"
        return 0
    fi

    log "INFO" "Running tests from: ${project_root}"

    if cd "${project_root}" && pytest -v --tb=short 2>&1 | tee -a "${LOG_FILE}"; then
        log "SUCCESS" "All tests passed"
        return 0
    else
        log "ERROR" "Tests failed"
        return 1
    fi
}

# Check test coverage
check_coverage() {
    log "INFO" "Checking test coverage (minimum: ${MIN_COVERAGE}%)..."

    if [[ -f "${SCRIPT_DIR}/../utils/check-coverage.sh" ]]; then
        if bash "${SCRIPT_DIR}/../utils/check-coverage.sh" "${MIN_COVERAGE}"; then
            log "SUCCESS" "Coverage meets minimum threshold"
            return 0
        else
            log "ERROR" "Coverage below minimum threshold of ${MIN_COVERAGE}%"
            return 1
        fi
    else
        log "WARNING" "Coverage checker not found, skipping"
        return 0
    fi
}

# Run security checks
run_security_checks() {
    log "INFO" "Running security checks..."

    if [[ -f "${SCRIPT_DIR}/../utils/run-security-checks.sh" ]]; then
        if bash "${SCRIPT_DIR}/../utils/run-security-checks.sh"; then
            log "SUCCESS" "Security checks passed"
            return 0
        else
            log "ERROR" "Security checks failed"
            return 1
        fi
    else
        log "WARNING" "Security checker not found, skipping"
        return 0
    fi
}

# Check for uncommitted changes
check_uncommitted_changes() {
    log "INFO" "Checking for uncommitted changes..."

    if ! git diff-index --quiet HEAD --; then
        log "WARNING" "You have uncommitted changes"
        log "INFO" "Consider committing or stashing them before pushing"
        return 0
    fi

    log "SUCCESS" "No uncommitted changes"
    return 0
}

# Check branch protection
check_branch_protection() {
    local remote="$1"
    local branch="$2"

    log "INFO" "Checking branch: ${branch}"

    # Warn if pushing to main/master
    if [[ "${branch}" == "refs/heads/main" ]] || [[ "${branch}" == "refs/heads/master" ]]; then
        log "WARNING" "Pushing directly to ${branch}"
        log "INFO" "Consider using pull requests for main/master branches"
    fi

    return 0
}

# Validate commit messages
validate_commits() {
    local remote="$1"
    local remote_ref="$2"

    log "INFO" "Validating commit messages..."

    # Get list of commits being pushed
    local range
    if git rev-parse "${remote_ref}" >/dev/null 2>&1; then
        range="${remote_ref}..HEAD"
    else
        # New branch, check all commits
        range="HEAD"
    fi

    local invalid_commits=0
    while IFS= read -r commit; do
        local message
        message=$(git log --format=%B -n 1 "${commit}")

        # Basic conventional commit check
        if ! echo "${message}" | grep -qE '^(feat|fix|docs|style|refactor|test|chore|perf|ci|build|revert|wip|security|config|deps|infra|typo|comment|example|mock|hotfix|cleanup|optimize)(\(.+\))?: .+'; then
            log "WARNING" "Commit ${commit:0:7} may not follow conventional commit format"
            log "INFO" "Message: ${message%%$'\n'*}"
            ((invalid_commits++))
        fi
    done < <(git rev-list "${range}")

    if [[ "${invalid_commits}" -gt 0 ]]; then
        log "WARNING" "${invalid_commits} commit(s) may not follow conventional commit format"
        log "INFO" "This is non-blocking, but consider following conventional commits"
    else
        log "SUCCESS" "All commits follow conventional commit format"
    fi

    return 0
}

# Main function
main() {
    log "INFO" "Starting pre-push hook..."
    log "INFO" "Log file: ${LOG_FILE}"

    # Check for skip flag
    if [[ "${SKIP_HOOKS}" == "true" ]]; then
        log "WARNING" "Hooks skipped via SKIP_HOOKS environment variable"
        log "WARNING" "Use with caution!"
        exit 0
    fi

    # Read stdin for remote and branch info
    local remote_name remote_url local_ref local_sha remote_ref remote_sha
    while read -r local_ref local_sha remote_ref remote_sha; do
        log "INFO" "Push details:"
        log "INFO" "  Local ref: ${local_ref}"
        log "INFO" "  Remote ref: ${remote_ref}"

        # Check branch protection
        check_branch_protection "${remote_name:-origin}" "${local_ref}"

        # Validate commit messages
        validate_commits "${remote_name:-origin}" "${remote_ref}"
    done

    # Check for uncommitted changes
    check_uncommitted_changes

    local exit_code=0

    # Run tests
    if [[ "${SKIP_TESTS}" != "true" ]]; then
        if ! run_tests; then
            exit_code=1
        fi
    else
        log "WARNING" "Tests skipped"
    fi

    # Check coverage
    if [[ "${SKIP_COVERAGE}" != "true" ]]; then
        if ! check_coverage; then
            exit_code=1
        fi
    else
        log "WARNING" "Coverage check skipped"
    fi

    # Run security checks
    if [[ "${SKIP_SECURITY}" != "true" ]]; then
        if ! run_security_checks; then
            exit_code=1
        fi
    else
        log "WARNING" "Security checks skipped"
    fi

    # Summary
    echo ""
    if [[ "${exit_code}" -eq 0 ]]; then
        log "SUCCESS" "All pre-push checks passed! 🚀"
        log "INFO" "Proceeding with push..."
    else
        log "ERROR" "Pre-push checks failed! ❌"
        log "INFO" "Fix the issues above or skip with: SKIP_HOOKS=true git push"
        echo ""
    fi

    exit "${exit_code}"
}

# Run main function
main "$@"
