#!/bin/bash
#
# Script: verify-hooks.sh
# Description: Verify hook system installation and functionality
# Usage: verify-hooks.sh
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

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"

    case "${level}" in
        ERROR)
            echo -e "${RED}✗ ${message}${NC}" >&2
            ((FAILED++))
            ;;
        SUCCESS)
            echo -e "${GREEN}✓ ${message}${NC}"
            ((PASSED++))
            ;;
        WARNING)
            echo -e "${YELLOW}⚠ ${message}${NC}"
            ((WARNINGS++))
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

# Verify directory structure
verify_structure() {
    echo ""
    log "INFO" "Verifying directory structure..."

    local dirs=(
        "${SCRIPT_DIR}/git"
        "${SCRIPT_DIR}/claude"
        "${SCRIPT_DIR}/utils"
    )

    for dir in "${dirs[@]}"; do
        if [[ -d "${dir}" ]]; then
            log "SUCCESS" "Directory exists: ${dir}"
        else
            log "ERROR" "Directory missing: ${dir}"
        fi
    done
}

# Verify Git hook scripts
verify_git_hooks() {
    echo ""
    log "INFO" "Verifying Git hook scripts..."

    local hooks=(
        "pre-commit.sh"
        "pre-push.sh"
        "post-checkout.sh"
        "post-merge.sh"
        "commit-msg.sh"
    )

    for hook in "${hooks[@]}"; do
        local hook_path="${SCRIPT_DIR}/git/${hook}"
        if [[ -f "${hook_path}" ]]; then
            if [[ -x "${hook_path}" ]]; then
                log "SUCCESS" "Hook exists and is executable: ${hook}"
            else
                log "ERROR" "Hook exists but not executable: ${hook}"
            fi
        else
            log "ERROR" "Hook missing: ${hook}"
        fi
    done
}

# Verify utility scripts
verify_utils() {
    echo ""
    log "INFO" "Verifying utility scripts..."

    local utils=(
        "check-coverage.sh"
        "scan-secrets.sh"
        "run-security-checks.sh"
        "format-code.sh"
        "validate-dependencies.sh"
    )

    for util in "${utils[@]}"; do
        local util_path="${SCRIPT_DIR}/utils/${util}"
        if [[ -f "${util_path}" ]]; then
            if [[ -x "${util_path}" ]]; then
                log "SUCCESS" "Utility exists and is executable: ${util}"
            else
                log "ERROR" "Utility exists but not executable: ${util}"
            fi
        else
            log "ERROR" "Utility missing: ${util}"
        fi
    done
}

# Verify Claude Code hooks
verify_claude_hooks() {
    echo ""
    log "INFO" "Verifying Claude Code hooks..."

    local hooks=(
        "pre-tool-use.json"
        "post-tool-use.json"
        "session-hooks.json"
    )

    for hook in "${hooks[@]}"; do
        local hook_path="${SCRIPT_DIR}/claude/${hook}"
        if [[ -f "${hook_path}" ]]; then
            # Validate JSON
            if python3 -m json.tool "${hook_path}" >/dev/null 2>&1; then
                log "SUCCESS" "Claude hook valid: ${hook}"
            else
                log "ERROR" "Claude hook invalid JSON: ${hook}"
            fi
        else
            log "ERROR" "Claude hook missing: ${hook}"
        fi
    done
}

# Verify pre-commit config
verify_precommit_config() {
    echo ""
    log "INFO" "Verifying pre-commit configuration..."

    local config="${SCRIPT_DIR}/.pre-commit-config.yaml"
    if [[ -f "${config}" ]]; then
        # Validate YAML
        if python3 -c "import yaml; yaml.safe_load(open('${config}'))" 2>/dev/null; then
            log "SUCCESS" "Pre-commit config valid"
        else
            log "ERROR" "Pre-commit config invalid YAML"
        fi
    else
        log "ERROR" "Pre-commit config missing"
    fi
}

# Verify documentation
verify_docs() {
    echo ""
    log "INFO" "Verifying documentation..."

    local docs=(
        "README.md"
        "INSTALLATION.md"
        "TROUBLESHOOTING.md"
    )

    for doc in "${docs[@]}"; do
        local doc_path="${SCRIPT_DIR}/${doc}"
        if [[ -f "${doc_path}" ]]; then
            log "SUCCESS" "Documentation exists: ${doc}"
        else
            log "ERROR" "Documentation missing: ${doc}"
        fi
    done
}

# Check required tools
check_tools() {
    echo ""
    log "INFO" "Checking required tools..."

    local required_tools=(
        "python3"
        "git"
        "pip"
    )

    local optional_tools=(
        "black"
        "ruff"
        "mypy"
        "pytest"
        "bandit"
        "safety"
        "pip-audit"
        "pre-commit"
    )

    for tool in "${required_tools[@]}"; do
        if command_exists "${tool}"; then
            log "SUCCESS" "Required tool installed: ${tool}"
        else
            log "ERROR" "Required tool missing: ${tool}"
        fi
    done

    for tool in "${optional_tools[@]}"; do
        if command_exists "${tool}"; then
            log "SUCCESS" "Optional tool installed: ${tool}"
        else
            log "WARNING" "Optional tool not installed: ${tool}"
        fi
    done
}

# Test hook syntax
test_hook_syntax() {
    echo ""
    log "INFO" "Testing hook script syntax..."

    local hooks=(
        "${SCRIPT_DIR}/git/pre-commit.sh"
        "${SCRIPT_DIR}/git/pre-push.sh"
        "${SCRIPT_DIR}/git/post-checkout.sh"
        "${SCRIPT_DIR}/git/post-merge.sh"
        "${SCRIPT_DIR}/git/commit-msg.sh"
    )

    for hook in "${hooks[@]}"; do
        if [[ -f "${hook}" ]]; then
            if bash -n "${hook}" 2>/dev/null; then
                log "SUCCESS" "Syntax valid: $(basename "${hook}")"
            else
                log "ERROR" "Syntax error: $(basename "${hook}")"
            fi
        fi
    done
}

# Test utility syntax
test_util_syntax() {
    echo ""
    log "INFO" "Testing utility script syntax..."

    local utils=(
        "${SCRIPT_DIR}/utils/check-coverage.sh"
        "${SCRIPT_DIR}/utils/scan-secrets.sh"
        "${SCRIPT_DIR}/utils/run-security-checks.sh"
        "${SCRIPT_DIR}/utils/format-code.sh"
        "${SCRIPT_DIR}/utils/validate-dependencies.sh"
    )

    for util in "${utils[@]}"; do
        if [[ -f "${util}" ]]; then
            if bash -n "${util}" 2>/dev/null; then
                log "SUCCESS" "Syntax valid: $(basename "${util}")"
            else
                log "ERROR" "Syntax error: $(basename "${util}")"
            fi
        fi
    done
}

# Check log directory
check_log_dir() {
    echo ""
    log "INFO" "Checking log directory..."

    local log_dir="${SCRIPT_DIR}/.hook-logs"
    if [[ -d "${log_dir}" ]]; then
        log "SUCCESS" "Log directory exists"
    else
        mkdir -p "${log_dir}"
        log "SUCCESS" "Log directory created"
    fi
}

# Show summary
show_summary() {
    echo ""
    echo "======================================"
    echo "Verification Summary"
    echo "======================================"
    echo -e "${GREEN}Passed:   ${PASSED}${NC}"
    echo -e "${RED}Failed:   ${FAILED}${NC}"
    echo -e "${YELLOW}Warnings: ${WARNINGS}${NC}"
    echo "======================================"
    echo ""

    if [[ "${FAILED}" -eq 0 ]]; then
        log "SUCCESS" "All verifications passed! 🎉"
        echo ""
        log "INFO" "Next steps:"
        echo "  1. Review README.md for usage instructions"
        echo "  2. Install hooks in your project (see INSTALLATION.md)"
        echo "  3. Test hooks with sample commits"
        echo ""
        return 0
    else
        log "ERROR" "Some verifications failed! ❌"
        echo ""
        log "INFO" "Please fix the issues above before using the hooks"
        echo "  - Check TROUBLESHOOTING.md for solutions"
        echo "  - Verify all files are present"
        echo "  - Ensure scripts are executable"
        echo ""
        return 1
    fi
}

# Main function
main() {
    echo "======================================"
    echo "Hook System Verification"
    echo "======================================"
    echo "Location: ${SCRIPT_DIR}"
    echo ""

    # Run all verifications
    verify_structure
    verify_git_hooks
    verify_utils
    verify_claude_hooks
    verify_precommit_config
    verify_docs
    check_tools
    test_hook_syntax
    test_util_syntax
    check_log_dir

    # Show summary
    show_summary
}

# Run main function
main "$@"
