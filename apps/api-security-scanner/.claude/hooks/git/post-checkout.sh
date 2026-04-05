#!/bin/bash
#
# Script: post-checkout.sh
# Description: Git post-checkout hook for Python projects
#              Syncs dependencies after branch checkout
# Usage: Automatically executed by git after checkout
#

set -euo pipefail

# Constants
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HOOK_NAME="post-checkout"
readonly LOG_FILE="${SCRIPT_DIR}/../.hook-logs/${HOOK_NAME}-$(date +%Y%m%d-%H%M%S).log"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration
SKIP_HOOKS="${SKIP_HOOKS:-false}"
AUTO_INSTALL="${AUTO_INSTALL:-true}"
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

# Check if dependencies changed
dependencies_changed() {
    local prev_ref="$1"
    local new_ref="$2"

    # Check if dependency files changed
    local dep_files=(
        "pyproject.toml"
        "requirements.txt"
        "requirements-dev.txt"
        "setup.py"
        "setup.cfg"
        "Pipfile"
        "poetry.lock"
    )

    for file in "${dep_files[@]}"; do
        if git diff --name-only "${prev_ref}" "${new_ref}" 2>/dev/null | grep -q "^${file}$"; then
            return 0
        fi
    done

    return 1
}

# Sync dependencies
sync_dependencies() {
    local project_root
    project_root=$(find_project_root)

    log "INFO" "Syncing dependencies in: ${project_root}"

    cd "${project_root}"

    # Check for different dependency management tools
    if [[ -f "pyproject.toml" ]] && command_exists poetry; then
        log "INFO" "Detected Poetry project"
        if poetry install --sync; then
            log "SUCCESS" "Poetry dependencies synced"
            return 0
        else
            log "ERROR" "Failed to sync Poetry dependencies"
            return 1
        fi
    elif [[ -f "Pipfile" ]] && command_exists pipenv; then
        log "INFO" "Detected Pipenv project"
        if pipenv install --dev; then
            log "SUCCESS" "Pipenv dependencies synced"
            return 0
        else
            log "ERROR" "Failed to sync Pipenv dependencies"
            return 1
        fi
    elif [[ -f "requirements.txt" ]]; then
        log "INFO" "Detected requirements.txt"
        if "${PYTHON_CMD}" -m pip install -r requirements.txt; then
            log "SUCCESS" "pip dependencies synced"

            # Also install dev requirements if present
            if [[ -f "requirements-dev.txt" ]]; then
                "${PYTHON_CMD}" -m pip install -r requirements-dev.txt
                log "SUCCESS" "Dev dependencies synced"
            fi
            return 0
        else
            log "ERROR" "Failed to sync pip dependencies"
            return 1
        fi
    else
        log "INFO" "No dependency files found"
        return 0
    fi
}

# Validate dependencies
validate_dependencies() {
    log "INFO" "Validating dependencies..."

    if [[ -f "${SCRIPT_DIR}/../utils/validate-dependencies.sh" ]]; then
        if bash "${SCRIPT_DIR}/../utils/validate-dependencies.sh"; then
            log "SUCCESS" "Dependencies validated"
            return 0
        else
            log "WARNING" "Dependency validation found issues"
            return 0  # Non-blocking
        fi
    else
        log "INFO" "Dependency validator not found, skipping"
        return 0
    fi
}

# Clean Python cache
clean_cache() {
    log "INFO" "Cleaning Python cache files..."

    local project_root
    project_root=$(find_project_root)

    cd "${project_root}"

    # Remove __pycache__ directories
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

    # Remove .pyc files
    find . -type f -name "*.pyc" -delete 2>/dev/null || true

    # Remove .pyo files
    find . -type f -name "*.pyo" -delete 2>/dev/null || true

    log "SUCCESS" "Cache cleaned"
}

# Show branch info
show_branch_info() {
    local branch_name
    branch_name=$(git rev-parse --abbrev-ref HEAD)

    log "INFO" "Checked out branch: ${branch_name}"

    # Show last commit
    local last_commit
    last_commit=$(git log -1 --pretty=format:"%h - %s (%an, %ar)")
    log "INFO" "Last commit: ${last_commit}"

    # Check if branch is behind remote
    if git rev-parse "@{u}" >/dev/null 2>&1; then
        local behind
        behind=$(git rev-list --count HEAD..@{u})
        if [[ "${behind}" -gt 0 ]]; then
            log "WARNING" "Branch is ${behind} commit(s) behind remote"
            log "INFO" "Consider running: git pull"
        fi
    fi
}

# Main function
main() {
    # Arguments from git: prev_head new_head branch_flag
    local prev_head="${1:-}"
    local new_head="${2:-}"
    local branch_flag="${3:-1}"

    log "INFO" "Starting post-checkout hook..."
    log "INFO" "Log file: ${LOG_FILE}"

    # Check for skip flag
    if [[ "${SKIP_HOOKS}" == "true" ]]; then
        log "INFO" "Hooks skipped via SKIP_HOOKS environment variable"
        exit 0
    fi

    # Only run on branch checkout (not file checkout)
    if [[ "${branch_flag}" != "1" ]]; then
        log "INFO" "File checkout detected, skipping hook"
        exit 0
    fi

    # Show branch info
    show_branch_info

    # Check if dependencies changed
    if [[ -n "${prev_head}" ]] && [[ -n "${new_head}" ]]; then
        if dependencies_changed "${prev_head}" "${new_head}"; then
            log "INFO" "Dependencies changed between branches"

            if [[ "${AUTO_INSTALL}" == "true" ]]; then
                if sync_dependencies; then
                    validate_dependencies
                else
                    log "WARNING" "Failed to sync dependencies automatically"
                    log "INFO" "You may need to manually install dependencies"
                fi
            else
                log "INFO" "Auto-install disabled. Run dependency sync manually."
            fi
        else
            log "INFO" "No dependency changes detected"
        fi
    fi

    # Clean cache
    clean_cache

    log "SUCCESS" "Post-checkout hook completed! ✓"

    exit 0
}

# Run main function
main "$@"
