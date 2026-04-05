#!/bin/bash
#
# Script: post-merge.sh
# Description: Git post-merge hook for Python projects
#              Installs dependencies and runs migrations after merge
# Usage: Automatically executed by git after merge
#

set -euo pipefail

# Constants
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HOOK_NAME="post-merge"
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
AUTO_MIGRATE="${AUTO_MIGRATE:-false}"
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
    # Check if dependency files changed in the merge
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
        if git diff-tree -r --name-only --no-commit-id ORIG_HEAD HEAD 2>/dev/null | grep -q "^${file}$"; then
            return 0
        fi
    done

    return 1
}

# Check if migration files changed
migrations_changed() {
    # Check for common migration directories
    local migration_dirs=(
        "migrations"
        "alembic/versions"
        "db/migrations"
    )

    for dir in "${migration_dirs[@]}"; do
        if git diff-tree -r --name-only --no-commit-id ORIG_HEAD HEAD 2>/dev/null | grep -q "^${dir}/"; then
            return 0
        fi
    done

    return 1
}

# Install dependencies
install_dependencies() {
    local project_root
    project_root=$(find_project_root)

    log "INFO" "Installing dependencies in: ${project_root}"

    cd "${project_root}"

    # Check for different dependency management tools
    if [[ -f "pyproject.toml" ]] && command_exists poetry; then
        log "INFO" "Detected Poetry project"
        if poetry install; then
            log "SUCCESS" "Poetry dependencies installed"
            return 0
        else
            log "ERROR" "Failed to install Poetry dependencies"
            return 1
        fi
    elif [[ -f "Pipfile" ]] && command_exists pipenv; then
        log "INFO" "Detected Pipenv project"
        if pipenv install --dev; then
            log "SUCCESS" "Pipenv dependencies installed"
            return 0
        else
            log "ERROR" "Failed to install Pipenv dependencies"
            return 1
        fi
    elif [[ -f "requirements.txt" ]]; then
        log "INFO" "Detected requirements.txt"
        if "${PYTHON_CMD}" -m pip install -r requirements.txt; then
            log "SUCCESS" "pip dependencies installed"

            # Also install dev requirements if present
            if [[ -f "requirements-dev.txt" ]]; then
                "${PYTHON_CMD}" -m pip install -r requirements-dev.txt
                log "SUCCESS" "Dev dependencies installed"
            fi
            return 0
        else
            log "ERROR" "Failed to install pip dependencies"
            return 1
        fi
    else
        log "INFO" "No dependency files found"
        return 0
    fi
}

# Run database migrations
run_migrations() {
    local project_root
    project_root=$(find_project_root)

    log "INFO" "Running database migrations..."

    cd "${project_root}"

    # Check for Alembic
    if [[ -f "alembic.ini" ]] && command_exists alembic; then
        log "INFO" "Detected Alembic migrations"
        if alembic upgrade head; then
            log "SUCCESS" "Alembic migrations completed"
            return 0
        else
            log "ERROR" "Alembic migrations failed"
            return 1
        fi
    # Check for Django
    elif [[ -f "manage.py" ]] && grep -q "django" requirements*.txt 2>/dev/null; then
        log "INFO" "Detected Django project"
        if "${PYTHON_CMD}" manage.py migrate; then
            log "SUCCESS" "Django migrations completed"
            return 0
        else
            log "ERROR" "Django migrations failed"
            return 1
        fi
    else
        log "INFO" "No migration system detected"
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

# Show merge info
show_merge_info() {
    log "INFO" "Merge completed"

    # Show what was merged
    local merge_commit
    merge_commit=$(git log -1 --pretty=format:"%h - %s (%an, %ar)")
    log "INFO" "Latest commit: ${merge_commit}"

    # Show files changed
    local files_changed
    files_changed=$(git diff-tree -r --name-only --no-commit-id ORIG_HEAD HEAD 2>/dev/null | wc -l | tr -d ' ')
    log "INFO" "Files changed: ${files_changed}"
}

# Main function
main() {
    # Arguments from git: squash_merge_flag
    local squash_merge="${1:-0}"

    log "INFO" "Starting post-merge hook..."
    log "INFO" "Log file: ${LOG_FILE}"

    # Check for skip flag
    if [[ "${SKIP_HOOKS}" == "true" ]]; then
        log "INFO" "Hooks skipped via SKIP_HOOKS environment variable"
        exit 0
    fi

    # Show merge info
    show_merge_info

    local exit_code=0

    # Check if dependencies changed
    if dependencies_changed; then
        log "INFO" "Dependencies changed in merge"

        if [[ "${AUTO_INSTALL}" == "true" ]]; then
            if ! install_dependencies; then
                log "WARNING" "Failed to install dependencies automatically"
                log "INFO" "You may need to manually install dependencies"
                exit_code=1
            fi
        else
            log "INFO" "Auto-install disabled. Run dependency installation manually."
        fi
    else
        log "INFO" "No dependency changes detected"
    fi

    # Check if migrations changed
    if migrations_changed; then
        log "INFO" "Migration files changed in merge"

        if [[ "${AUTO_MIGRATE}" == "true" ]]; then
            if ! run_migrations; then
                log "WARNING" "Failed to run migrations automatically"
                log "INFO" "You may need to manually run migrations"
                exit_code=1
            fi
        else
            log "INFO" "Auto-migrate disabled. Run migrations manually if needed."
        fi
    else
        log "INFO" "No migration changes detected"
    fi

    # Clean cache
    clean_cache

    # Summary
    echo ""
    if [[ "${exit_code}" -eq 0 ]]; then
        log "SUCCESS" "Post-merge hook completed! ✓"
    else
        log "WARNING" "Post-merge hook completed with warnings ⚠"
        log "INFO" "Check the log file for details: ${LOG_FILE}"
    fi

    exit 0  # Always exit 0 to not block the merge
}

# Run main function
main "$@"
