#!/bin/bash
#
# post-merge.sh - Git post-merge hook for Python projects

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../utils/common.sh"

# Configuration
SKIP_HOOKS="${SKIP_HOOKS:-false}"
AUTO_INSTALL="${AUTO_INSTALL:-true}"
AUTO_MIGRATE="${AUTO_MIGRATE:-false}"

# Check if dependency files changed
deps_changed() {
    git diff-tree -r --name-only --no-commit-id ORIG_HEAD HEAD 2>/dev/null | \
        grep -qE '^(pyproject\.toml|requirements\.txt|Pipfile|poetry\.lock)$'
}

# Check if migration files changed
migrations_changed() {
    git diff-tree -r --name-only --no-commit-id ORIG_HEAD HEAD 2>/dev/null | \
        grep -qE '^(migrations/|alembic/versions/|db/migrations/)' 2>/dev/null
}

# Install dependencies
install_deps() {
    local project_root
    project_root=$(find_project_root)
    cd "$project_root" || return 1

    # Try Poetry first
    if [[ -f "pyproject.toml" ]] && cmd_exists poetry; then
        info "Installing Poetry dependencies"
        poetry install || return 1
    # Then Pipenv
    elif [[ -f "Pipfile" ]] && cmd_exists pipenv; then
        info "Installing Pipenv dependencies"
        pipenv install --dev || return 1
    # Finally pip
    elif [[ -f "requirements.txt" ]]; then
        info "Installing pip dependencies"
        $(detect_python) -m pip install -r requirements.txt || return 1
        [[ -f "requirements-dev.txt" ]] && $(detect_python) -m pip install -r requirements-dev.txt
    else
        return 0
    fi

    info "Dependencies installed"
}

# Run migrations
run_migrations() {
    local project_root
    project_root=$(find_project_root)
    cd "$project_root" || return 1

    # Check for Alembic
    if [[ -f "alembic.ini" ]] && cmd_exists alembic; then
        info "Running Alembic migrations"
        alembic upgrade head || return 1
    # Check for Django
    elif [[ -f "manage.py" ]]; then
        info "Running Django migrations"
        $(detect_python) manage.py migrate || return 1
    else
        return 0
    fi

    info "Migrations complete"
}

# Main
main() {
    [[ "$SKIP_HOOKS" == "true" ]] && exit 0

    # Handle dependency changes
    if deps_changed; then
        info "Dependencies changed"

        if [[ "$AUTO_INSTALL" == "true" ]]; then
            install_deps || warn "Failed to install dependencies"
        else
            info "Auto-install disabled"
        fi
    fi

    # Handle migration changes
    if migrations_changed; then
        info "Migrations changed"

        if [[ "$AUTO_MIGRATE" == "true" ]]; then
            run_migrations || warn "Failed to run migrations"
        else
            info "Auto-migrate disabled"
        fi
    fi

    info "Post-merge complete"
}

main "$@"
