#!/bin/bash
#
# post-checkout.sh - Git post-checkout hook for Python projects

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../utils/common.sh"

# Configuration
SKIP_HOOKS="${SKIP_HOOKS:-false}"
AUTO_INSTALL="${AUTO_INSTALL:-true}"

# Check if dependency files changed
deps_changed() {
    local prev="$1"
    local new="$2"

    git diff --name-only "$prev" "$new" 2>/dev/null | \
        grep -qE '^(pyproject\.toml|requirements\.txt|Pipfile|poetry\.lock)$'
}

# Sync dependencies
sync_deps() {
    local project_root
    project_root=$(find_project_root)
    cd "$project_root" || return 1

    # Try Poetry first
    if [[ -f "pyproject.toml" ]] && cmd_exists poetry; then
        info "Syncing Poetry dependencies"
        poetry install --sync || return 1
    # Then Pipenv
    elif [[ -f "Pipfile" ]] && cmd_exists pipenv; then
        info "Syncing Pipenv dependencies"
        pipenv install --dev || return 1
    # Finally pip
    elif [[ -f "requirements.txt" ]]; then
        info "Syncing pip dependencies"
        $(detect_python) -m pip install -r requirements.txt || return 1
        [[ -f "requirements-dev.txt" ]] && $(detect_python) -m pip install -r requirements-dev.txt
    else
        warn "No dependency files found"
        return 0
    fi

    info "Dependencies synced"
}

# Clean Python cache
clean_cache() {
    local project_root
    project_root=$(find_project_root)
    find "$project_root" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$project_root" -type f -name "*.pyc" -delete 2>/dev/null || true
}

# Main
main() {
    local prev_head="${1:-}"
    local new_head="${2:-}"
    local branch_flag="${3:-1}"

    [[ "$SKIP_HOOKS" == "true" ]] && exit 0
    [[ "$branch_flag" != "1" ]] && exit 0

    # Check if dependencies changed
    if [[ -n "$prev_head" ]] && [[ -n "$new_head" ]]; then
        if deps_changed "$prev_head" "$new_head"; then
            info "Dependencies changed"

            if [[ "$AUTO_INSTALL" == "true" ]]; then
                sync_deps || warn "Failed to sync dependencies"
            else
                info "Auto-install disabled"
            fi
        fi
    fi

    # Clean cache
    clean_cache
    info "Post-checkout complete"
}

main "$@"
