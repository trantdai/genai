#!/bin/bash
#
# common.sh - Shared utilities for git hooks
# Usage: source "$(dirname "${BASH_SOURCE[0]}")/../utils/common.sh"

set -euo pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Logging functions
error() {
    echo -e "${RED}✗ $*${NC}" >&2
}

warn() {
    echo -e "${YELLOW}⚠ $*${NC}"
}

info() {
    echo -e "${GREEN}✓ $*${NC}"
}

# Check if command exists
cmd_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Find project root (looks for pyproject.toml, setup.py, or requirements.txt)
find_project_root() {
    local current_dir="$(pwd)"
    while [[ "${current_dir}" != "/" ]]; do
        if [[ -f "${current_dir}/pyproject.toml" ]] || \
           [[ -f "${current_dir}/setup.py" ]] || \
           [[ -f "${current_dir}/requirements.txt" ]]; then
            echo "${current_dir}"
            return 0
        fi
        current_dir="$(dirname "${current_dir}")"
    done
    echo "$(pwd)"
}

# Detect Python command (python3, python, or error)
detect_python() {
    if cmd_exists python3; then
        echo "python3"
    elif cmd_exists python; then
        echo "python"
    else
        error "Python not found"
        return 1
    fi
}

# Exit with error message
die() {
    error "$@"
    exit 1
}

# Get staged Python files
get_staged_python_files() {
    git diff --cached --name-only --diff-filter=ACM | grep -E '\.py$' || true
}
