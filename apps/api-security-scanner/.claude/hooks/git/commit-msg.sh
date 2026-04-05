#!/bin/bash
#
# Script: commit-msg.sh
# Description: Git commit-msg hook for Python projects
#              Validates commit message format (conventional commits)
# Usage: Automatically executed by git during commit
#

set -euo pipefail

# Constants
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HOOK_NAME="commit-msg"
readonly LOG_FILE="${SCRIPT_DIR}/../.hook-logs/${HOOK_NAME}-$(date +%Y%m%d-%H%M%S).log"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration
SKIP_HOOKS="${SKIP_HOOKS:-false}"
SKIP_COMMIT_MSG="${SKIP_COMMIT_MSG:-false}"
STRICT_MODE="${STRICT_MODE:-false}"

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

# Valid commit types
readonly VALID_TYPES=(
    "feat"      # ✨ New feature
    "fix"       # 🐛 Bug fix
    "docs"      # 📚 Documentation
    "style"     # 💄 Code style
    "refactor"  # ♻️ Refactoring
    "test"      # 🧪 Tests
    "chore"     # 🔧 Chores
    "perf"      # ⚡ Performance
    "ci"        # 👷 CI/CD
    "build"     # 📦 Build
    "revert"    # ⏪ Revert
    "wip"       # 🚧 Work in progress
    "security"  # 🔒 Security
    "config"    # ⚙️ Configuration
    "deps"      # ⬆️ Dependencies
    "infra"     # 🏗️ Infrastructure
    "typo"      # ✏️ Typos
    "comment"   # 💬 Comments
    "example"   # 📝 Examples
    "mock"      # 🎭 Mocks
    "hotfix"    # 🚑 Hotfix
    "cleanup"   # 🧹 Cleanup
    "optimize"  # 🚀 Optimization
)

# Show usage
show_usage() {
    cat <<EOF

${BLUE}Conventional Commit Format:${NC}
  <type>(<scope>): <icon> <description>

  [optional body]

  [optional footer]

${BLUE}Valid Types:${NC}
  feat      ✨ New feature for the user
  fix       🐛 Bug fix for the user
  docs      📚 Documentation changes
  style     💄 Code style changes (formatting, etc)
  refactor  ♻️ Code refactoring
  test      🧪 Adding or updating tests
  chore     🔧 Build process or auxiliary tool changes
  perf      ⚡ Performance improvements
  ci        👷 CI/CD changes
  build     📦 Build system changes
  revert    ⏪ Revert a previous commit
  security  🔒 Security improvements
  deps      ⬆️ Dependency updates

${BLUE}Examples:${NC}
  feat(auth): ✨ add OAuth2 integration
  fix(api): 🐛 handle null values in user endpoint
  docs(readme): 📚 update installation instructions
  security(auth): 🔒 implement rate limiting

${BLUE}More Info:${NC}
  https://www.conventionalcommits.org/

EOF
}

# Validate commit message format
validate_format() {
    local message="$1"

    # Get first line (subject)
    local subject
    subject=$(echo "${message}" | head -n 1)

    log "INFO" "Validating commit message: ${subject}"

    # Check if message is empty
    if [[ -z "${subject}" ]]; then
        log "ERROR" "Commit message is empty"
        return 1
    fi

    # Check subject length (recommended max 72 characters)
    local subject_length=${#subject}
    if [[ "${subject_length}" -gt 72 ]]; then
        log "WARNING" "Subject line is ${subject_length} characters (recommended max: 72)"
        if [[ "${STRICT_MODE}" == "true" ]]; then
            return 1
        fi
    fi

    # Extract type and scope
    local type scope description

    # Pattern: type(scope): description or type: description
    if [[ "${subject}" =~ ^([a-z]+)(\([a-z0-9-]+\))?:\ .+ ]]; then
        type="${BASH_REMATCH[1]}"
        scope="${BASH_REMATCH[2]}"
        description="${subject#*: }"
    else
        log "ERROR" "Commit message does not follow conventional commit format"
        log "INFO" "Expected format: <type>(<scope>): <description>"
        show_usage
        return 1
    fi

    # Validate type
    local valid_type=false
    for valid in "${VALID_TYPES[@]}"; do
        if [[ "${type}" == "${valid}" ]]; then
            valid_type=true
            break
        fi
    done

    if [[ "${valid_type}" == "false" ]]; then
        log "ERROR" "Invalid commit type: ${type}"
        log "INFO" "Valid types: ${VALID_TYPES[*]}"
        show_usage
        return 1
    fi

    # Check description
    if [[ -z "${description}" ]]; then
        log "ERROR" "Commit description is empty"
        return 1
    fi

    # Check if description starts with lowercase (recommended)
    if [[ "${description}" =~ ^[A-Z] ]]; then
        log "WARNING" "Description should start with lowercase"
        if [[ "${STRICT_MODE}" == "true" ]]; then
            return 1
        fi
    fi

    # Check if description ends with period (should not)
    if [[ "${description}" =~ \.$ ]]; then
        log "WARNING" "Description should not end with a period"
        if [[ "${STRICT_MODE}" == "true" ]]; then
            return 1
        fi
    fi

    # Check for WIP commits
    if [[ "${type}" == "wip" ]]; then
        log "WARNING" "WIP commits should not be pushed to main branches"
    fi

    log "SUCCESS" "Commit message format is valid"
    return 0
}

# Check for common issues
check_common_issues() {
    local message="$1"

    # Check for merge commit messages (allow them)
    if [[ "${message}" =~ ^Merge\ (branch|pull\ request) ]]; then
        log "INFO" "Merge commit detected, skipping validation"
        return 0
    fi

    # Check for revert commit messages (allow them)
    if [[ "${message}" =~ ^Revert\ \" ]]; then
        log "INFO" "Revert commit detected, skipping validation"
        return 0
    fi

    # Check for fixup/squash commits (allow them)
    if [[ "${message}" =~ ^(fixup|squash)! ]]; then
        log "INFO" "Fixup/squash commit detected, skipping validation"
        return 0
    fi

    return 1
}

# Main function
main() {
    local commit_msg_file="${1:-}"

    log "INFO" "Starting commit-msg hook..."
    log "INFO" "Log file: ${LOG_FILE}"

    # Check for skip flag
    if [[ "${SKIP_HOOKS}" == "true" ]] || [[ "${SKIP_COMMIT_MSG}" == "true" ]]; then
        log "WARNING" "Commit message validation skipped"
        exit 0
    fi

    # Check if commit message file exists
    if [[ ! -f "${commit_msg_file}" ]]; then
        log "ERROR" "Commit message file not found: ${commit_msg_file}"
        exit 1
    fi

    # Read commit message
    local message
    message=$(cat "${commit_msg_file}")

    # Check for common special cases
    if check_common_issues "${message}"; then
        exit 0
    fi

    # Validate commit message
    if validate_format "${message}"; then
        log "SUCCESS" "Commit message validation passed! ✓"
        exit 0
    else
        log "ERROR" "Commit message validation failed! ❌"
        log "INFO" "Fix your commit message or skip with: SKIP_COMMIT_MSG=true git commit"
        echo ""
        exit 1
    fi
}

# Run main function
main "$@"
