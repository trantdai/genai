# Shell Scripting Standards

## General Principles
- Use bash for shell scripts (#!/bin/bash)
- Follow patterns documented in `docs/` directory
- Make scripts portable and maintainable
- Use shellcheck for linting
- Add proper error handling

## Script Structure
- Start with shebang: `#!/bin/bash`
- Add script description and usage in comments
- Set strict error handling: `set -euo pipefail`
- Define functions before use
- Use main() function for script entry point
- Exit with appropriate status codes

## Security Best Practices
- **Input Validation**: Validate all user inputs and arguments
- **Command Injection Prevention**: Quote all variables properly
- **Path Traversal Prevention**: Validate file paths
- **Privilege Management**: Run with least privilege, use sudo only when necessary
- **Secrets Management**: Never hardcode secrets, use environment variables or secret managers
- **Temporary Files**: Use mktemp for temporary files, clean up on exit
- **Error Handling**: Check return codes, use trap for cleanup

## Code Style
- Use meaningful variable names (lowercase with underscores)
- Use UPPERCASE for environment variables and constants
- Quote all variables: `"${variable}"` not `$variable`
- Use `[[` instead of `[` for conditionals
- Use `$(command)` instead of backticks
- Indent with 2 or 4 spaces consistently
- Use functions for reusable code
- Add comments for complex logic

## Error Handling
```bash
set -euo pipefail  # Exit on error, undefined variable, pipe failure

# Trap errors and cleanup
trap cleanup EXIT ERR

cleanup() {
    # Cleanup code here
    rm -f "${temp_file}"
}
```

## Input Validation
```bash
# Validate required arguments
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <argument>" >&2
    exit 1
fi

# Validate file exists
if [[ ! -f "${file}" ]]; then
    echo "Error: File not found: ${file}" >&2
    exit 1
fi
```

## Logging
- Use descriptive error messages
- Log to stderr for errors: `echo "Error: message" >&2`
- Log to stdout for normal output
- Use consistent log format
- Include timestamps for important events

## Best Practices
- Use readonly for constants
- Use local for function variables
- Check command existence before use: `command -v cmd`
- Use arrays for lists of items
- Use parameter expansion for string manipulation
- Avoid parsing ls output
- Use find with -exec or while read loop
- Use process substitution when appropriate

## Testing
- Test scripts with different inputs
- Test error conditions
- Use shellcheck for static analysis
- Test on target platforms
- Document test cases

## Documentation
- Add usage information at the top
- Document function parameters and return values
- Add examples of usage
- Document dependencies and requirements
- Keep documentation up-to-date

## Example Template
```bash
#!/bin/bash
#
# Script: script_name.sh
# Description: Brief description of what the script does
# Usage: script_name.sh [options] <arguments>
#

set -euo pipefail

# Constants
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

# Cleanup function
cleanup() {
    # Add cleanup code here
    :
}

trap cleanup EXIT ERR

# Usage information
usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [options] <argument>

Description of the script

Options:
    -h, --help      Show this help message
    -v, --verbose   Enable verbose output

Examples:
    ${SCRIPT_NAME} example_arg
EOF
}

# Main function
main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                set -x
                shift
                ;;
            *)
                break
                ;;
        esac
    done

    # Validate arguments
    if [[ $# -lt 1 ]]; then
        echo "Error: Missing required argument" >&2
        usage
        exit 1
    fi

    # Script logic here
    echo "Processing: $1"
}

# Run main function
main "$@"
```
