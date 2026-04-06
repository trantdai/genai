# Development Lifecycle Hooks

Hook system for automating quality checks, security scans, and development workflows.

## Overview

**Integrated with:**
- Git hooks: Pre-commit, pre-push, post-checkout, post-merge, commit-msg
- Claude Code hooks: Pre-tool-use, post-tool-use, session hooks
- Pre-commit framework: Comprehensive linting and formatting

## Installation

See [INSTALLATION.md](INSTALLATION.md) for detailed setup.

```bash
pip install pre-commit
pre-commit install
pre-commit install --hook-type commit-msg
```

## Git Hooks (`git/` directory)

| Hook | Purpose |
|------|---------|
| `pre-commit.sh` | Format (Black), lint (Ruff), secret scan, type check |
| `pre-push.sh` | Full tests, coverage ≥80%, security scan |
| `post-checkout.sh` | Auto-sync dependencies, clean cache |
| `post-merge.sh` | Auto-install dependencies |
| `commit-msg.sh` | Validate conventional commit format |

## Claude Code Hooks (`claude/` directory)

| Hook | Purpose |
|------|---------|
| `pre-tool-use.json` | Validate Python, scan secrets, warn destructive ops |
| `post-tool-use.json` | Auto-format (Black), lint fixes (Ruff) |
| `session-hooks.json` | Environment checks (start), cleanup (end) |

## Utility Scripts (`utils/` directory)

| Script | Purpose |
|--------|---------|
| `check-coverage.sh` | Verify coverage ≥80% |
| `scan-secrets.sh` | Secret scanning |
| `run-security-checks.sh` | Run all security tools |
| `format-code.sh` | Format Python files |
| `validate-dependencies.sh` | Check vulnerabilities |

## Environment Variables

```bash
# Skip hooks
export SKIP_HOOKS=true           # All hooks
export SKIP_FORMAT=true          # Formatting
export SKIP_LINT=true            # Linting
export SKIP_SECRETS=true         # Secret scanning
export SKIP_TESTS=true           # Tests
export SKIP_COVERAGE=true        # Coverage
export SKIP_SECURITY=true        # Security scan

# Configuration
export AUTO_INSTALL=true         # Auto-install dependencies
export MIN_COVERAGE=80           # Coverage threshold
export PYTHON_CMD=python3        # Python command
```

## Commit Message Format

```
<type>(<scope>): <description>

[optional body]
```

**Valid types**: feat, fix, docs, style, refactor, test, chore, security, perf

**Examples**:
- `feat(auth): add OAuth2 integration`
- `fix(api): handle null values`
- `security(auth): implement rate limiting`

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

```bash
# Check hooks installed
ls -la .git/hooks/

# Make executable
chmod +x hooks/git/*.sh hooks/utils/*.sh

# Install tools
pip install black ruff mypy pytest pytest-cov bandit safety pip-audit
```

## References

- [INSTALLATION.md](INSTALLATION.md)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Pre-commit Framework](https://pre-commit.com/)
