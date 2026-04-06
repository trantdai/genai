# Development Lifecycle Hooks

Hook system for automating quality checks, security scans, and development workflows.

## Overview

Automated checks integrated with:
- **Git hooks**: Pre-commit, pre-push, post-checkout, post-merge, commit-msg
- **Claude Code hooks**: Pre-tool-use, post-tool-use, session hooks
- **Pre-commit framework**: Comprehensive linting and formatting

## Installation

See [INSTALLATION.md](INSTALLATION.md) for detailed setup instructions.

```bash
# Quick start
pip install pre-commit
pre-commit install
pre-commit install --hook-type commit-msg
```

## Git Hooks

Located in `git/` directory:

| Hook | Purpose |
|------|---------|
| `pre-commit.sh` | Format (Black), lint (Ruff), secret scan, type check |
| `pre-push.sh` | Full tests, coverage check (80%), security scan |
| `post-checkout.sh` | Auto-sync dependencies, clean cache |
| `post-merge.sh` | Auto-install dependencies, run migrations (if enabled) |
| `commit-msg.sh` | Validate conventional commit format |

## Claude Code Hooks

Located in `claude/` directory:

| Hook | Purpose |
|------|---------|
| `pre-tool-use.json` | Validate Python syntax, scan secrets, warn destructive ops |
| `post-tool-use.json` | Auto-format (Black), lint fixes (Ruff), run tests (optional) |
| `session-hooks.json` | Environment checks (start), cleanup (end) |

## Utility Scripts

Located in `utils/` directory:

| Script | Purpose |
|--------|---------|
| `check-coverage.sh` | Verify test coverage ≥80% |
| `scan-secrets.sh` | Comprehensive secret scanning |
| `run-security-checks.sh` | Run all security tools |
| `format-code.sh` | Format all Python files |
| `validate-dependencies.sh` | Check for vulnerabilities |

## Environment Variables

```bash
# Skip hooks
export SKIP_HOOKS=true           # All hooks
export SKIP_FORMAT=true          # Formatting only
export SKIP_LINT=true            # Linting only
export SKIP_SECRETS=true         # Secret scanning
export SKIP_TESTS=true           # Tests
export SKIP_COVERAGE=true        # Coverage check
export SKIP_SECURITY=true        # Security scan

# Configuration
export AUTO_INSTALL=true         # Auto-install dependencies
export AUTO_MIGRATE=false        # Auto-run migrations
export MIN_COVERAGE=80           # Coverage threshold
export PYTHON_CMD=python3        # Python command
```

## Usage Examples

```bash
# Normal commit (hooks run automatically)
git commit -m "feat(api): add new endpoint"

# Skip hooks temporarily
SKIP_HOOKS=true git commit -m "hotfix: critical fix"

# Skip specific check
SKIP_FORMAT=true git commit -m "wip: work in progress"

# Run pre-commit on all files
pre-commit run --all-files

# Run specific hook
pre-commit run black --all-files
```

## Commit Message Format

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Valid types**: feat, fix, docs, style, refactor, test, chore, security, perf

**Examples**:
- `feat(auth): add OAuth2 integration`
- `fix(api): handle null values`
- `docs(readme): update installation`
- `security(auth): implement rate limiting`

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues and solutions.

**Quick fixes**:
```bash
# Check if hooks installed
ls -la .git/hooks/

# Make scripts executable
chmod +x hooks/git/*.sh hooks/utils/*.sh

# Install required tools
pip install black ruff mypy pytest pytest-cov bandit safety pip-audit
```

## Logging

All hook executions logged to `.hook-logs/` directory.

```bash
# View recent logs
ls -lt .hook-logs/

# Clean old logs (>7 days)
find .hook-logs -name "*.log" -mtime +7 -delete
```

## References

- [INSTALLATION.md](INSTALLATION.md) - Setup guide
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Issue resolution
- [Conventional Commits](https://www.conventionalcommits.org/) - Commit format
- [Pre-commit Framework](https://pre-commit.com/) - Documentation
