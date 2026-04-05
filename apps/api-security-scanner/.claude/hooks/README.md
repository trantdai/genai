# Development Lifecycle Hooks

Comprehensive hook system for automating quality checks, security scans, and development workflows at various points in the development lifecycle.

## 📋 Table of Contents

- [Overview](#overview)
- [Hook Types](#hook-types)
- [Quick Start](#quick-start)
- [Git Hooks](#git-hooks)
- [Claude Code Hooks](#claude-code-hooks)
- [Pre-commit Framework](#pre-commit-framework)
- [Utility Scripts](#utility-scripts)
- [Configuration](#configuration)
- [Skipping Hooks](#skipping-hooks)
- [Troubleshooting](#troubleshooting)

## 🎯 Overview

This hook system provides automated checks and workflows that integrate with:

- **Git**: Pre-commit, pre-push, post-checkout, post-merge, commit-msg
- **Claude Code**: Pre-tool-use, post-tool-use, session hooks
- **Pre-commit Framework**: Comprehensive linting and formatting

### Key Features

✅ **Automated Quality Checks**: Format, lint, and type-check code automatically
🔒 **Security Scanning**: Detect secrets, vulnerabilities, and security issues
🧪 **Test Automation**: Run tests and check coverage thresholds
📦 **Dependency Management**: Auto-sync and validate dependencies
⚡ **Performance**: Parallel execution where possible
🎛️ **Configurable**: Skip mechanisms and environment variables
📊 **Detailed Logging**: All executions logged for debugging

## 🔧 Hook Types

### Git Hooks

Located in [`git/`](git/) directory:

| Hook | Trigger | Purpose | Speed |
|------|---------|---------|-------|
| [`pre-commit.sh`](git/pre-commit.sh) | Before commit | Format, lint, secret scan | Fast ⚡ |
| [`pre-push.sh`](git/pre-push.sh) | Before push | Full tests, coverage, security | Slow 🐢 |
| [`post-checkout.sh`](git/post-checkout.sh) | After checkout | Dependency sync | Medium ⚙️ |
| [`post-merge.sh`](git/post-merge.sh) | After merge | Install deps, migrations | Medium ⚙️ |
| [`commit-msg.sh`](git/commit-msg.sh) | During commit | Validate commit message | Fast ⚡ |

### Claude Code Hooks

Located in [`claude/`](claude/) directory:

| Hook | Purpose |
|------|---------|
| [`pre-tool-use.json`](claude/pre-tool-use.json) | Validate before Claude executes commands |
| [`post-tool-use.json`](claude/post-tool-use.json) | Auto-format and test after file modifications |
| [`session-hooks.json`](claude/session-hooks.json) | Session start/end automation |

### Utility Scripts

Located in [`utils/`](utils/) directory:

| Script | Purpose |
|--------|---------|
| [`check-coverage.sh`](utils/check-coverage.sh) | Verify test coverage meets 80% threshold |
| [`scan-secrets.sh`](utils/scan-secrets.sh) | Comprehensive secret scanning |
| [`run-security-checks.sh`](utils/run-security-checks.sh) | Run all security tools |
| [`format-code.sh`](utils/format-code.sh) | Format all Python files |
| [`validate-dependencies.sh`](utils/validate-dependencies.sh) | Check for security vulnerabilities |

## 🚀 Quick Start

### 1. Install Hooks

See [INSTALLATION.md](INSTALLATION.md) for detailed instructions.

```bash
# Install Git hooks
cd your-project
bash /path/to/hooks/INSTALLATION.md

# Or manually
ln -s ../../hooks/git/pre-commit.sh .git/hooks/pre-commit
ln -s ../../hooks/git/pre-push.sh .git/hooks/pre-push
# ... etc
```

### 2. Install Pre-commit Framework

```bash
pip install pre-commit
pre-commit install
pre-commit install --hook-type commit-msg
```

### 3. Test Hooks

```bash
# Test pre-commit hook
git add .
git commit -m "test: 🧪 testing hooks"

# Test utility scripts
bash hooks/utils/format-code.sh
bash hooks/utils/scan-secrets.sh
```

## 📝 Git Hooks

### Pre-commit Hook

Runs **before** each commit. Fast checks only.

**What it does:**
- ✅ Format Python files with Black
- ✅ Lint with Ruff
- ✅ Type check with mypy (non-blocking)
- ✅ Scan for secrets
- ✅ Check trailing whitespace
- ✅ Check file sizes

**Usage:**
```bash
# Normal commit (hooks run automatically)
git commit -m "feat(api): ✨ add new endpoint"

# Skip hooks in emergency
SKIP_HOOKS=true git commit -m "hotfix: 🚑 critical fix"

# Skip specific checks
SKIP_FORMAT=true git commit -m "wip: 🚧 work in progress"
SKIP_LINT=true git commit -m "wip: 🚧 work in progress"
SKIP_SECRETS=true git commit -m "test: 🧪 testing"
```

### Pre-push Hook

Runs **before** each push. Comprehensive checks.

**What it does:**
- ✅ Run full test suite
- ✅ Check test coverage (minimum 80%)
- ✅ Run security scans
- ✅ Validate commit messages
- ✅ Check for uncommitted changes

**Usage:**
```bash
# Normal push (hooks run automatically)
git push origin feature-branch

# Skip hooks in emergency
SKIP_HOOKS=true git push origin feature-branch

# Skip specific checks
SKIP_TESTS=true git push origin feature-branch
SKIP_COVERAGE=true git push origin feature-branch
SKIP_SECURITY=true git push origin feature-branch
```

### Post-checkout Hook

Runs **after** branch checkout.

**What it does:**
- ✅ Detect dependency changes
- ✅ Auto-install dependencies (if enabled)
- ✅ Clean Python cache
- ✅ Show branch info

**Configuration:**
```bash
# Enable/disable auto-install
export AUTO_INSTALL=true  # default: true
```

### Post-merge Hook

Runs **after** merge operations.

**What it does:**
- ✅ Detect dependency changes
- ✅ Auto-install dependencies (if enabled)
- ✅ Detect migration changes
- ✅ Run migrations (if enabled)
- ✅ Clean Python cache

**Configuration:**
```bash
# Enable/disable auto-install and migrations
export AUTO_INSTALL=true   # default: true
export AUTO_MIGRATE=false  # default: false (safety)
```

### Commit-msg Hook

Runs **during** commit to validate message format.

**What it does:**
- ✅ Validate conventional commit format
- ✅ Check commit type
- ✅ Check subject length
- ✅ Provide helpful error messages

**Valid Format:**
```
<type>(<scope>): <icon> <description>

[optional body]

[optional footer]
```

**Examples:**
```bash
✅ feat(auth): ✨ add OAuth2 integration
✅ fix(api): 🐛 handle null values
✅ docs(readme): 📚 update installation
✅ security(auth): 🔒 implement rate limiting

❌ Added new feature
❌ Fix bug
❌ Update code
```

## 🤖 Claude Code Hooks

### Pre-tool-use Hooks

Validate operations **before** Claude Code executes them.

**Features:**
- 🔍 Validate Python syntax before file writes
- ⚠️ Warn about large file operations
- 🔒 Scan for secrets before file writes
- ✅ Validate JSON/YAML syntax
- 🚨 Warn about destructive commands
- 🛡️ Prevent production environment changes

**Configuration:**

Edit [`claude/pre-tool-use.json`](claude/pre-tool-use.json):

```json
{
  "configuration": {
    "enabled": true,
    "log_level": "info",
    "timeout_seconds": 30
  }
}
```

### Post-tool-use Hooks

Automate tasks **after** Claude Code modifies files.

**Features:**
- ✨ Auto-format Python files with Black
- 📦 Auto-fix issues with Ruff
- 🔤 Sort imports with isort
- 🧪 Run tests for modified files (optional)
- 🔍 Type check with mypy (optional)
- 📝 Auto-stage modified files (optional)
- 🔒 Security scan after package installs

**Configuration:**

Edit [`claude/post-tool-use.json`](claude/post-tool-use.json):

```json
{
  "configuration": {
    "enabled": true,
    "auto_test_enabled": false,
    "auto_stage_enabled": false,
    "type_checking_enabled": true,
    "cleanup_enabled": false
  }
}
```

### Session Hooks

Run at session **start** and **end**.

**Session Start:**
- ✅ Check environment setup
- ✅ Verify required tools
- ✅ Check git status
- ✅ Load environment variables
- ✅ Run quick security scan
- 📋 Display welcome message

**Session End:**
- ✅ Clean up temporary files
- ✅ Save session state
- ✅ Show git status summary
- ✅ Warn about uncommitted changes
- 📊 Display session summary

## 🎨 Pre-commit Framework

Comprehensive linting and formatting using the pre-commit framework.

**Included Hooks:**
- **Black**: Python code formatting
- **Ruff**: Fast Python linting
- **isort**: Import sorting
- **mypy**: Static type checking
- **Bandit**: Security linting
- **detect-secrets**: Secret detection
- **Safety**: Dependency vulnerability scanning
- **Prettier**: JSON/YAML/Markdown formatting
- **shellcheck**: Shell script linting
- **hadolint**: Dockerfile linting
- **yamllint**: YAML linting
- **markdownlint**: Markdown linting
- **commitizen**: Commit message linting

**Usage:**
```bash
# Install
pre-commit install

# Run on all files
pre-commit run --all-files

# Run specific hook
pre-commit run black --all-files

# Update hooks
pre-commit autoupdate
```

## 🛠️ Utility Scripts

### Check Coverage

Verify test coverage meets minimum threshold (default: 80%).

```bash
# Check with default threshold (80%)
bash hooks/utils/check-coverage.sh

# Check with custom threshold
bash hooks/utils/check-coverage.sh 90

# Set via environment variable
MIN_COVERAGE=85 bash hooks/utils/check-coverage.sh
```

### Scan Secrets

Comprehensive secret scanning for sensitive data.

```bash
# Scan all files
bash hooks/utils/scan-secrets.sh

# Scan staged files only
bash hooks/utils/scan-secrets.sh --staged

# Scan specific file
bash hooks/utils/scan-secrets.sh --file path/to/file.py

# Quick scan (first 100 files)
bash hooks/utils/scan-secrets.sh --quick
```

### Run Security Checks

Run all security tools and generate report.

```bash
# Run all security checks
bash hooks/utils/run-security-checks.sh

# View generated report
cat security-report.txt
```

### Format Code

Format all Python files in the project.

```bash
# Format current directory
bash hooks/utils/format-code.sh

# Format specific directory
bash hooks/utils/format-code.sh src/

# Format entire project
bash hooks/utils/format-code.sh .
```

### Validate Dependencies

Check for security vulnerabilities in dependencies.

```bash
# Validate dependencies
bash hooks/utils/validate-dependencies.sh

# View generated report
cat dependency-report.txt
```

## ⚙️ Configuration

### Environment Variables

Global configuration via environment variables:

```bash
# Skip all hooks
export SKIP_HOOKS=true

# Skip specific checks
export SKIP_FORMAT=true
export SKIP_LINT=true
export SKIP_SECRETS=true
export SKIP_TESTS=true
export SKIP_COVERAGE=true
export SKIP_SECURITY=true
export SKIP_COMMIT_MSG=true

# Auto-install dependencies
export AUTO_INSTALL=true

# Auto-run migrations
export AUTO_MIGRATE=false

# Coverage threshold
export MIN_COVERAGE=80

# Python command
export PYTHON_CMD=python3

# Strict mode for commit messages
export STRICT_MODE=false
```

### Per-project Configuration

Create `.env` file in project root:

```bash
# .env
SKIP_HOOKS=false
AUTO_INSTALL=true
AUTO_MIGRATE=false
MIN_COVERAGE=85
PYTHON_CMD=python3.11
```

## 🚫 Skipping Hooks

### Temporary Skip

Skip hooks for a single operation:

```bash
# Skip all hooks
SKIP_HOOKS=true git commit -m "emergency fix"
SKIP_HOOKS=true git push

# Skip specific checks
SKIP_FORMAT=true git commit -m "wip"
SKIP_TESTS=true git push
```

### Permanent Skip

Disable hooks permanently (not recommended):

```bash
# Remove git hooks
rm .git/hooks/pre-commit
rm .git/hooks/pre-push

# Disable pre-commit framework
pre-commit uninstall
```

## 📊 Logging

All hook executions are logged to [`.hook-logs/`](.hook-logs/) directory:

```bash
# View recent logs
ls -lt .hook-logs/

# View specific log
cat .hook-logs/pre-commit-20260330-193000.log

# Clean old logs (older than 7 days)
find .hook-logs -name "*.log" -mtime +7 -delete
```

## 🔍 Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed troubleshooting guide.

### Common Issues

**Hooks not running:**
```bash
# Check if hooks are installed
ls -la .git/hooks/

# Reinstall hooks
bash hooks/INSTALLATION.md
```

**Permission denied:**
```bash
# Make scripts executable
chmod +x hooks/git/*.sh
chmod +x hooks/utils/*.sh
```

**Tool not found:**
```bash
# Install required tools
pip install black ruff mypy pytest pytest-cov bandit safety pip-audit
```

## 📚 Additional Resources

- [INSTALLATION.md](INSTALLATION.md) - Detailed installation guide
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and solutions
- [Conventional Commits](https://www.conventionalcommits.org/) - Commit message format
- [Pre-commit Framework](https://pre-commit.com/) - Pre-commit documentation

## 🤝 Contributing

When contributing to this hook system:

1. Follow shell scripting standards from `.roo/rules/08-shell-scripting-standards.md`
2. Test hooks thoroughly before committing
3. Update documentation for any changes
4. Add examples for new features
5. Ensure backward compatibility

## 📄 License

Part of the Python Claude Template project.
