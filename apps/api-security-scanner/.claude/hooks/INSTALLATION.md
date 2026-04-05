# Hook System Installation Guide

Complete guide for installing and configuring the development lifecycle hooks system.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Installation](#quick-installation)
- [Detailed Installation](#detailed-installation)
- [Verification](#verification)
- [Configuration](#configuration)
- [Uninstallation](#uninstallation)

## ✅ Prerequisites

### Required Tools

```bash
# Python 3.8+
python3 --version

# Git
git --version

# pip
pip --version
```

### Recommended Tools

```bash
# Install Python development tools
pip install black ruff mypy isort

# Install testing tools
pip install pytest pytest-cov pytest-mock

# Install security tools
pip install bandit safety pip-audit detect-secrets

# Install pre-commit framework
pip install pre-commit

# Optional: Install additional security tools
pip install gitleaks truffleHog  # If available
```

## 🚀 Quick Installation

### Option 1: Automated Installation Script

```bash
#!/bin/bash
# Quick install script

HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

# Make scripts executable
chmod +x "${HOOKS_DIR}"/git/*.sh
chmod +x "${HOOKS_DIR}"/utils/*.sh

# Install Git hooks
cd "${PROJECT_ROOT}"
mkdir -p .git/hooks

ln -sf "../../hooks/git/pre-commit.sh" .git/hooks/pre-commit
ln -sf "../../hooks/git/pre-push.sh" .git/hooks/pre-push
ln -sf "../../hooks/git/post-checkout.sh" .git/hooks/post-checkout
ln -sf "../../hooks/git/post-merge.sh" .git/hooks/post-merge
ln -sf "../../hooks/git/commit-msg.sh" .git/hooks/commit-msg

# Install pre-commit framework
if command -v pre-commit >/dev/null 2>&1; then
    cp "${HOOKS_DIR}/.pre-commit-config.yaml" "${PROJECT_ROOT}/.pre-commit-config.yaml"
    pre-commit install
    pre-commit install --hook-type commit-msg
fi

echo "✓ Hooks installed successfully!"
```

Save this as `install-hooks.sh` and run:

```bash
bash hooks/install-hooks.sh
```

### Option 2: Manual Quick Install

```bash
# Navigate to project root
cd your-project

# Make scripts executable
chmod +x hooks/git/*.sh
chmod +x hooks/utils/*.sh

# Create symlinks
ln -sf ../../hooks/git/pre-commit.sh .git/hooks/pre-commit
ln -sf ../../hooks/git/pre-push.sh .git/hooks/pre-push
ln -sf ../../hooks/git/post-checkout.sh .git/hooks/post-checkout
ln -sf ../../hooks/git/post-merge.sh .git/hooks/post-merge
ln -sf ../../hooks/git/commit-msg.sh .git/hooks/commit-msg

# Install pre-commit
cp hooks/.pre-commit-config.yaml .pre-commit-config.yaml
pre-commit install
pre-commit install --hook-type commit-msg
```

## 📖 Detailed Installation

### Step 1: Prepare Environment

```bash
# Navigate to your project
cd /path/to/your/project

# Verify Git repository
git rev-parse --git-dir

# Create hooks directory if needed
mkdir -p .git/hooks

# Create log directory
mkdir -p hooks/.hook-logs
```

### Step 2: Make Scripts Executable

```bash
# Make all Git hook scripts executable
chmod +x hooks/git/pre-commit.sh
chmod +x hooks/git/pre-push.sh
chmod +x hooks/git/post-checkout.sh
chmod +x hooks/git/post-merge.sh
chmod +x hooks/git/commit-msg.sh

# Make all utility scripts executable
chmod +x hooks/utils/check-coverage.sh
chmod +x hooks/utils/scan-secrets.sh
chmod +x hooks/utils/run-security-checks.sh
chmod +x hooks/utils/format-code.sh
chmod +x hooks/utils/validate-dependencies.sh

# Verify permissions
ls -la hooks/git/*.sh
ls -la hooks/utils/*.sh
```

### Step 3: Install Git Hooks

#### Using Symlinks (Recommended)

Symlinks allow hooks to update automatically when the source files change.

```bash
# Pre-commit hook
ln -sf ../../hooks/git/pre-commit.sh .git/hooks/pre-commit

# Pre-push hook
ln -sf ../../hooks/git/pre-push.sh .git/hooks/pre-push

# Post-checkout hook
ln -sf ../../hooks/git/post-checkout.sh .git/hooks/post-checkout

# Post-merge hook
ln -sf ../../hooks/git/post-merge.sh .git/hooks/post-merge

# Commit-msg hook
ln -sf ../../hooks/git/commit-msg.sh .git/hooks/commit-msg

# Verify symlinks
ls -la .git/hooks/
```

#### Using Copies (Alternative)

If symlinks don't work on your system:

```bash
# Copy hooks
cp hooks/git/pre-commit.sh .git/hooks/pre-commit
cp hooks/git/pre-push.sh .git/hooks/pre-push
cp hooks/git/post-checkout.sh .git/hooks/post-checkout
cp hooks/git/post-merge.sh .git/hooks/post-merge
cp hooks/git/commit-msg.sh .git/hooks/commit-msg

# Make executable
chmod +x .git/hooks/pre-commit
chmod +x .git/hooks/pre-push
chmod +x .git/hooks/post-checkout
chmod +x .git/hooks/post-merge
chmod +x .git/hooks/commit-msg
```

### Step 4: Install Pre-commit Framework

```bash
# Install pre-commit
pip install pre-commit

# Copy configuration
cp hooks/.pre-commit-config.yaml .pre-commit-config.yaml

# Install pre-commit hooks
pre-commit install

# Install commit-msg hook
pre-commit install --hook-type commit-msg

# Verify installation
pre-commit --version
```

### Step 5: Install Python Dependencies

```bash
# Core tools
pip install black ruff mypy isort

# Testing tools
pip install pytest pytest-cov pytest-mock pytest-asyncio

# Security tools
pip install bandit safety pip-audit detect-secrets

# Optional tools
pip install pipdeptree  # For dependency tree visualization
```

### Step 6: Configure Environment

Create `.env` file in project root:

```bash
# .env
SKIP_HOOKS=false
AUTO_INSTALL=true
AUTO_MIGRATE=false
MIN_COVERAGE=80
PYTHON_CMD=python3
STRICT_MODE=false
```

Or set environment variables in your shell profile:

```bash
# ~/.bashrc or ~/.zshrc
export AUTO_INSTALL=true
export MIN_COVERAGE=80
export PYTHON_CMD=python3
```

### Step 7: Initialize Secret Scanning

```bash
# Create secrets baseline
detect-secrets scan > .secrets.baseline

# Add to .gitignore
echo ".secrets.baseline" >> .gitignore
```

### Step 8: Configure YAML Linting (Optional)

Create `.yamllint.yml`:

```yaml
extends: default

rules:
  line-length:
    max: 120
  indentation:
    spaces: 2
  comments:
    min-spaces-from-content: 1
```

## ✓ Verification

### Test Git Hooks

```bash
# Test pre-commit hook
echo "# Test" >> test_file.py
git add test_file.py
git commit -m "test: 🧪 testing pre-commit hook"

# Test commit-msg hook
git commit --allow-empty -m "invalid commit message"  # Should fail
git commit --allow-empty -m "test: 🧪 valid message"  # Should pass

# Test pre-push hook (if you have tests)
git push origin feature-branch
```

### Test Utility Scripts

```bash
# Test format script
bash hooks/utils/format-code.sh .

# Test secret scanner
bash hooks/utils/scan-secrets.sh --quick

# Test coverage checker (requires tests)
bash hooks/utils/check-coverage.sh

# Test security checks
bash hooks/utils/run-security-checks.sh

# Test dependency validator
bash hooks/utils/validate-dependencies.sh
```

### Test Pre-commit Framework

```bash
# Run on all files
pre-commit run --all-files

# Run specific hook
pre-commit run black --all-files

# Test auto-update
pre-commit autoupdate
```

### Verify Logs

```bash
# Check log directory
ls -la hooks/.hook-logs/

# View recent log
tail -f hooks/.hook-logs/pre-commit-*.log
```

## ⚙️ Configuration

### Per-User Configuration

Create `~/.config/python-hooks/config`:

```bash
# User-specific hook configuration
SKIP_HOOKS=false
MIN_COVERAGE=85
PYTHON_CMD=python3.11
```

### Per-Project Configuration

Create `.git/hooks/config`:

```bash
# Project-specific hook configuration
AUTO_INSTALL=true
AUTO_MIGRATE=false
STRICT_MODE=true
```

### Claude Code Configuration

Edit hook configurations:

```bash
# Edit pre-tool-use hooks
vim hooks/claude/pre-tool-use.json

# Edit post-tool-use hooks
vim hooks/claude/post-tool-use.json

# Edit session hooks
vim hooks/claude/session-hooks.json
```

## 🗑️ Uninstallation

### Remove Git Hooks

```bash
# Remove symlinks/files
rm .git/hooks/pre-commit
rm .git/hooks/pre-push
rm .git/hooks/post-checkout
rm .git/hooks/post-merge
rm .git/hooks/commit-msg

# Or remove all hooks
rm .git/hooks/*
```

### Remove Pre-commit Framework

```bash
# Uninstall pre-commit hooks
pre-commit uninstall
pre-commit uninstall --hook-type commit-msg

# Remove configuration
rm .pre-commit-config.yaml
```

### Clean Up

```bash
# Remove logs
rm -rf hooks/.hook-logs/

# Remove generated reports
rm -f bandit-report.json
rm -f safety-report.json
rm -f pip-audit-report.json
rm -f security-report.txt
rm -f dependency-report.txt
rm -f coverage.json
rm -rf htmlcov/
```

## 🔄 Updating Hooks

### Update Hook Scripts

```bash
# If using symlinks, just pull latest changes
git pull origin main

# If using copies, re-copy the files
cp hooks/git/*.sh .git/hooks/
chmod +x .git/hooks/*
```

### Update Pre-commit Hooks

```bash
# Update to latest versions
pre-commit autoupdate

# Re-run on all files
pre-commit run --all-files
```

## 🐳 Docker Installation

If using Docker:

```dockerfile
# Dockerfile
FROM python:3.11-slim

# Install Git
RUN apt-get update && apt-get install -y git

# Install Python tools
RUN pip install black ruff mypy pytest pytest-cov bandit safety pip-audit pre-commit

# Copy hooks
COPY hooks/ /app/hooks/
RUN chmod +x /app/hooks/git/*.sh /app/hooks/utils/*.sh

# Install hooks
WORKDIR /app
RUN git init && \
    ln -sf ../../hooks/git/pre-commit.sh .git/hooks/pre-commit && \
    ln -sf ../../hooks/git/pre-push.sh .git/hooks/pre-push
```

## 🎯 Platform-Specific Notes

### macOS

```bash
# Install GNU sed if needed
brew install gnu-sed

# Use gsed instead of sed
export PATH="/usr/local/opt/gnu-sed/libexec/gnubin:$PATH"
```

### Linux

```bash
# Install required packages
sudo apt-get update
sudo apt-get install -y git python3 python3-pip

# Or on RHEL/CentOS
sudo yum install -y git python3 python3-pip
```

### Windows (WSL)

```bash
# Use WSL2 for best compatibility
wsl --install

# Inside WSL, follow Linux instructions
```

### Windows (Git Bash)

```bash
# Use Git Bash or WSL
# Some features may not work in native Windows
```

## 📚 Next Steps

After installation:

1. Read [README.md](README.md) for usage instructions
2. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) if you encounter issues
3. Configure hooks for your project needs
4. Test hooks with sample commits
5. Share installation guide with team

## 🆘 Getting Help

If you encounter issues:

1. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
2. Review log files in `hooks/.hook-logs/`
3. Verify all prerequisites are installed
4. Test hooks individually
5. Check file permissions

## 📄 License

Part of the Python Claude Template project.
