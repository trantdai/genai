# Hook System Troubleshooting Guide

Common issues and solutions for the development lifecycle hooks system.

## 📋 Table of Contents

- [Common Issues](#common-issues)
- [Git Hooks Issues](#git-hooks-issues)
- [Pre-commit Framework Issues](#pre-commit-framework-issues)
- [Tool-Specific Issues](#tool-specific-issues)
- [Performance Issues](#performance-issues)
- [Platform-Specific Issues](#platform-specific-issues)
- [Debugging](#debugging)

## 🔧 Common Issues

### Hooks Not Running

**Symptom:** Git hooks don't execute when committing or pushing.

**Solutions:**

```bash
# 1. Check if hooks are installed
ls -la .git/hooks/

# 2. Verify hooks are executable
chmod +x .git/hooks/pre-commit
chmod +x .git/hooks/pre-push
chmod +x .git/hooks/commit-msg

# 3. Check if hooks are symlinks
ls -la .git/hooks/ | grep "^l"

# 4. Verify symlink targets exist
readlink .git/hooks/pre-commit

# 5. Reinstall hooks
bash hooks/INSTALLATION.md
```

### Permission Denied Errors

**Symptom:** `Permission denied` when hooks try to execute.

**Solutions:**

```bash
# Make all hook scripts executable
chmod +x hooks/git/*.sh
chmod +x hooks/utils/*.sh

# Make Git hooks executable
chmod +x .git/hooks/*

# Verify permissions
ls -la hooks/git/
ls -la .git/hooks/
```

### Command Not Found

**Symptom:** `command not found: black` or similar errors.

**Solutions:**

```bash
# Install missing tools
pip install black ruff mypy pytest pytest-cov bandit safety pip-audit

# Verify installation
which black
which ruff
which pytest

# Check Python path
echo $PATH
which python3

# Use specific Python version
export PYTHON_CMD=python3.11
```

### Hooks Fail Silently

**Symptom:** Hooks don't report errors or seem to do nothing.

**Solutions:**

```bash
# Check log files
ls -la hooks/.hook-logs/
tail -f hooks/.hook-logs/pre-commit-*.log

# Run hooks manually to see output
bash hooks/git/pre-commit.sh

# Enable verbose mode
set -x
bash hooks/git/pre-commit.sh
```

## 🔀 Git Hooks Issues

### Pre-commit Hook Fails

**Issue:** Pre-commit hook fails with formatting errors.

**Solutions:**

```bash
# Auto-fix formatting issues
bash hooks/utils/format-code.sh

# Or fix manually
black .
ruff check --fix .
isort .

# Then commit again
git add .
git commit -m "fix: 🐛 formatting issues"
```

### Pre-push Hook Takes Too Long

**Issue:** Pre-push hook runs for several minutes.

**Solutions:**

```bash
# Skip tests temporarily
SKIP_TESTS=true git push

# Skip coverage check
SKIP_COVERAGE=true git push

# Skip all checks (emergency only)
SKIP_HOOKS=true git push

# Or optimize tests
pytest -n auto  # Run tests in parallel
```

### Commit Message Validation Fails

**Issue:** Commit message doesn't follow conventional format.

**Solutions:**

```bash
# Use correct format
git commit -m "feat(api): ✨ add new endpoint"
git commit -m "fix(auth): 🐛 handle null values"

# Skip validation temporarily
SKIP_COMMIT_MSG=true git commit -m "quick fix"

# View valid formats
bash hooks/git/commit-msg.sh --help
```

### Post-checkout Hook Fails

**Issue:** Dependencies fail to install after checkout.

**Solutions:**

```bash
# Disable auto-install
export AUTO_INSTALL=false

# Install manually
pip install -r requirements.txt

# Or use specific tool
poetry install
pipenv install
```

### Post-merge Hook Issues

**Issue:** Migrations fail after merge.

**Solutions:**

```bash
# Disable auto-migrate
export AUTO_MIGRATE=false

# Run migrations manually
alembic upgrade head
# or
python manage.py migrate

# Check migration status
alembic current
```

## 🎨 Pre-commit Framework Issues

### Pre-commit Not Installed

**Symptom:** `pre-commit: command not found`

**Solutions:**

```bash
# Install pre-commit
pip install pre-commit

# Verify installation
pre-commit --version

# Install hooks
pre-commit install
pre-commit install --hook-type commit-msg
```

### Pre-commit Hooks Fail

**Issue:** Pre-commit hooks fail on first run.

**Solutions:**

```bash
# Update hooks
pre-commit autoupdate

# Clean cache
pre-commit clean

# Reinstall
pre-commit uninstall
pre-commit install

# Run manually
pre-commit run --all-files
```

### Specific Hook Fails

**Issue:** One specific pre-commit hook fails.

**Solutions:**

```bash
# Skip specific hook temporarily
SKIP=black git commit -m "test"

# Or skip multiple hooks
SKIP=black,ruff git commit -m "test"

# Disable hook in config
# Edit .pre-commit-config.yaml and comment out the hook

# Run specific hook manually
pre-commit run black --all-files
```

### Pre-commit Too Slow

**Issue:** Pre-commit takes too long to run.

**Solutions:**

```bash
# Run only on changed files (default)
pre-commit run

# Skip slow hooks
SKIP=mypy,bandit git commit -m "quick fix"

# Disable specific hooks in .pre-commit-config.yaml
# Comment out slow hooks like mypy or bandit
```

## 🛠️ Tool-Specific Issues

### Black Formatting Issues

**Issue:** Black fails to format files.

**Solutions:**

```bash
# Check Black version
black --version

# Update Black
pip install --upgrade black

# Run with verbose output
black --verbose .

# Check for syntax errors
python3 -m py_compile file.py
```

### Ruff Linting Errors

**Issue:** Ruff reports unfixable errors.

**Solutions:**

```bash
# Show all errors
ruff check .

# Try auto-fix
ruff check --fix .

# Ignore specific rules
ruff check --ignore E501 .

# Configure in pyproject.toml
[tool.ruff]
ignore = ["E501", "F401"]
```

### Mypy Type Checking Fails

**Issue:** Mypy reports type errors.

**Solutions:**

```bash
# Install type stubs
pip install types-requests types-PyYAML

# Ignore missing imports
mypy --ignore-missing-imports .

# Configure in pyproject.toml
[tool.mypy]
ignore_missing_imports = true

# Skip mypy temporarily
SKIP_LINT=true git commit -m "wip"
```

### Pytest Fails

**Issue:** Tests fail during pre-push.

**Solutions:**

```bash
# Run tests manually to see full output
pytest -v

# Run specific test
pytest tests/test_file.py::test_function

# Skip failing tests temporarily
pytest -k "not slow"

# Skip tests in hook
SKIP_TESTS=true git push
```

### Coverage Below Threshold

**Issue:** Test coverage is below 80%.

**Solutions:**

```bash
# Check coverage report
pytest --cov=. --cov-report=html
open htmlcov/index.html

# Lower threshold temporarily
MIN_COVERAGE=70 bash hooks/utils/check-coverage.sh

# Skip coverage check
SKIP_COVERAGE=true git push

# Add more tests to increase coverage
```

### Secret Scanner False Positives

**Issue:** Secret scanner detects false positives.

**Solutions:**

```bash
# Update secrets baseline
detect-secrets scan --baseline .secrets.baseline

# Audit baseline
detect-secrets audit .secrets.baseline

# Skip secret scan temporarily
SKIP_SECRETS=true git commit -m "test data"

# Exclude files in .pre-commit-config.yaml
exclude: ^tests/fixtures/
```

## ⚡ Performance Issues

### Hooks Run Too Slowly

**Issue:** Hooks take too long to complete.

**Solutions:**

```bash
# Profile hook execution
time bash hooks/git/pre-commit.sh

# Skip slow checks
SKIP_LINT=true git commit -m "quick fix"

# Run checks in parallel (if supported)
# Edit hook scripts to use parallel execution

# Reduce scope
# Only run on changed files, not all files
```

### Large Repository Issues

**Issue:** Hooks timeout on large repositories.

**Solutions:**

```bash
# Increase timeout in hook scripts
# Edit hooks and increase timeout values

# Run on staged files only
git diff --cached --name-only | xargs black

# Use pre-commit framework (more efficient)
pre-commit run

# Exclude large directories
# Add to .gitignore or hook exclude patterns
```

### Memory Issues

**Issue:** Hooks consume too much memory.

**Solutions:**

```bash
# Process files in batches
# Edit hook scripts to process files in smaller batches

# Increase system memory limits
ulimit -m unlimited

# Use lighter alternatives
# Replace heavy tools with lighter ones
```

## 🖥️ Platform-Specific Issues

### macOS Issues

**Issue:** BSD sed doesn't work with hooks.

**Solutions:**

```bash
# Install GNU sed
brew install gnu-sed

# Add to PATH
export PATH="/usr/local/opt/gnu-sed/libexec/gnubin:$PATH"

# Or use gsed explicitly in scripts
gsed -i 's/pattern/replacement/' file
```

**Issue:** Permission issues with symlinks.

**Solutions:**

```bash
# Use absolute paths for symlinks
ln -sf "$(pwd)/hooks/git/pre-commit.sh" .git/hooks/pre-commit

# Or copy files instead
cp hooks/git/pre-commit.sh .git/hooks/pre-commit
```

### Linux Issues

**Issue:** Different shell behavior.

**Solutions:**

```bash
# Ensure bash is used
#!/bin/bash

# Check shell
echo $SHELL

# Use bash explicitly
bash hooks/git/pre-commit.sh
```

### Windows (WSL) Issues

**Issue:** Line ending problems.

**Solutions:**

```bash
# Configure Git line endings
git config --global core.autocrlf input

# Convert existing files
dos2unix hooks/git/*.sh

# Or use sed
sed -i 's/\r$//' hooks/git/*.sh
```

**Issue:** Path issues between Windows and WSL.

**Solutions:**

```bash
# Use WSL paths
cd /mnt/c/Users/username/project

# Or use wslpath
wslpath -u "C:\Users\username\project"
```

## 🐛 Debugging

### Enable Debug Mode

```bash
# Enable bash debug mode
set -x
bash hooks/git/pre-commit.sh

# Or add to script
#!/bin/bash
set -x  # Enable debug output
set -euo pipefail
```

### Check Environment

```bash
# Print all environment variables
env | grep -i hook
env | grep -i skip

# Check PATH
echo $PATH

# Check Python environment
which python3
python3 --version
pip list
```

### Manual Hook Execution

```bash
# Run hook manually
bash hooks/git/pre-commit.sh

# Run with specific file
bash hooks/git/commit-msg.sh .git/COMMIT_EDITMSG

# Run utility scripts
bash hooks/utils/scan-secrets.sh --staged
bash hooks/utils/check-coverage.sh 80
```

### Check Log Files

```bash
# List all logs
ls -lt hooks/.hook-logs/

# View latest log
tail -f hooks/.hook-logs/pre-commit-*.log

# Search for errors
grep -i error hooks/.hook-logs/*.log

# View specific hook log
cat hooks/.hook-logs/pre-commit-20260330-193000.log
```

### Test Individual Components

```bash
# Test Black
black --check file.py

# Test Ruff
ruff check file.py

# Test mypy
mypy file.py

# Test pytest
pytest tests/

# Test secret scanner
bash hooks/utils/scan-secrets.sh --file file.py
```

### Verify Git Configuration

```bash
# Check Git hooks path
git config core.hooksPath

# List Git hooks
ls -la .git/hooks/

# Check Git version
git --version

# Verify repository
git rev-parse --git-dir
```

## 🔍 Advanced Debugging

### Trace Hook Execution

```bash
# Add tracing to hook
#!/bin/bash
set -x  # Print commands
set -v  # Print input lines

# Or use bash -x
bash -x hooks/git/pre-commit.sh
```

### Profile Performance

```bash
# Time each section
time bash hooks/git/pre-commit.sh

# Profile with detailed timing
PS4='+ $(date "+%s.%N")\011 '
set -x
bash hooks/git/pre-commit.sh
```

### Check File Permissions

```bash
# Check all permissions
find hooks -type f -exec ls -la {} \;

# Fix all permissions
find hooks -type f -name "*.sh" -exec chmod +x {} \;
```

## 🆘 Getting Help

If issues persist:

1. **Check Documentation**
   - Read [README.md](README.md)
   - Review [INSTALLATION.md](INSTALLATION.md)

2. **Review Logs**
   - Check `hooks/.hook-logs/`
   - Look for error messages

3. **Test Components**
   - Run hooks manually
   - Test tools individually

4. **Verify Setup**
   - Check prerequisites
   - Verify installation

5. **Temporary Workarounds**
   - Skip problematic hooks
   - Use environment variables

6. **Report Issues**
   - Include error messages
   - Provide log files
   - Describe environment

## 📚 Additional Resources

- [Git Hooks Documentation](https://git-scm.com/docs/githooks)
- [Pre-commit Framework](https://pre-commit.com/)
- [Black Documentation](https://black.readthedocs.io/)
- [Ruff Documentation](https://docs.astral.sh/ruff/)
- [Pytest Documentation](https://docs.pytest.org/)

## 📄 License

Part of the Python Claude Template project.
