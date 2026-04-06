# Hook System Installation

Quick setup guide for development hooks.

## Prerequisites

```bash
# Required
python3 --version  # 3.11+
git --version
pip --version

# Install tools
pip install black ruff mypy pytest pytest-cov bandit safety pip-audit pre-commit
```

## Quick Install

```bash
# 1. Make scripts executable
chmod +x hooks/git/*.sh hooks/utils/*.sh

# 2. Install Git hooks (symlinks)
ln -sf ../../hooks/git/pre-commit.sh .git/hooks/pre-commit
ln -sf ../../hooks/git/pre-push.sh .git/hooks/pre-push
ln -sf ../../hooks/git/post-checkout.sh .git/hooks/post-checkout
ln -sf ../../hooks/git/post-merge.sh .git/hooks/post-merge
ln -sf ../../hooks/git/commit-msg.sh .git/hooks/commit-msg

# 3. Install pre-commit framework
pre-commit install
pre-commit install --hook-type commit-msg

# 4. Test installation
pre-commit run --all-files
```

## Verify Installation

```bash
# Check hooks are installed
ls -la .git/hooks/

# Check tools are available
which black ruff mypy pytest bandit

# Run hooks manually
bash hooks/git/pre-commit.sh
```

## Configuration

### pyproject.toml
```toml
[tool.black]
line-length = 100
target-version = ['py313']

[tool.ruff]
line-length = 100
select = ["E", "F", "I", "N", "W", "UP", "B", "C4", "S"]

[tool.mypy]
strict = true
python_version = "3.13"

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py", "*_test.py"]
```

### .pre-commit-config.yaml
```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 24.1.0
    hooks:
      - id: black
        args: [--line-length=100]
  
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.0
    hooks:
      - id: ruff
        args: [--fix]
```

## Environment Variables

Optional configuration:
```bash
# Skip specific checks
export SKIP_FORMAT=true
export SKIP_LINT=true
export SKIP_TESTS=true
export SKIP_COVERAGE=true

# Adjust thresholds
export MIN_COVERAGE=80
export PYTHON_CMD=python3

# Auto-install dependencies
export AUTO_INSTALL=true
```

## Platform-Specific

### macOS
```bash
brew install python@3.13
pip3 install -r requirements-dev.txt
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get install python3-dev python3-pip
pip3 install -r requirements-dev.txt
```

### Windows (Git Bash)
```bash
pip install -r requirements-dev.txt
# Use forward slashes in paths
```

## Uninstall

```bash
# Remove Git hooks
rm .git/hooks/pre-commit .git/hooks/pre-push .git/hooks/commit-msg

# Uninstall pre-commit
pre-commit uninstall
pre-commit uninstall --hook-type commit-msg

# Remove configuration (optional)
rm .pre-commit-config.yaml
```

## Troubleshooting

- **Hooks not running**: Check permissions `chmod +x .git/hooks/*`
- **Command not found**: Verify tool installation `which black ruff mypy`
- **Permission denied**: Make scripts executable `chmod +x hooks/*/*.sh`

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed solutions.
