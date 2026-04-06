# Hook System Troubleshooting

Common issues and quick solutions for development hooks.

## Quick Fixes

### Hooks Not Running
- Check: `ls -la .git/hooks/`
- Fix: `chmod +x .git/hooks/* && chmod +x hooks/*/*.sh`
- Reinstall: Run installation script

### Permission Denied
```bash
chmod +x hooks/git/*.sh hooks/utils/*.sh .git/hooks/*
```

### Command Not Found
```bash
pip install black ruff mypy pytest pytest-cov bandit safety pip-audit
```

### Hooks Fail Silently
- Check logs: `tail -f .hook-logs/pre-commit-*.log`
- Run manually: `bash hooks/git/pre-commit.sh`
- Debug mode: `set -x && bash hooks/git/pre-commit.sh`

## Git Hooks Issues

### Pre-commit Hook Fails
- Run formatters manually: `black . && ruff check --fix .`
- Skip temporarily: `SKIP_FORMAT=true git commit`
- Check Python version: `python3 --version`

### Pre-push Hook Slow
- Skip coverage: `SKIP_COVERAGE=true git push`
- Run tests in parallel: `pytest -n auto`

### Commit Message Rejected
- Format: `type(scope): description`
- Valid types: feat, fix, docs, style, refactor, test, chore, security, perf
- Example: `feat(api): add user authentication`

## Pre-commit Framework Issues

### Pre-commit Not Installed
```bash
pip install pre-commit
pre-commit install
pre-commit install --hook-type commit-msg
```

### Hook Updates Not Applied
```bash
pre-commit autoupdate
pre-commit run --all-files
```

### Specific Hook Fails
```bash
# Run single hook
pre-commit run black --all-files
pre-commit run ruff --all-files

# Skip failing hook
SKIP=mypy git commit
```

## Tool-Specific Issues

### Black Formatting Conflicts
- Configure in `pyproject.toml`: `line-length = 100`
- Check config: `black --version && black --config pyproject.toml --check .`

### Ruff Linting Errors
- Auto-fix: `ruff check --fix .`
- Ignore specific rules: Add to `pyproject.toml` `[tool.ruff] ignore = ["E501"]`

### MyPy Type Errors
- Install type stubs: `pip install types-requests types-redis`
- Skip strict mode: Remove `--strict` from hook config

### Pytest Failures
- Run specific test: `pytest tests/test_file.py::test_function -v`
- Skip slow tests: `pytest -m "not slow"`

## Performance Issues

### Slow Pre-commit Hook
- Run only on changed files: Pre-commit does this by default
- Skip expensive checks: `SKIP_TESTS=true git commit`
- Reduce coverage check frequency

### Slow Pre-push Hook
- Run tests in parallel: `pytest -n auto`
- Skip security scans locally: `SKIP_SECURITY=true git push`

## Environment Variables

Skip specific checks:
```bash
export SKIP_FORMAT=true    # Skip formatting
export SKIP_LINT=true      # Skip linting
export SKIP_TESTS=true     # Skip tests
export SKIP_COVERAGE=true  # Skip coverage
export SKIP_SECURITY=true  # Skip security scan
export SKIP_HOOKS=true     # Skip all hooks
```

## Debugging

### Check Hook Execution
```bash
# Verbose mode
bash -x hooks/git/pre-commit.sh

# Check exit codes
bash hooks/git/pre-commit.sh; echo $?

# View logs
tail -f .hook-logs/pre-commit-*.log
```

### Verify Tool Installation
```bash
which python3 black ruff mypy pytest bandit
pip list | grep -E "black|ruff|mypy|pytest|bandit"
```

### Reset Hooks
```bash
# Remove all hooks
rm -rf .git/hooks/*

# Reinstall
pre-commit install
pre-commit install --hook-type commit-msg
```

## Platform-Specific

### Windows (Git Bash/WSL)
- Line endings: Configure `git config core.autocrlf true`
- Path separators: Use forward slashes in paths
- Python command: May need `python` instead of `python3`

### macOS
- Install XCode tools: `xcode-select --install`
- Use Homebrew Python: `brew install python@3.13`

### Linux
- Install Python dev headers: `sudo apt-get install python3-dev`
- Check file permissions: Unix file systems required

## Getting Help

1. Check logs in `.hook-logs/`
2. Run hooks manually to see full output
3. Verify all tools are installed: `pip list`
4. Check Python version: `python3 --version`
5. Review hook configuration in `pyproject.toml`

For persistent issues, review:
- [README.md](README.md) - Hook system overview
- [INSTALLATION.md](INSTALLATION.md) - Setup instructions
- Tool documentation: Black, Ruff, mypy, pytest
