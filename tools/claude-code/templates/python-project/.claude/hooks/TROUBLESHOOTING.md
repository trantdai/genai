# Hook System Troubleshooting

## Common Issues

**Hooks Not Running**
```bash
ls -la .git/hooks/
chmod +x .git/hooks/* hooks/*/*.sh
```

**Permission Denied**
```bash
chmod +x hooks/git/*.sh hooks/utils/*.sh
```

**Tools Not Found**
```bash
pip install black ruff mypy pytest pytest-cov bandit safety pip-audit pre-commit
which black ruff mypy pytest bandit
```

**Hook Fails**
- Run manually: `bash hooks/git/pre-commit.sh`
- Check logs: `tail -f .hook-logs/pre-commit-*.log`
- Debug: `bash -x hooks/git/pre-commit.sh`

**Skip Hooks Temporarily**
```bash
SKIP_FORMAT=true git commit
SKIP_TESTS=true git push
SKIP_HOOKS=true git commit
```

**Pre-commit Framework**
```bash
pre-commit install
pre-commit run --all-files
pre-commit autoupdate
```

**Commit Message Rejected**
- Format: `type(scope): description`
- Valid types: feat, fix, docs, style, refactor, test, chore, security, perf

## Environment Variables

```bash
export SKIP_FORMAT=true    # Skip formatting
export SKIP_LINT=true      # Skip linting
export SKIP_TESTS=true     # Skip tests
export SKIP_COVERAGE=true  # Skip coverage
export SKIP_SECURITY=true  # Skip security
export SKIP_HOOKS=true     # Skip all
```

See [README.md](README.md) and [INSTALLATION.md](INSTALLATION.md) for setup details.
