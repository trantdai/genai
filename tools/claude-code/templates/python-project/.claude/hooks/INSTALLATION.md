# Hook System Installation

## Install

```bash
# 1. Install tools
pip install black ruff mypy pytest pytest-cov bandit safety pip-audit pre-commit

# 2. Make scripts executable
chmod +x hooks/git/*.sh hooks/utils/*.sh

# 3. Install Git hooks
ln -sf ../../hooks/git/pre-commit.sh .git/hooks/pre-commit
ln -sf ../../hooks/git/pre-push.sh .git/hooks/pre-push
ln -sf ../../hooks/git/post-checkout.sh .git/hooks/post-checkout
ln -sf ../../hooks/git/post-merge.sh .git/hooks/post-merge
ln -sf ../../hooks/git/commit-msg.sh .git/hooks/commit-msg

# 4. Install pre-commit framework
pre-commit install
pre-commit install --hook-type commit-msg

# 5. Test
pre-commit run --all-files
```

## Verify

```bash
ls -la .git/hooks/
which black ruff mypy pytest bandit
```

## Configuration

Tool configuration in `pyproject.toml`. Pre-commit hooks in `.pre-commit-config.yaml`.

See [README.md](README.md) for usage. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for issues.
