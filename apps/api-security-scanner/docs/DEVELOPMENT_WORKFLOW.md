# Development Workflow Guide

This guide explains the complete development workflow for the API Security Scanner project, automated through Make commands.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Workflow Phases](#workflow-phases)
- [Quick Reference](#quick-reference)
- [Detailed Phase Guide](#detailed-phase-guide)
- [Common Scenarios](#common-scenarios)
- [Troubleshooting](#troubleshooting)

---

## Overview

The development workflow is organized into **5 phases**, each with a dedicated Make command:

```
┌─────────────────────────────────────────────────────────┐
│ PHASE 1: SETUP (once per project or after git clone)   │
├─────────────────────────────────────────────────────────┤
│ make setup                                              │
│   ├─→ Create .venv if not exists                       │
│   ├─→ Install dependencies                             │
│   └─→ Create .env from .env.example                    │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ PHASE 2: DAILY START                                   │
├─────────────────────────────────────────────────────────┤
│ make sync                                               │
│   ├─→ git pull --rebase                                │
│   ├─→ Update deps if requirements changed              │
│   └─→ Show status                                      │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ PHASE 3: DEVELOPMENT LOOP (repeat many times)          │
├─────────────────────────────────────────────────────────┤
│ [Edit code]                                             │
│ make dev                                                │
│   ├─→ Run CI pipeline (fast)                           │
│   └─→ Show results                                     │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ PHASE 4: PRE-COMMIT (when ready to commit)             │
├─────────────────────────────────────────────────────────┤
│ make precommit                                         │
│   ├─→ Run full CI pipeline                             │
│   ├─→ Generate requirements-lock.txt                   │
│   └─→ Show what changed                                │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ PHASE 5: COMMIT & PUSH                                  │
├─────────────────────────────────────────────────────────┤
│ make commit MSG="feat: add new feature"                │
│   ├─→ git add -A                                       │
│   └─→ git commit -m "..."                              │
│                                                         │
│ make push                                               │
│   ├─→ git pull --rebase (sync one more time)           │
│   ├─→ If conflicts → STOP, let user resolve            │
│   ├─→ If no conflicts → git push                       │
│   └─→ Show success message                             │
└─────────────────────────────────────────────────────────┘
```

---

## Quick Reference

### Essential Commands

| Command | When to Use | What It Does |
|---------|-------------|--------------|
| `make setup` | Once after clone | Creates venv, installs deps, sets up config |
| `make sync` | Start of day | Pulls latest code, updates deps |
| `make dev` | During coding | Quick checks (format, lint, test) |
| `make precommit` | Before commit | Full CI + lock dependencies |
| `make commit MSG="..."` | Ready to commit | Commits with message |
| `make push` | After commit | Safely pushes to remote |

### Utility Commands

| Command | Purpose |
|---------|---------|
| `make help` | Show all available commands |
| `make status` | Show git status |
| `make test` | Run tests with coverage |
| `make lint` | Run linting only |
| `make format` | Format code only |
| `make clean` | Clean generated files |
| `make clean-all` | Clean everything including venv |

---

## Detailed Phase Guide

### Phase 1: Initial Setup

**When:** First time working on the project, or after `make clean-all`

**Command:**
```bash
make setup
```

**What happens:**
1. Creates Python virtual environment at `.venv/`
2. Upgrades pip to latest version
3. Installs production dependencies from `requirements.txt`
4. Installs development dependencies from `requirements-dev.txt`
5. Installs project in editable mode (`pip install -e .`)
6. Creates `.env` from `.env.example` (if it doesn't exist)

**After setup:**
```bash
# Activate the virtual environment
source .venv/bin/activate

# Verify installation
python --version
pip list
```

**⚠️ Important:** Always activate the virtual environment before working:
```bash
source .venv/bin/activate
```

---

### Phase 2: Daily Sync

**When:** Start of each day, or before starting new work

**Command:**
```bash
make sync
```

**What happens:**
1. Pulls latest changes from remote using `git pull --rebase`
2. Checks if `requirements.txt` or `requirements-dev.txt` changed
3. If changed, automatically reinstalls dependencies
4. Shows current git status

**Why rebase?**
- Creates cleaner, linear history
- Avoids unnecessary merge commits
- Replays your local commits on top of remote changes

**If sync fails:**
```bash
# Conflict during pull
⚠️  Pull failed - resolve conflicts manually

# Steps to resolve:
1. Check which files have conflicts: git status
2. Edit conflicted files (look for <<<<<<< markers)
3. Stage resolved files: git add <file>
4. Continue rebase: git rebase --continue
5. Try sync again: make sync
```

---

### Phase 3: Development Loop

**When:** Frequently during development (after each code change)

**Command:**
```bash
make dev
```

**What happens:**
1. **Formats code** with `ruff format`
2. **Runs linter** with `ruff check --fix` (auto-fixes issues)
3. **Runs tests** with `pytest --no-cov` (fast, no coverage)

**Why use `make dev` instead of `make ci`?**
- ✅ **Faster** - Skips coverage, security checks
- ✅ **Frequent feedback** - Run after every change
- ✅ **Auto-fixes** - Automatically fixes linting issues

**Typical development cycle:**
```bash
# 1. Edit code
vim src/api_security_scanner/scanner.py

# 2. Quick check
make dev

# 3. If tests fail, fix and repeat
vim src/api_security_scanner/scanner.py
make dev

# 4. Continue until all checks pass
```

---

### Phase 4: Pre-Commit Checks

**When:** Before committing code (when you're confident it's ready)

**Command:**
```bash
make precommit
```

**What happens:**
1. Runs **full CI pipeline**:
   - Cleans old artifacts
   - Formats code
   - Runs linting
   - Runs tests **with coverage**
   - Runs security checks (bandit)
2. **Locks dependencies** to `requirements-lock.txt`
3. Shows files that changed

**Why lock dependencies?**
- Records exact versions that work
- Helps reproduce bugs
- Documents working environment
- **Shared with team** - Everyone uses same versions

**What is `requirements-lock.txt`?**
```
requirements.txt         → httpx>=0.27.0 (flexible, committed)
requirements-lock.txt    → httpx==0.27.2 (exact, committed)
```

**Important:** Both files are committed to git so the team shares known-working versions!

**If precommit fails:**
```bash
# Test failure
❌ Tests failed

# Fix the issue
vim tests/test_scanner.py
make dev  # Quick check
make precommit  # Full check again
```

---

### Phase 5: Commit & Push

**When:** After `make precommit` passes

#### Step 1: Commit

**Command:**
```bash
make commit MSG="feat: add authentication support"
```

**What happens:**
1. Stages all changes (`git add -A`)
2. Commits with your message

**Commit message format:**
```bash
make commit MSG="type: description"

# Examples:
make commit MSG="feat: add OAuth2 authentication"
make commit MSG="fix: handle null values in API response"
make commit MSG="docs: update installation guide"
make commit MSG="test: add unit tests for scanner"
```

**Common types:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `test:` - Tests
- `refactor:` - Code refactoring
- `chore:` - Maintenance

#### Step 2: Push

**Command:**
```bash
make push
```

**What happens:**
1. **Syncs with remote** using `git pull --rebase`
2. **Checks for conflicts**
3. If no conflicts → **Pushes to remote**
4. If conflicts → **Stops and shows instructions**

**If conflicts occur:**
```bash
⚠️  CONFLICT DETECTED!

Please resolve conflicts manually:
  1. Fix conflicts in affected files
  2. git add <resolved-files>
  3. git rebase --continue
  4. make push (try again)
```

**Conflict resolution example:**
```bash
# 1. Check conflicted files
git status

# 2. Edit conflicted file
vim src/api_security_scanner/scanner.py

# Look for conflict markers:
<<<<<<< HEAD
your code
=======
their code
>>>>>>> branch-name

# 3. Choose which code to keep, remove markers

# 4. Stage resolved file
git add src/api_security_scanner/scanner.py

# 5. Continue rebase
git rebase --continue

# 6. Push again
make push
```

---

## Common Scenarios

### Scenario 1: Starting Your Day

```bash
# 1. Activate virtual environment
source .venv/bin/activate

# 2. Sync with team
make sync

# 3. Start coding!
```

### Scenario 2: Making a Quick Fix

```bash
# 1. Edit code
vim src/api_security_scanner/scanner.py

# 2. Quick check
make dev

# 3. If good, commit
make precommit
make commit MSG="fix: handle edge case in scanner"
make push
```

### Scenario 3: Adding a New Feature

```bash
# 1. Sync first
make sync

# 2. Create feature branch (optional)
git checkout -b feature/new-scanner

# 3. Develop with frequent checks
vim src/api_security_scanner/scanner.py
make dev

vim tests/test_scanner.py
make dev

# 4. When feature is complete
make precommit

# 5. Commit and push
make commit MSG="feat: add SQL injection scanner"
make push
```

### Scenario 4: Updating Dependencies

```bash
# 1. Edit requirements file
vim requirements.txt
# Change: httpx>=0.27.0 to httpx>=0.28.0

# 2. Sync will auto-install
make sync

# 3. Test with new version
make dev

# 4. If all good, commit
make precommit
make commit MSG="chore: upgrade httpx to 0.28.0"
make push
```

### Scenario 5: Fresh Start

```bash
# 1. Clean everything
make clean-all

# 2. Setup from scratch
make setup

# 3. Activate venv
source .venv/bin/activate

# 4. Verify
make dev
```

---

## Troubleshooting

### Problem: "make: command not found"

**Solution:** Install Make
```bash
# macOS
brew install make

# Ubuntu/Debian
sudo apt-get install make

# Windows (use WSL or Git Bash)
```

### Problem: "python3: command not found"

**Solution:** Install Python 3.13+
```bash
# macOS
brew install python@3.13

# Ubuntu/Debian
sudo apt-get install python3.13
```

### Problem: Virtual environment not activating

**Solution:**
```bash
# Make sure you're in project directory
cd apps/api-security-scanner

# Activate manually
source .venv/bin/activate

# Verify
which python
# Should show: /path/to/project/.venv/bin/python
```

### Problem: Dependencies not installing

**Solution:**
```bash
# Clean and reinstall
make clean-all
make setup

# Or manually
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt
pip install -e .
```

### Problem: Tests failing after sync

**Possible causes:**
1. **Someone pushed breaking changes**
   - Check git log: `git log --oneline -5`
   - Contact team member who made the change

2. **Dependencies out of sync**
   - Force reinstall: `make clean && make sync`

3. **Conflicts not fully resolved**
   - Check status: `git status`
   - Ensure no conflict markers in code

### Problem: Push rejected (non-fast-forward)

**Solution:**
```bash
# Someone pushed while you were working
make sync  # This will rebase your commits
make push  # Try again
```

### Problem: Accidentally committed to wrong branch

**Solution:**
```bash
# Undo last commit (keeps changes)
git reset --soft HEAD~1

# Switch to correct branch
git checkout correct-branch

# Commit again
make commit MSG="your message"
make push
```

---

## Best Practices

### ✅ Do's

- ✅ Run `make sync` at start of day
- ✅ Run `make dev` frequently during development
- ✅ Run `make precommit` before every commit
- ✅ Write clear commit messages
- ✅ Keep commits small and focused
- ✅ Activate virtual environment before working
- ✅ Review `requirements-lock.txt` changes before committing

### ❌ Don'ts

- ❌ Don't skip `make precommit`
- ❌ Don't commit without testing
- ❌ Don't push directly without `make push` (it has safety checks)
- ❌ Don't edit `requirements-lock.txt` manually
- ❌ Don't commit with venv deactivated
- ❌ Don't force push (`git push -f`) without team agreement

---

## Advanced Tips

### Tip 1: Check What Changed Before Committing

```bash
make precommit
git diff --cached  # See staged changes
git status         # See file list
```

### Tip 2: Commit Only Specific Files

```bash
# Instead of make commit (which does git add -A)
git add src/specific_file.py
git commit -m "feat: update specific feature"
make push
```

### Tip 3: Test Specific Test File

```bash
source .venv/bin/activate
pytest tests/unit/test_scanner.py -v
```

### Tip 4: Run Security Check Only

```bash
make security-check
```

### Tip 5: See Full CI Output

```bash
make ci
# Or for more verbose
make test-verbose
```

---

## Workflow Cheat Sheet

```bash
# DAILY ROUTINE
make sync                              # Start of day
[code, code, code]
make dev                               # After each change
make precommit                        # Before commit
make commit MSG="feat: new feature"    # Commit
make push                              # Push to remote

# UTILITY
make help                              # Show all commands
make status                            # Git status
make clean                             # Clean artifacts
make test                              # Run tests only
make lint                              # Lint only
make format                            # Format only

# EMERGENCY
make clean-all                         # Nuclear option
make setup                             # Start fresh
```

---

## Questions?

- Check `make help` for all available commands
- Review the [Makefile](../Makefile) for implementation details
- See [README.md](../README.md) for project overview

---

**Happy coding! 🚀**
