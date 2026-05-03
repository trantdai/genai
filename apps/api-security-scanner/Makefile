# ============================================================================
# PHONY TARGETS (commands that don't create files)
# ============================================================================
# Note: install and install-dev are NOT in .PHONY because they now create
# marker files (.deps-*-installed) that Make uses for smart caching
.PHONY: help test test-unit test-integration test-verbose test-coverage lint format clean run security-check check quality ci setup sync dev precommit commit push status clean-all

# ============================================================================
# DEFAULT TARGET (runs when you type just 'make')
# ============================================================================
.DEFAULT_GOAL := help

# ============================================================================
# VARIABLES
# ============================================================================
PYTHON := python3
VENV := .venv
VENV_BIN := $(VENV)/bin
VENV_PYTHON := $(VENV_BIN)/python
VENV_PIP := $(VENV_BIN)/pip
ACTIVATE := source $(VENV_BIN)/activate

# Git configuration
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")

# ============================================================================
# HELP (self-documenting Makefile)
# ============================================================================
# This automatically generates help from comments with '##'
# Try it: make help
help: ## Show this help message
	@echo "════════════════════════════════════════════════════════════════"
	@echo "  API Security Scanner - Development Workflow"
	@echo "════════════════════════════════════════════════════════════════"
	@echo ""
	@echo "📋 WORKFLOW COMMANDS (use these in order):"
	@echo "  make setup          - Initial project setup (run once)"
	@echo "  make sync           - Sync with remote & update deps (daily)"
	@echo "  make dev            - Quick dev checks (use frequently)"
	@echo "  make precommit      - Full checks before commit"
	@echo "  make commit         - Commit changes (MSG='your message')"
	@echo "  make push           - Push to remote (with safety checks)"
	@echo ""
	@echo "🔧 UTILITY COMMANDS:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		grep -v "WORKFLOW COMMANDS" | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "📖 For detailed workflow guide, see: docs/DEVELOPMENT_WORKFLOW.md"
	@echo "════════════════════════════════════════════════════════════════"

# ============================================================================
# PHASE 1: PROJECT SETUP
# ============================================================================
# Run this once when you first clone the project or want a fresh start.
# Creates virtual environment, installs dependencies, sets up config files.
# ============================================================================

.venv-created:
	@echo "🔧 Creating virtual environment..."
	$(PYTHON) -m venv $(VENV)
	@touch .venv-created
	@echo "✓ Virtual environment created at $(VENV)"

setup: .venv-created ## 🚀 Initial project setup (run once after clone)
	@echo ""
	@echo "════════════════════════════════════════"
	@echo "🚀 Setting up project..."
	@echo "════════════════════════════════════════"
	@echo ""
	@echo "📦 Installing dependencies..."
	@$(VENV_PIP) install --upgrade pip
	@$(VENV_PIP) install -r requirements.txt
	@$(VENV_PIP) install -r requirements-dev.txt
	@$(VENV_PIP) install -e .
	@touch .deps-prod-installed .deps-dev-installed
	@echo "✓ Dependencies installed"
	@echo ""
	@if [ -f .env.example ] && [ ! -f .env ]; then \
		echo "📝 Creating .env from .env.example..."; \
		cp .env.example .env; \
		echo "✓ .env created (please review and update)"; \
	else \
		echo "ℹ️  .env already exists or .env.example not found"; \
	fi
	@echo ""
	@echo "════════════════════════════════════════"
	@echo "✓ Setup complete!"
	@echo "════════════════════════════════════════"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Activate venv: source $(VENV_BIN)/activate"
	@echo "  2. Start coding!"
	@echo "  3. Run 'make dev' to test your changes"
	@echo ""

# ============================================================================
# PHASE 2: DAILY SYNC
# ============================================================================
# Run this at the start of each day or before starting new work.
# Pulls latest changes and updates dependencies if needed.
# ============================================================================

sync: ## 🔄 Sync with remote and update dependencies (run daily)
	@echo ""
	@echo "════════════════════════════════════════"
	@echo "🔄 Syncing with remote..."
	@echo "════════════════════════════════════════"
	@echo ""
	@echo "📥 Pulling latest changes..."
	@git pull --rebase origin $(GIT_BRANCH) || (echo "⚠️  Pull failed - resolve conflicts manually" && exit 1)
	@echo "✓ Code synced"
	@echo ""
	@echo "📦 Checking dependencies..."
	@$(MAKE) --no-print-directory .deps-dev-installed
	@echo ""
	@echo "📊 Current status:"
	@git status --short
	@echo ""
	@echo "════════════════════════════════════════"
	@echo "✓ Sync complete! Ready to code."
	@echo "════════════════════════════════════════"
	@echo ""

# ============================================================================
# DEPENDENCY INSTALLATION (with smart caching via marker files)
# ============================================================================
# These targets use "marker files" to avoid reinstalling dependencies
# unnecessarily. Make checks file timestamps to determine if reinstall is needed.
#
# How it works:
#   1. Make checks if marker file (.deps-*-installed) exists
#   2. If not, or if requirements.txt is newer → runs pip install
#   3. If marker exists and is newer than requirements → skips install
#
# This makes repeated 'make test' commands much faster!
#
# Example timeline:
#   First run:  make test → installs deps (30 sec) → runs tests
#   Second run: make test → skips install (0 sec) → runs tests
#   After editing requirements.txt: make test → reinstalls (30 sec) → runs tests
# ============================================================================

.deps-prod-installed: requirements.txt .venv-created
	@echo "📦 Installing production dependencies..."
	@echo "   (This only runs when requirements.txt changes)"
	@$(VENV_PIP) install -r requirements.txt
	@touch .deps-prod-installed
	@echo "✓ Production dependencies installed"

.deps-dev-installed: requirements-dev.txt .deps-prod-installed
	@echo "📦 Installing development dependencies..."
	@echo "   (This only runs when requirements-dev.txt changes)"
	@$(VENV_PIP) install -r requirements-dev.txt
	@$(VENV_PIP) install -e .
	@touch .deps-dev-installed
	@echo "✓ Development dependencies installed"

# Convenience targets (these just trigger the marker file targets)
install: .deps-prod-installed ## Install production dependencies (cached)

install-dev: .deps-dev-installed ## Install development dependencies (cached)

# ============================================================================
# PHASE 3: DEVELOPMENT LOOP
# ============================================================================
# Run this frequently during development for quick feedback.
# Lighter than full CI - skips some slower checks.
# ============================================================================

dev: .deps-dev-installed ## 🔨 Quick development checks (use frequently)
	@echo ""
	@echo "════════════════════════════════════════"
	@echo "🔨 Running development checks..."
	@echo "════════════════════════════════════════"
	@echo ""
	@echo "1️⃣  Formatting code..."
	@$(VENV_BIN)/ruff format src/ tests/
	@echo "✓ Code formatted"
	@echo ""
	@echo "2️⃣  Running linter..."
	@$(VENV_BIN)/ruff check --fix src/ tests/
	@echo "✓ Linting passed"
	@echo ""
	@echo "3️⃣  Running tests..."
	@$(VENV_BIN)/pytest --no-cov -q
	@echo "✓ Tests passed"
	@echo ""
	@echo "════════════════════════════════════════"
	@echo "✓ Development checks passed!"
	@echo "════════════════════════════════════════"
	@echo ""

# ============================================================================
# PHASE 4: PRE-COMMIT CHECKS
# ============================================================================
# Run this before committing to ensure everything is production-ready.
# Includes full CI pipeline + dependency locking.
# ============================================================================

precommit: ci ## 🎯 Full precommit checks (run before committing)
	@echo ""
	@echo "🔒 Locking dependencies..."
	@$(VENV_PIP) freeze > requirements-lock.txt
	@echo "✓ Dependencies locked to requirements-lock.txt"
	@echo ""
	@echo "📊 Files changed:"
	@git status --short
	@echo ""
	@echo "════════════════════════════════════════"
	@echo "✓ Precommit checks complete!"
	@echo "✓ Ready to commit"
	@echo "════════════════════════════════════════"
	@echo ""
	@echo "Next: make commit MSG='your commit message'"
	@echo ""

# ============================================================================
# PHASE 5: COMMIT & PUSH
# ============================================================================
# Git workflow automation with safety checks.
# ============================================================================

status: ## 📊 Show git status
	@git status

commit: ## 💾 Commit changes (usage: make commit MSG="your message")
	@if [ -z "$(MSG)" ]; then \
		echo "❌ Error: Commit message required"; \
		echo "Usage: make commit MSG='feat: add new feature'"; \
		exit 1; \
	fi
	@echo ""
	@echo "════════════════════════════════════════"
	@echo "💾 Committing changes..."
	@echo "════════════════════════════════════════"
	@echo ""
	@echo "📝 Commit message: $(MSG)"
	@echo ""
	@echo "📊 Files to commit:"
	@git status --short
	@echo ""
	@git add -A
	@git commit -m "$(MSG)"
	@echo ""
	@echo "✓ Changes committed"
	@echo ""
	@echo "Next: make push"
	@echo ""

push: ## 🚀 Push to remote (with safety checks)
	@echo ""
	@echo "════════════════════════════════════════"
	@echo "🚀 Pushing to remote..."
	@echo "════════════════════════════════════════"
	@echo ""
	@echo "🔄 Syncing with remote first..."
	@git pull --rebase origin $(GIT_BRANCH) || (echo "" && echo "⚠️  CONFLICT DETECTED!" && echo "" && echo "Please resolve conflicts manually:" && echo "  1. Fix conflicts in affected files" && echo "  2. git add <resolved-files>" && echo "  3. git rebase --continue" && echo "  4. make push (try again)" && echo "" && exit 1)
	@echo "✓ Synced with remote"
	@echo ""
	@echo "📤 Pushing to origin/$(GIT_BRANCH)..."
	@git push origin $(GIT_BRANCH)
	@echo ""
	@echo "════════════════════════════════════════"
	@echo "✓ Successfully pushed to remote!"
	@echo "════════════════════════════════════════"
	@echo ""

# ============================================================================
# TESTING (automatically ensures dev dependencies are installed)
# ============================================================================
# All test targets depend on .deps-dev-installed, which means:
#   - Dependencies are automatically installed if needed
#   - Installation is skipped if dependencies are already up-to-date
#   - You never have to remember to run 'make install-dev' first!
# ============================================================================

test: .deps-dev-installed ## Run tests with coverage
	@$(VENV_BIN)/pytest

test-unit: .deps-dev-installed ## Run unit tests only
	@$(VENV_BIN)/pytest tests/unit -m unit

test-integration: .deps-dev-installed ## Run integration tests only
	@$(VENV_BIN)/pytest tests/integration -m integration

test-verbose: .deps-dev-installed ## Run tests with verbose output
	@$(VENV_BIN)/pytest -v

test-coverage: .deps-dev-installed ## Run tests with HTML coverage report
	@$(VENV_BIN)/pytest --cov=src/api_security_scanner --cov-report=html --cov-report=term

# ============================================================================
# CODE QUALITY CHECKS
# ============================================================================

check: .deps-dev-installed ## Run tests and linting (fast check before commit)
	@echo "Running tests..."
	@$(VENV_BIN)/pytest
	@echo "✓ Tests passed!"
	@echo "Running linting..."
	@$(VENV_BIN)/ruff check src/ tests/
	@echo "Running type checks..."
	@$(VENV_BIN)/mypy src/
	@echo "✓ All checks passed!"

lint: .deps-dev-installed ## Run linting and type checks
	@$(VENV_BIN)/ruff check src/ tests/
	@$(VENV_BIN)/mypy src/

format: .deps-dev-installed ## Format code with ruff
	@$(VENV_BIN)/ruff format src/ tests/
	@$(VENV_BIN)/ruff check --fix src/ tests/

security-check: .deps-dev-installed ## Run security linting
	@$(VENV_BIN)/bandit -r src/ -c pyproject.toml

quality: .deps-dev-installed ## Run all quality checks (format, lint, type check, security)
	@echo "Running formatter..."
	@$(VENV_BIN)/ruff format src/ tests/
	@echo "Running linter..."
	@$(VENV_BIN)/ruff check --fix src/ tests/
	@echo "Running type checker..."
	@$(VENV_BIN)/mypy src/
	@echo "Running security checks..."
	@$(VENV_BIN)/bandit -r src/ -c pyproject.toml
	@echo "All quality checks passed!"

# ============================================================================
# CI/CD PIPELINE
# ============================================================================
# This target runs all checks that should pass before committing code.
# It's designed to catch issues early, before they reach CI/CD servers.
#
# Execution order:
#   1. clean          → Remove old artifacts
#   2. .deps-dev-installed → Ensure dependencies are current
#   3. format         → Auto-format code
#   4. lint           → Check code quality
#   5. test           → Run all tests
#   6. security-check → Scan for security issues
#
# If ANY step fails, the pipeline stops immediately.
# ============================================================================

ci: clean .deps-dev-installed format lint test security-check ## Run full CI pipeline
	@echo ""
	@echo "════════════════════════════════════════"
	@echo "✓ CI Pipeline Complete!"
	@echo "✓ Code is ready to commit"
	@echo "════════════════════════════════════════"

# ============================================================================
# CLEANUP
# ============================================================================
# Removes all generated files including:
#   - Python cache files (__pycache__, *.pyc)
#   - Test artifacts (.pytest_cache, .coverage, htmlcov)
#   - Build artifacts (dist, build, *.egg-info)
#   - Tool caches (.mypy_cache, .ruff_cache)
#   - Marker files (.deps-*-installed) ← Forces fresh install next time
# Note: Does NOT remove .venv (use 'make clean-all' for that)
# ============================================================================

clean: ## Clean up generated files (keeps .venv)
	@echo "🧹 Cleaning up..."
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@rm -rf .pytest_cache .coverage htmlcov dist build
	@rm -rf .mypy_cache .ruff_cache
	@rm -f .deps-prod-installed .deps-dev-installed
	@echo "✓ Cleanup complete"

clean-all: clean ## Clean everything including .venv (fresh start)
	@echo "🧹 Removing virtual environment..."
	@rm -rf $(VENV) .venv-created
	@echo "✓ Complete cleanup done"
	@echo ""
	@echo "Run 'make setup' to start fresh"

# ============================================================================
# RUN
# ============================================================================

run: ## Run the scanner (requires installation)
	@echo "Usage: api-scanner scan <url>"
	@echo "Example: api-scanner scan https://api.example.com"
