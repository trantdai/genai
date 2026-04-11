.PHONY: help install install-dev test lint format clean run security-check

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	pip install -r requirements.txt

install-dev: ## Install development dependencies
	pip install -r requirements.txt -r requirements-dev.txt
	pip install -e .

test: ## Run tests with coverage
	pytest

test-unit: ## Run unit tests only
	pytest tests/unit -m unit

test-integration: ## Run integration tests only
	pytest tests/integration -m integration

test-verbose: ## Run tests with verbose output
	pytest -v

test-coverage: ## Run tests with HTML coverage report
	pytest --cov=src/api_security_scanner --cov-report=html --cov-report=term

lint: ## Run linting and type checks
	ruff check src/ tests/
	mypy src/

format: ## Format code with ruff
	ruff format src/ tests/
	ruff check --fix src/ tests/

security-check: ## Run security linting
	bandit -r src/ -c pyproject.toml

quality: ## Run all quality checks (format, lint, type check, security)
	@echo "Running formatter..."
	@ruff format src/ tests/
	@echo "Running linter..."
	@ruff check --fix src/ tests/
	@echo "Running type checker..."
	@mypy src/
	@echo "Running security checks..."
	@bandit -r src/ -c pyproject.toml
	@echo "All quality checks passed!"

clean: ## Clean up generated files
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache .coverage htmlcov dist build
	rm -rf .mypy_cache .ruff_cache

run: ## Run the scanner (requires installation)
	@echo "Usage: api-scanner scan <url>"
	@echo "Example: api-scanner scan https://api.example.com"

.DEFAULT_GOAL := help
