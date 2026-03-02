.PHONY: help install install-dev test lint format clean docker-up docker-down run-api run-worker

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	pip install -r requirements.txt

install-dev: ## Install development dependencies
	pip install -r requirements.txt -r requirements-dev.txt

test: ## Run tests with coverage
	pytest

test-verbose: ## Run tests with verbose output
	pytest -v

test-coverage: ## Run tests with coverage report
	pytest --cov=claudeskills --cov-report=html --cov-report=term

lint: ## Run linting and type checks
	ruff check .
	mypy claudeskills

format: ## Format code with ruff
	ruff format .
	ruff check --fix .

clean: ## Clean up generated files
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache .coverage htmlcov dist build

docker-up: ## Start Docker services (Temporal + PostgreSQL)
	docker-compose up -d

docker-down: ## Stop Docker services
	docker-compose down

docker-logs: ## Show Docker logs
	docker-compose logs -f

run-api: ## Run the FastAPI server locally
	uvicorn claudeskills.api.main:app --reload --host 0.0.0.0 --port 8000

run-worker: ## Run the Temporal worker locally
	python -m claudeskills.worker.main

check-temporal: ## Check if Temporal server is ready
	@curl -s http://localhost:8233 > /dev/null && echo "Temporal is ready" || echo "Temporal is not ready"
