# CLAUDE.md - Python Project Guide

## Project Overview

This is a **Python project** using modern development practices and tools. The codebase follows strict standards for maintainability, security, and performance.

### 🏗️ Architecture
- **Layout**: [`src-layout`](https://packaging.python.org/en/latest/discussions/src-layout-vs-flat-layout/) pattern for clean package structure
- **Python Version**: 3.13+ (modern Python features enabled)
- **Type System**: Full type hints required for all functions and classes
- **Async Support**: [`asyncio`](https://docs.python.org/3/library/asyncio.html) and [`async`/`await`](https://docs.python.org/3/reference/compound_stmts.html#async-def) patterns

### 🧰 Tech Stack
- **Formatter**: [`Black`](https://black.readthedocs.io/) (100-character line length)
- **Linter**: [`Ruff`](https://docs.astral.sh/ruff/) (replaces flake8, pylint, isort)
- **Type Checker**: [`mypy`](https://mypy.readthedocs.io/) (strict mode enabled)
- **Testing**: [`pytest`](https://docs.pytest.org/) with [`pytest-mock`](https://pytest-mock.readthedocs.io/)
- **Data Validation**: [`Pydantic`](https://docs.pydantic.dev/) v2+ for all data models
- **Package Manager**: [`uv`](https://docs.astral.sh/uv/) or [`pip-tools`](https://pip-tools.readthedocs.io/) for dependency management

## 📏 Development Standards

### Code Style Requirements
```python
# ✅ REQUIRED: Type hints for all functions
def process_data(items: list[dict[str, Any]], validate: bool = True) -> ProcessedData:
    """Process input data with optional validation."""
    pass

# ✅ REQUIRED: Pydantic models for data structures
class UserModel(BaseModel):
    id: int
    name: str
    email: EmailStr
    created_at: datetime = Field(default_factory=datetime.now)

# ✅ REQUIRED: Async/await for I/O operations
async def fetch_user(user_id: int) -> UserModel:
    """Fetch user data asynchronously."""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"/users/{user_id}")
        return UserModel.model_validate(response.json())
```

### Formatting & Linting
- **Black**: 100-character line length, automatic formatting
- **Ruff**: Replaces isort, flake8, pylint - handles imports and linting
- **Pre-commit hooks**: Automatic formatting and validation on commit

### Documentation Requirements
```python
def complex_function(data: list[dict[str, Any]], options: ProcessingOptions) -> Result:
    """Process complex data with configurable options.

    Args:
        data: List of dictionaries containing raw input data
        options: Configuration object for processing behavior

    Returns:
        Processed result with validation and metadata

    Raises:
        ValidationError: When input data fails validation
        ProcessingError: When processing logic encounters errors

    Example:
        >>> options = ProcessingOptions(validate=True, timeout=30)
        >>> result = complex_function(raw_data, options)
        >>> print(result.success_count)
        42
    """
```

## 🧪 Testing Requirements

### Framework Standards
```python
# ✅ Use pytest exclusively (never unittest)
import pytest
from unittest.mock import AsyncMock  # ❌ FORBIDDEN
from pytest_mock import MockerFixture  # ✅ REQUIRED

# ✅ Async test pattern
@pytest.mark.asyncio
async def test_async_function(mocker: MockerFixture):
    """Test async function with proper mocking."""
    mock_client = mocker.AsyncMock()
    mock_client.get.return_value.json.return_value = {"id": 1, "name": "Test"}

    result = await fetch_user(1)
    assert result.name == "Test"
```

### Coverage Requirements
- **Minimum**: 80% code coverage required
- **Target**: 90%+ for critical business logic
- **Command**: `pytest --cov=src --cov-report=html --cov-fail-under=80`

### Test Organization
```
tests/
├── conftest.py                 # Shared fixtures
├── unit/                       # Fast, isolated tests
│   ├── test_models.py         # Pydantic model tests
│   ├── test_services.py       # Business logic tests
│   └── test_utils.py          # Utility function tests
├── integration/                # Tests with external dependencies
│   ├── test_database.py       # Database integration
│   └── test_api_clients.py    # External API integration
└── e2e/                       # End-to-end scenarios
    └── test_workflows.py      # Complete user workflows
```

### Test Naming Convention
```python
# Pattern: test_[unit_under_test]_[scenario]_[expected_outcome]
def test_user_creation_with_valid_data_succeeds():
    """Test that user creation succeeds with valid input data."""
    pass

def test_user_creation_with_invalid_email_raises_validation_error():
    """Test that invalid email raises ValidationError during user creation."""
    pass
```

## 🔒 Security Standards

### Input Validation
```python
# ✅ REQUIRED: Pydantic validation at boundaries
class APIRequest(BaseModel):
    user_id: int = Field(gt=0, description="Must be positive integer")
    email: EmailStr = Field(description="Must be valid email address")
    data: dict[str, Any] = Field(max_items=100, description="Limited size dict")

# ✅ REQUIRED: Sanitize file paths
def safe_file_operation(filename: str) -> Path:
    """Safely handle file operations preventing path traversal."""
    safe_filename = secure_filename(filename)  # Remove dangerous chars
    base_path = Path("/app/uploads")
    full_path = (base_path / safe_filename).resolve()

    # Prevent path traversal
    if not str(full_path).startswith(str(base_path)):
        raise SecurityError("Path traversal attempt detected")

    return full_path
```

### Secret Management
```python
# ✅ REQUIRED: Environment variables for secrets
import os
from pydantic import BaseSettings, SecretStr

class Settings(BaseSettings):
    database_url: SecretStr
    api_key: SecretStr
    jwt_secret: SecretStr

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# ❌ FORBIDDEN: Hardcoded secrets
DATABASE_URL = "postgresql://user:password@localhost/db"  # NEVER DO THIS
```

### SQL Injection Prevention
```python
# ✅ REQUIRED: Parameterized queries only
async def get_user_safe(user_id: int) -> User:
    """Safe database query with parameters."""
    query = "SELECT * FROM users WHERE id = $1"
    result = await database.fetch_one(query, user_id)
    return User.model_validate(dict(result))

# ❌ FORBIDDEN: String concatenation
async def get_user_unsafe(user_id: int) -> User:
    """DANGEROUS - SQL injection vulnerable."""
    query = f"SELECT * FROM users WHERE id = {user_id}"  # NEVER DO THIS
    result = await database.fetch_one(query)
    return User.model_validate(dict(result))
```

### Error Handling
```python
# ✅ REQUIRED: Safe error responses
try:
    result = await risky_operation()
except DatabaseError as e:
    logger.error("Database operation failed", extra={"error": str(e), "user_id": user_id})
    # ✅ Generic error message for API response
    raise HTTPException(status_code=500, detail="Internal server error")
    # ❌ FORBIDDEN: Expose internal details
    # raise HTTPException(status_code=500, detail=str(e))
```

## 📁 Project Structure

### Standard Layout
```
my-python-project/
├── src/
│   └── my_package/
│       ├── __init__.py
│       ├── main.py              # Application entry point
│       ├── models/              # Pydantic models
│       │   ├── __init__.py
│       │   ├── user.py
│       │   └── common.py
│       ├── services/            # Business logic
│       │   ├── __init__.py
│       │   ├── user_service.py
│       │   └── auth_service.py
│       ├── repositories/        # Data access layer
│       │   ├── __init__.py
│       │   └── user_repository.py
│       ├── utils/              # Utility functions
│       │   ├── __init__.py
│       │   └── helpers.py
│       └── config.py           # Configuration management
├── tests/                      # Mirror src structure
├── docs/                       # Documentation
├── scripts/                    # Development scripts
├── pyproject.toml             # Project configuration
├── requirements.txt           # Dependencies (if using pip)
├── requirements-dev.txt       # Development dependencies
├── .env.example              # Environment template
├── .gitignore                # Git ignore rules
├── README.md                 # Project documentation
└── Dockerfile                # Container configuration
```

### File Organization Rules
- **Models**: [`src/package/models/`](src/package/models/) - Pydantic models and data structures
- **Services**: [`src/package/services/`](src/package/services/) - Business logic and workflows
- **Repositories**: [`src/package/repositories/`](src/package/repositories/) - Data access layer
- **Utils**: [`src/package/utils/`](src/package/utils/) - Pure functions and helpers
- **Config**: [`src/package/config.py`](src/package/config.py) - Centralized configuration

### Configuration Files
- **[`pyproject.toml`](pyproject.toml)**: Primary project configuration (tools, dependencies, metadata)
- **[`.env`](.env)**: Environment variables (never commit to version control)
- **[`.env.example`](.env.example)**: Template for environment variables
- **[`requirements.txt`](requirements.txt)**: Pinned production dependencies
- **[`requirements-dev.txt`](requirements-dev.txt)**: Development-only dependencies

## 🔧 Common Commands

### Development Setup
```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### Code Quality
```bash
# Format code (run before commit)
black src tests --line-length 100

# Lint and fix imports/style
ruff check src tests --fix

# Type checking
mypy src

# Run all quality checks
black src tests --check && ruff check src tests && mypy src
```

### Testing
```bash
# Run all tests with coverage
pytest --cov=src --cov-report=html --cov-report=term

# Run specific test file
pytest tests/unit/test_models.py -v

# Run tests matching pattern
pytest -k "test_user" -v

# Run tests with debugging
pytest --pdb -s tests/unit/test_services.py::test_specific_function
```

### Security Scanning
```bash
# Scan for security vulnerabilities
pip-audit

# Check for secrets in code
bandit -r src/

# Scan dependencies for known issues
safety check

# Comprehensive security check
pip-audit && bandit -r src/ && safety check
```

### Database Operations (if applicable)
```bash
# Run database migrations
alembic upgrade head

# Create new migration
alembic revision --autogenerate -m "Add user table"

# Reset database (development only)
alembic downgrade base && alembic upgrade head
```

## 🎯 Key Principles

### Code Quality
- **DRY (Don't Repeat Yourself)**: Extract common logic into reusable functions
- **SOLID Principles**: Single responsibility, open/closed, Liskov substitution, interface segregation, dependency inversion
- **Type Safety**: Use type hints everywhere, enable [`mypy`](https://mypy.readthedocs.io/) strict mode
- **Readability**: Code should be self-documenting with clear variable names

### Error Handling
```python
# ✅ REQUIRED: Specific exception handling
try:
    result = await database_operation()
except DatabaseConnectionError as e:
    logger.error("Database connection failed", exc_info=True)
    raise ServiceUnavailableError("Database temporarily unavailable") from e
except ValidationError as e:
    logger.warning("Invalid input data", extra={"errors": e.errors()})
    raise BadRequestError("Invalid request data") from e

# ❌ FORBIDDEN: Bare except clauses
try:
    risky_operation()
except:  # NEVER DO THIS
    pass
```

### Performance
- **Async I/O**: Use [`asyncio`](https://docs.python.org/3/library/asyncio.html) for database, HTTP, file operations
- **Connection Pooling**: Reuse database connections and HTTP clients
- **Caching**: Cache expensive computations and external API calls
- **Profiling**: Use [`cProfile`](https://docs.python.org/3/library/profile.html) and [`memory_profiler`](https://pypi.org/project/memory-profiler/) for optimization

### Logging
```python
import structlog

logger = structlog.get_logger()

# ✅ REQUIRED: Structured logging
logger.info(
    "User created successfully",
    user_id=user.id,
    email=user.email,
    registration_type="email_signup"
)

# ✅ REQUIRED: Error context
logger.error(
    "Payment processing failed",
    user_id=user_id,
    payment_amount=amount,
    error_code=e.code,
    exc_info=True  # Include stack trace
)
```

### Dependency Management
```python
# pyproject.toml - Use minimum version constraints
[project]
dependencies = [
    "fastapi>=0.104.0",
    "pydantic>=2.5.0",
    "httpx>=0.25.0",
    "structlog>=23.2.0"
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "pytest-mock>=3.12.0",
    "black>=23.10.0",
    "ruff>=0.1.0",
    "mypy>=1.6.0"
]
```

## 🚦 Development Workflow

### Before Starting Work
1. **Activate virtual environment**: `source .venv/bin/activate`
2. **Pull latest changes**: `git pull origin main`
3. **Install/update dependencies**: `pip install -r requirements-dev.txt`
4. **Run tests**: `pytest` (ensure starting from clean state)

### During Development
1. **Write tests first** (TDD approach recommended)
2. **Run tests frequently**: `pytest -x` (fail fast)
3. **Check types**: `mypy src` before committing
4. **Format code**: `black src tests` before committing

### Before Committing
1. **Run full test suite**: `pytest --cov=src --cov-fail-under=80`
2. **Check code quality**: `black src tests --check && ruff check src tests`
3. **Security scan**: `bandit -r src/ && pip-audit`
4. **Verify types**: `mypy src`

### Pre-commit Hook (automatic)
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.10.1
    hooks:
      - id: black
        args: [--line-length=100]

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.5
    hooks:
      - id: ruff
        args: [--fix]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.6.1
    hooks:
      - id: mypy
```

---

## 📋 Quick Checklist

Before considering any task complete, ensure:

- [ ] **Type hints** on all functions and class methods
- [ ] **Docstrings** using Google style for public APIs
- [ ] **Tests** written and passing (80%+ coverage)
- [ ] **Security** review completed (no hardcoded secrets)
- [ ] **Error handling** implemented with specific exceptions
- [ ] **Logging** added for important operations
- [ ] **Code formatting** applied (`black`, `ruff`)
- [ ] **Type checking** passes (`mypy`)
- [ ] **Dependencies** use minimum version constraints (`>=`)
- [ ] **Documentation** updated in README if public API changes

---

*This guide ensures consistent, secure, and maintainable Python code. When in doubt, prioritize code clarity, security, and test coverage.*
