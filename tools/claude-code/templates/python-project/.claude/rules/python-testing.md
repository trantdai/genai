# Python Testing Rules

## Overview
This document defines comprehensive testing standards for Python projects. All code must have adequate test coverage and follow these testing practices to ensure reliability and maintainability.

## Testing Framework Requirements

### Pytest Exclusively
- **Mandatory**: Use pytest for all testing (no unittest module)
- **Rationale**: Better fixtures, cleaner syntax, superior plugin ecosystem
- **Configuration**: Must be configured in `pyproject.toml`

```toml
[tool.pytest.ini_options]
minversion = "7.0"
addopts = [
    "--strict-markers",
    "--strict-config",
    "--cov=src",
    "--cov-report=term-missing",
    "--cov-report=html:htmlcov",
    "--cov-report=xml",
    "--cov-fail-under=80",
]
testpaths = ["tests"]
markers = [
    "unit: Unit tests",
    "integration: Integration tests",
    "e2e: End-to-end tests",
    "slow: Slow running tests",
]
```

### Pytest-Mock for Mocking
- **Mandatory**: Use pytest-mock plugin (never unittest.mock directly)
- **Rationale**: Automatic cleanup, better pytest integration
- **Installation**: Include in test dependencies

```toml
[tool.poetry.group.test.dependencies]
pytest = ">=7.4.0"
pytest-mock = ">=3.11.0"
pytest-asyncio = ">=0.21.0"
pytest-cov = ">=4.1.0"
```

## Test Organization and Naming

### Directory Structure
```
tests/
├── __init__.py
├── conftest.py          # Shared fixtures
├── unit/                # Unit tests
│   ├── __init__.py
│   ├── test_models.py
│   ├── test_services.py
│   └── test_utils.py
├── integration/         # Integration tests
│   ├── __init__.py
│   ├── test_database.py
│   └── test_api.py
└── e2e/                # End-to-end tests
    ├── __init__.py
    └── test_workflows.py
```

### Test File Naming
✅ **DO**: Follow pytest naming conventions
```
test_*.py           # Prefix with 'test_'
*_test.py          # Suffix with '_test'
test_user_service.py    # Mirror source structure
test_models/test_user.py  # Group related tests
```

❌ **DON'T**: Use non-standard naming
```
user_tests.py      # Wrong suffix
tests_for_user.py  # Non-standard format
UserTest.py        # Wrong case
```

### Test Function Naming
✅ **DO**: Descriptive test names
```python
def test_user_creation_with_valid_email():
    """Test that user creation succeeds with valid email."""
    pass

def test_user_creation_fails_with_invalid_email():
    """Test that user creation fails with invalid email format."""
    pass

def test_user_service_returns_none_when_user_not_found():
    """Test that UserService returns None for non-existent user."""
    pass
```

❌ **DON'T**: Vague or unclear names
```python
def test_user():          # Too vague
def test_creation():      # Missing context
def test_1():            # Non-descriptive
def testUser():          # Wrong naming convention
```

## Coverage Requirements

### Minimum Coverage Thresholds
- **Overall Coverage**: 80% minimum (enforced by CI)
- **New Code**: 90% minimum coverage
- **Critical Paths**: 95% minimum coverage (authentication, payment, data integrity)

### Coverage Configuration
```toml
[tool.coverage.run]
source = ["src"]
omit = [
    "*/tests/*",
    "*/venv/*",
    "*/.venv/*",
    "*/migrations/*",
    "*/settings/*",
    "*/manage.py",
]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise AssertionError",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
    "if TYPE_CHECKING:",
]
```

### Coverage Reporting
```bash
# Generate coverage report
pytest --cov=src --cov-report=html --cov-report=term-missing

# Check coverage threshold
pytest --cov=src --cov-fail-under=80
```

## Fixture Usage Patterns

### Shared Fixtures in conftest.py
```python
# tests/conftest.py
import pytest
from unittest.mock import AsyncMock

@pytest.fixture
def sample_user_data():
    """Sample user data for testing."""
    return {
        "id": "user_123",
        "email": "test@example.com",
        "name": "Test User",
        "created_at": "2024-01-01T00:00:00Z"
    }

@pytest.fixture
def mock_database_session(mocker):
    """Mock database session."""
    session = mocker.Mock()
    session.commit = mocker.Mock()
    session.rollback = mocker.Mock()
    session.close = mocker.Mock()
    return session

@pytest.fixture
async def async_client():
    """Async HTTP client for testing."""
    async with httpx.AsyncClient() as client:
        yield client
```

### Scoped Fixtures
```python
@pytest.fixture(scope="session")
def database_url():
    """Database URL for test session."""
    return "sqlite:///:memory:"

@pytest.fixture(scope="module")
def test_database(database_url):
    """Test database that persists for module."""
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)

@pytest.fixture(scope="function")  # Default scope
def clean_database(test_database):
    """Clean database for each test function."""
    # Setup
    yield test_database
    # Teardown - clean tables
    for table in reversed(Base.metadata.sorted_tables):
        test_database.execute(table.delete())
```

### Parameterized Fixtures
```python
@pytest.fixture(params=["sqlite", "postgresql", "mysql"])
def database_type(request):
    """Test against multiple database types."""
    return request.param

@pytest.mark.parametrize("user_data,expected_valid", [
    ({"email": "valid@test.com", "name": "Valid User"}, True),
    ({"email": "invalid-email", "name": "Invalid User"}, False),
    ({"email": "", "name": "Empty Email"}, False),
])
def test_user_validation(user_data, expected_valid):
    """Test user validation with multiple scenarios."""
    result = validate_user_data(user_data)
    assert result.is_valid == expected_valid
```

## Mocking Best Practices

### Using pytest-mock
✅ **DO**: Use pytest-mock mocker fixture
```python
def test_user_service_calls_database(mocker, sample_user_data):
    """Test that UserService properly calls database methods."""
    # Mock the database call
    mock_db = mocker.patch('src.services.user_service.database')
    mock_db.get_user.return_value = sample_user_data

    # Execute the code under test
    service = UserService()
    result = service.get_user("user_123")

    # Verify the interaction
    mock_db.get_user.assert_called_once_with("user_123")
    assert result == sample_user_data

def test_external_api_call_with_timeout(mocker):
    """Test external API call with timeout handling."""
    mock_requests = mocker.patch('src.services.api_client.requests')
    mock_requests.get.side_effect = requests.Timeout("Request timeout")

    client = ApiClient()

    with pytest.raises(ApiTimeoutError):
        client.fetch_user_data("user_123")

    mock_requests.get.assert_called_once()
```

❌ **DON'T**: Use unittest.mock directly
```python
import unittest.mock  # Avoid this

def test_user_service():
    with unittest.mock.patch('src.services.database') as mock_db:  # Don't do this
        # Test code here
        pass
```

### Mock Return Values and Side Effects
```python
def test_database_connection_retry(mocker):
    """Test database connection with retry logic."""
    mock_connect = mocker.patch('src.database.create_connection')

    # First call fails, second succeeds
    mock_connect.side_effect = [
        ConnectionError("Connection failed"),
        mocker.Mock(name="successful_connection")
    ]

    db = Database()
    connection = db.get_connection_with_retry()

    assert mock_connect.call_count == 2
    assert connection is not None

def test_async_service_method(mocker):
    """Test async method with mock."""
    mock_async_method = mocker.patch(
        'src.services.async_service.external_api_call',
        new_callable=AsyncMock
    )
    mock_async_method.return_value = {"status": "success"}

    service = AsyncService()
    result = await service.process_data()

    mock_async_method.assert_called_once()
    assert result["status"] == "success"
```

### Mock Configuration and Verification
```python
def test_service_configuration(mocker):
    """Test service configuration and method calls."""
    mock_logger = mocker.patch('src.services.user_service.logger')
    mock_cache = mocker.patch('src.services.user_service.cache')

    # Configure mock behavior
    mock_cache.get.return_value = None
    mock_cache.set.return_value = True

    service = UserService()
    service.get_user_with_cache("user_123")

    # Verify interactions
    mock_cache.get.assert_called_once_with("user:user_123")
    mock_cache.set.assert_called_once()
    mock_logger.info.assert_called()
```

## Async Testing with pytest-asyncio

### Configuration
```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"  # Automatically detect async tests
```

### Async Test Examples
```python
import pytest
import pytest_asyncio

@pytest_asyncio.fixture
async def async_database():
    """Async database fixture."""
    db = await create_async_database()
    yield db
    await db.close()

@pytest.mark.asyncio
async def test_async_user_creation(async_database, sample_user_data):
    """Test async user creation."""
    service = AsyncUserService(async_database)

    user = await service.create_user(sample_user_data)

    assert user.id is not None
    assert user.email == sample_user_data["email"]

@pytest.mark.asyncio
async def test_concurrent_operations():
    """Test concurrent async operations."""
    service = AsyncService()

    # Test multiple concurrent operations
    tasks = [
        service.process_item(f"item_{i}")
        for i in range(10)
    ]

    results = await asyncio.gather(*tasks)

    assert len(results) == 10
    assert all(result.success for result in results)
```

### Async Mocking
```python
@pytest.mark.asyncio
async def test_async_external_call(mocker):
    """Test async external service call."""
    mock_client = mocker.patch(
        'src.services.external_service.httpx.AsyncClient'
    )
    mock_response = mocker.Mock()
    mock_response.json.return_value = {"data": "test"}
    mock_client.return_value.__aenter__.return_value.get = AsyncMock(
        return_value=mock_response
    )

    service = ExternalService()
    result = await service.fetch_data("endpoint")

    assert result["data"] == "test"
```

## Integration Testing Guidelines

### Database Integration Tests
```python
@pytest.mark.integration
def test_user_repository_database_integration(test_database):
    """Test UserRepository with real database."""
    repo = UserRepository(test_database)

    # Create test data
    user_data = {
        "email": "integration@test.com",
        "name": "Integration Test User"
    }

    # Test creation
    user = repo.create(user_data)
    assert user.id is not None

    # Test retrieval
    retrieved_user = repo.get_by_id(user.id)
    assert retrieved_user.email == user_data["email"]

    # Test update
    repo.update(user.id, {"name": "Updated Name"})
    updated_user = repo.get_by_id(user.id)
    assert updated_user.name == "Updated Name"

    # Test deletion
    repo.delete(user.id)
    deleted_user = repo.get_by_id(user.id)
    assert deleted_user is None
```

### API Integration Tests
```python
@pytest.mark.integration
async def test_user_api_endpoints(async_client, test_database):
    """Test user API endpoints integration."""
    # Create user via API
    create_data = {
        "email": "api@test.com",
        "name": "API Test User"
    }

    response = await async_client.post("/users", json=create_data)
    assert response.status_code == 201

    user_data = response.json()
    user_id = user_data["id"]

    # Get user via API
    response = await async_client.get(f"/users/{user_id}")
    assert response.status_code == 200
    assert response.json()["email"] == create_data["email"]

    # Update user via API
    update_data = {"name": "Updated API User"}
    response = await async_client.put(f"/users/{user_id}", json=update_data)
    assert response.status_code == 200

    # Delete user via API
    response = await async_client.delete(f"/users/{user_id}")
    assert response.status_code == 204
```

## Test Data Management

### Factory Pattern for Test Data
```python
# tests/factories.py
import factory
from datetime import datetime
from src.models.user import User

class UserFactory(factory.Factory):
    class Meta:
        model = User

    id = factory.Sequence(lambda n: f"user_{n}")
    email = factory.LazyAttribute(lambda obj: f"{obj.id}@example.com")
    name = factory.Faker('name')
    created_at = factory.LazyFunction(datetime.utcnow)
    is_active = True

# Usage in tests
def test_user_service_with_factory():
    """Test using factory-generated data."""
    user = UserFactory()
    assert user.email.endswith("@example.com")
    assert user.is_active is True

def test_multiple_users():
    """Test with multiple generated users."""
    users = UserFactory.build_batch(5)
    assert len(users) == 5
    assert all(user.is_active for user in users)
```

### JSON Test Data Files
```python
# tests/data/sample_users.json
[
    {
        "id": "user_1",
        "email": "user1@example.com",
        "name": "First User",
        "role": "admin"
    },
    {
        "id": "user_2",
        "email": "user2@example.com",
        "name": "Second User",
        "role": "user"
    }
]

# Loading test data
@pytest.fixture
def sample_users():
    """Load sample users from JSON file."""
    with open("tests/data/sample_users.json") as f:
        return json.load(f)

def test_user_processing(sample_users):
    """Test user processing with loaded data."""
    processor = UserProcessor()
    results = processor.process_batch(sample_users)

    assert len(results) == len(sample_users)
    assert all(result.success for result in results)
```

## Error and Exception Testing

### Testing Expected Exceptions
```python
def test_user_service_raises_not_found():
    """Test that UserService raises NotFound for invalid ID."""
    service = UserService()

    with pytest.raises(UserNotFoundError) as exc_info:
        service.get_user("nonexistent_id")

    assert "nonexistent_id" in str(exc_info.value)
    assert exc_info.value.error_code == "USER_NOT_FOUND"

def test_validation_error_details():
    """Test detailed validation error information."""
    invalid_data = {"email": "invalid-email", "age": -5}

    with pytest.raises(ValidationError) as exc_info:
        validate_user_data(invalid_data)

    error = exc_info.value
    assert "email" in error.field_errors
    assert "age" in error.field_errors
    assert len(error.field_errors) == 2
```

### Testing Error Recovery
```python
def test_service_recovers_from_temporary_failure(mocker):
    """Test service recovery from temporary failures."""
    mock_external_service = mocker.patch('src.services.external_api')

    # First call fails, second succeeds
    mock_external_service.call.side_effect = [
        TemporaryServiceError("Service temporarily unavailable"),
        {"status": "success", "data": "result"}
    ]

    service = ResilientService()
    result = service.get_data_with_retry()

    assert result["status"] == "success"
    assert mock_external_service.call.call_count == 2
```

## Performance and Load Testing

### Performance Test Markers
```python
@pytest.mark.slow
@pytest.mark.performance
def test_bulk_user_processing_performance():
    """Test performance of bulk user processing."""
    import time

    users = UserFactory.build_batch(1000)
    processor = UserProcessor()

    start_time = time.time()
    results = processor.process_batch(users)
    end_time = time.time()

    processing_time = end_time - start_time

    assert len(results) == 1000
    assert processing_time < 5.0  # Should complete within 5 seconds
    assert all(result.success for result in results)

@pytest.mark.benchmark
def test_database_query_performance(benchmark, test_database):
    """Benchmark database query performance."""
    repo = UserRepository(test_database)

    # Setup test data
    for i in range(100):
        repo.create({"email": f"user_{i}@test.com", "name": f"User {i}"})

    # Benchmark the query
    result = benchmark(repo.get_all_active_users)

    assert len(result) == 100
```

## Test Execution and CI Integration

### Running Tests Locally
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test types
pytest -m unit                    # Unit tests only
pytest -m integration            # Integration tests only
pytest -m "not slow"             # Skip slow tests

# Run tests in parallel
pytest -n auto                   # Requires pytest-xdist

# Run tests with verbose output
pytest -v --tb=short
```

### CI/CD Configuration
```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.11, 3.12]

    steps:
    - uses: actions/checkout@v4

    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}

    - name: Install dependencies
      run: |
        pip install poetry
        poetry install --with test

    - name: Run tests
      run: |
        poetry run pytest --cov=src --cov-report=xml --cov-fail-under=80

    - name: Upload coverage reports
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
```

## Test Documentation

### Test Documentation Standards
```python
def test_complex_business_logic():
    """
    Test complex business logic for user subscription processing.

    This test verifies that:
    1. User subscription is properly validated
    2. Payment processing is initiated correctly
    3. User account is upgraded on successful payment
    4. Appropriate notifications are sent
    5. Rollback occurs on payment failure

    Test data includes edge cases:
    - Expired credit cards
    - Insufficient funds
    - Network timeouts
    """
    # Test implementation with clear comments
    pass
```

## References
- [Pytest Documentation](https://docs.pytest.org/)
- [pytest-mock Plugin](https://pytest-mock.readthedocs.io/)
- [pytest-asyncio Plugin](https://pytest-asyncio.readthedocs.io/)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)
- [Factory Boy Documentation](https://factoryboy.readthedocs.io/)
