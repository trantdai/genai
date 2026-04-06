# Python Testing Rules

## Overview
Comprehensive testing standards for Python projects ensuring reliability and maintainability.

## Testing Framework Requirements

### Pytest Exclusively
- **Mandatory**: Use pytest for all testing (never unittest module)
- **Configuration**: Configure in `pyproject.toml` (see [pytest docs](https://docs.pytest.org/))

### Required Dependencies
```toml
[tool.poetry.group.test.dependencies]
pytest = ">=7.4.0"
pytest-mock = ">=3.11.0"  # Use instead of unittest.mock
pytest-asyncio = ">=0.21.0"
pytest-cov = ">=4.1.0"
```

## Test Organization

### Directory Structure
```
tests/
├── conftest.py          # Shared fixtures
├── unit/                # Unit tests
├── integration/         # Integration tests
└── e2e/                # End-to-end tests
```

### Naming Conventions
✅ **DO**: Follow pytest conventions
- Files: `test_*.py` or `*_test.py`
- Functions: `test_<descriptive_name>()`
- Classes: `Test<ClassName>`

❌ **DON'T**: Use non-standard naming
- `user_tests.py` (wrong suffix)
- `def testUser()` (wrong case)

## Coverage Requirements

### Minimum Thresholds
- **Overall**: 80% minimum (enforced by CI)
- **New Code**: 90% minimum
- **Critical Paths**: 95% minimum (auth, payment, data integrity)

### Coverage Configuration
```toml
[tool.coverage.run]
source = ["src"]
omit = ["*/tests/*", "*/venv/*", "*/.venv/*"]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
    "if TYPE_CHECKING:",
]
```

## Testing Best Practices

### Test Structure (AAA Pattern)
```python
def test_user_creation_with_valid_email():
    """Test that user creation succeeds with valid email."""
    # Arrange
    email = "test@example.com"
    name = "Test User"
    
    # Act
    user = create_user(name, email)
    
    # Assert
    assert user.email == email
    assert user.name == name
```

### Descriptive Test Names
✅ **DO**: Clear, descriptive names
```python
def test_user_service_returns_none_when_user_not_found():
    """Test that UserService returns None for non-existent user."""
    pass

def test_calculate_discount_raises_error_for_negative_price():
    """Test that negative prices raise ValueError."""
    pass
```

❌ **DON'T**: Vague names
```python
def test_user():          # Too vague
def test_1():            # Non-descriptive
```

## Fixture Usage

### Shared Fixtures (conftest.py)
```python
# tests/conftest.py
import pytest

@pytest.fixture
def sample_user_data():
    """Sample user data for testing."""
    return {
        "id": "user_123",
        "email": "test@example.com",
        "name": "Test User"
    }

@pytest.fixture
def mock_database_session(mocker):
    """Mock database session."""
    session = mocker.Mock()
    session.commit = mocker.Mock()
    session.rollback = mocker.Mock()
    return session
```

### Fixture Scopes
- `function` (default): Per test function
- `module`: Per test module
- `session`: Per test session

### Parameterized Fixtures
```python
@pytest.mark.parametrize("user_data,expected_valid", [
    ({"email": "valid@test.com", "name": "Valid"}, True),
    ({"email": "invalid", "name": "Invalid"}, False),
])
def test_user_validation(user_data, expected_valid):
    """Test user validation with multiple scenarios."""
    assert validate_user(user_data) == expected_valid
```

## Mocking with pytest-mock

✅ **DO**: Use pytest-mock mocker fixture
```python
def test_user_service_calls_database(mocker, sample_user_data):
    """Test that UserService properly calls database methods."""
    mock_db = mocker.patch('src.services.user_service.database')
    mock_db.get_user.return_value = sample_user_data
    
    service = UserService()
    result = service.get_user("user_123")
    
    mock_db.get_user.assert_called_once_with("user_123")
    assert result == sample_user_data
```

❌ **DON'T**: Use unittest.mock directly
```python
import unittest.mock  # Avoid this

def test_user_service():
    with unittest.mock.patch('src.services.database') as mock_db:  # Don't do this
        pass
```

## Async Testing

### Configuration
```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"  # Automatically detect async tests
```

### Async Test Example
```python
import pytest

@pytest.mark.asyncio
async def test_async_user_creation(async_database):
    """Test async user creation."""
    service = AsyncUserService(async_database)
    user = await service.create_user({"name": "Test", "email": "test@example.com"})
    
    assert user.id is not None
    assert user.email == "test@example.com"
```

## Exception Testing

✅ **DO**: Test expected exceptions
```python
def test_user_service_raises_not_found():
    """Test that UserService raises NotFound for invalid ID."""
    service = UserService()
    
    with pytest.raises(UserNotFoundError) as exc_info:
        service.get_user("nonexistent_id")
    
    assert "nonexistent_id" in str(exc_info.value)
```

## Integration Testing

### Database Integration
- Use real database (not mocks) for integration tests
- Clean database state between tests
- Test full CRUD operations

### API Integration
- Test actual HTTP endpoints
- Verify request/response formats
- Test error handling

## Test Execution

### Common Commands
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test types
pytest -m unit                    # Unit tests only
pytest -m integration            # Integration tests only
pytest -m "not slow"             # Skip slow tests

# Run in parallel
pytest -n auto                   # Requires pytest-xdist

# Run with verbose output
pytest -v --tb=short
```

### CI/CD Integration
See [GitHub Actions documentation](https://docs.github.com/en/actions) for CI/CD setup examples.

## Key Testing Principles

### DO
- Write tests before or with code (TDD)
- Test one behavior per test
- Use descriptive test names
- Use AAA pattern (Arrange-Act-Assert)
- Mock external dependencies
- Test edge cases and error conditions
- Maintain test independence
- Keep tests simple and readable

### DON'T
- Test implementation details
- Have tests depend on each other
- Use sleep() in tests (use proper async/mocking)
- Ignore failing tests
- Skip writing tests for "simple" code
- Use production data in tests
- Hard-code test data that changes

## Success Criteria

Before merging code:
- [ ] All tests pass
- [ ] Coverage ≥ 80%
- [ ] Tests follow naming conventions
- [ ] Edge cases tested
- [ ] Error handling tested
- [ ] Async operations tested properly
- [ ] Integration tests for external dependencies
- [ ] No flaky tests

## References
- [Pytest Documentation](https://docs.pytest.org/)
- [pytest-mock Plugin](https://pytest-mock.readthedocs.io/)
- [pytest-asyncio Plugin](https://pytest-asyncio.readthedocs.io/)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)
