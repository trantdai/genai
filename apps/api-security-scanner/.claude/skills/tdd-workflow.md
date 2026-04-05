# Test-Driven Development (TDD) Workflow

## When to Use
Use this skill when implementing new features or fixing bugs using Test-Driven Development methodology. This ensures code is testable, maintainable, and meets requirements from the start.

## Prerequisites
- pytest installed and configured
- pytest-cov for coverage reporting
- pytest-mock for mocking (never unittest.mock)
- Project structure follows src-layout: `src/<package_name>/`
- Tests mirror source structure in `tests/` directory
- Virtual environment activated

## Workflow Steps

### 1. Understand Requirements
```bash
# Review the feature/bug requirements
# Identify acceptance criteria
# Break down into testable units
```

### 2. Write Failing Test First (Red Phase)
```bash
# Navigate to project directory
cd /path/to/project

# Activate virtual environment
source .venv/bin/activate

# Create test file if it doesn't exist
# Test files must be named test_*.py or *_test.py
touch tests/test_<module_name>.py
```

Write the test that describes the desired behavior:
```python
# tests/test_feature.py
import pytest
from src.mypackage.feature import new_function

def test_new_function_returns_expected_result():
    """Test that new_function returns correct result for valid input."""
    # Arrange
    input_data = {"key": "value"}

    # Act
    result = new_function(input_data)

    # Assert
    assert result == expected_output
    assert isinstance(result, dict)
```

Run the test to confirm it fails:
```bash
pytest tests/test_<module_name>.py::test_name -v
```

**Expected**: Test should fail because implementation doesn't exist yet.

### 3. Implement Minimal Code (Green Phase)
Write the simplest code that makes the test pass:

```python
# src/mypackage/feature.py
def new_function(input_data: dict) -> dict:
    """Process input data and return result.

    Args:
        input_data: Dictionary containing input parameters

    Returns:
        Dictionary containing processed results

    Raises:
        ValueError: If input_data is invalid
    """
    # Minimal implementation to pass test
    return expected_output
```

Run the test again:
```bash
pytest tests/test_<module_name>.py::test_name -v
```

**Expected**: Test should now pass.

### 4. Add Edge Cases and Error Handling
Write additional tests for edge cases:
```python
def test_new_function_handles_empty_input():
    """Test that new_function handles empty input gracefully."""
    with pytest.raises(ValueError, match="Input cannot be empty"):
        new_function({})

def test_new_function_handles_invalid_type():
    """Test that new_function validates input type."""
    with pytest.raises(TypeError):
        new_function("invalid")

def test_new_function_handles_none():
    """Test that new_function handles None input."""
    with pytest.raises(ValueError):
        new_function(None)
```

Run tests and implement error handling:
```bash
pytest tests/test_<module_name>.py -v
```

### 5. Refactor (Refactor Phase)
Improve code quality while keeping tests green:
- Extract complex logic into helper functions
- Improve variable names
- Add type hints
- Optimize performance
- Remove duplication

Run tests after each refactoring:
```bash
pytest tests/test_<module_name>.py -v
```

### 6. Check Test Coverage
```bash
# Run tests with coverage report
pytest tests/test_<module_name>.py --cov=src/<package_name> --cov-report=term-missing --cov-report=html

# View coverage report
open htmlcov/index.html  # macOS
# or
xdg-open htmlcov/index.html  # Linux
```

**Success Criteria**: Minimum 80% coverage for new code.

### 7. Run Full Test Suite
```bash
# Run all tests to ensure no regression
pytest tests/ -v

# Run with coverage for entire codebase
pytest tests/ --cov=src --cov-report=term-missing --cov-report=html --cov-fail-under=80
```

### 8. Run Quality Checks
```bash
# Format code
black src/ tests/

# Sort imports
isort src/ tests/

# Lint code
ruff check src/ tests/

# Type check
mypy src/
```

## Success Criteria
- ✅ All tests pass
- ✅ Code coverage ≥ 80%
- ✅ No linting errors
- ✅ Type hints present and valid
- ✅ Code is formatted correctly
- ✅ Edge cases are tested
- ✅ Error handling is tested
- ✅ Documentation is complete

## Common Issues

### Issue: Test passes without implementation
**Solution**: Review test assertions. Ensure test actually validates behavior, not just syntax.

### Issue: Coverage below 80%
**Solution**:
```bash
# Identify uncovered lines
pytest --cov=src --cov-report=term-missing

# Add tests for uncovered code paths
# Focus on branches, error handling, and edge cases
```

### Issue: Tests are slow
**Solution**:
- Use pytest fixtures for setup/teardown
- Mock external dependencies with pytest-mock
- Use pytest-xdist for parallel execution:
```bash
pytest tests/ -n auto
```

### Issue: Circular imports in tests
**Solution**:
- Ensure proper package structure
- Use absolute imports
- Check for circular dependencies in source code

### Issue: Mock not working correctly
**Solution**:
- Use pytest-mock plugin (mocker fixture)
- Never use unittest.mock directly
```python
def test_with_mock(mocker):
    mock_obj = mocker.patch('module.function')
    mock_obj.return_value = expected_value
```

## Examples

### Example 1: Simple Function TDD
```python
# 1. Write test (RED)
def test_calculate_total_with_tax():
    assert calculate_total(100, tax_rate=0.1) == 110.0

# 2. Implement (GREEN)
def calculate_total(amount: float, tax_rate: float) -> float:
    return amount * (1 + tax_rate)

# 3. Add edge cases
def test_calculate_total_zero_amount():
    assert calculate_total(0, tax_rate=0.1) == 0.0

def test_calculate_total_negative_raises_error():
    with pytest.raises(ValueError):
        calculate_total(-100, tax_rate=0.1)

# 4. Refactor with validation
def calculate_total(amount: float, tax_rate: float) -> float:
    if amount < 0:
        raise ValueError("Amount cannot be negative")
    return amount * (1 + tax_rate)
```

### Example 2: Class-Based TDD
```python
# 1. Write test (RED)
def test_user_creation():
    user = User(name="John", email="john@example.com")
    assert user.name == "John"
    assert user.email == "john@example.com"

# 2. Implement (GREEN)
class User:
    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email

# 3. Add validation tests
def test_user_invalid_email():
    with pytest.raises(ValueError, match="Invalid email"):
        User(name="John", email="invalid")

# 4. Refactor with validation
class User:
    def __init__(self, name: str, email: str):
        if "@" not in email:
            raise ValueError("Invalid email")
        self.name = name
        self.email = email
```

### Example 3: Async Function TDD
```python
# 1. Write test (RED)
@pytest.mark.asyncio
async def test_fetch_data():
    result = await fetch_data("https://api.example.com")
    assert result["status"] == "success"

# 2. Implement (GREEN)
async def fetch_data(url: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.json()

# 3. Add error handling tests
@pytest.mark.asyncio
async def test_fetch_data_handles_timeout(mocker):
    mocker.patch('aiohttp.ClientSession.get', side_effect=asyncio.TimeoutError)
    with pytest.raises(asyncio.TimeoutError):
        await fetch_data("https://api.example.com")
```

## Related Skills
- [`code-review-workflow.md`](./code-review-workflow.md) - Run after TDD cycle to ensure quality
- [`refactoring-workflow.md`](./refactoring-workflow.md) - Use during refactor phase
- [`performance-analysis.md`](./performance-analysis.md) - Optimize after tests pass

## Best Practices
- Write tests before implementation (Red-Green-Refactor)
- Keep tests simple and focused (one assertion per test when possible)
- Use descriptive test names that explain behavior
- Follow AAA pattern: Arrange, Act, Assert
- Test behavior, not implementation details
- Use fixtures for common setup
- Mock external dependencies
- Run tests frequently during development
- Commit after each green phase
- Never skip the refactor phase
