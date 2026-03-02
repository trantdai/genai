---
name: add-tests
description: Add comprehensive tests for existing code in claudeskills
argument-hint: [file-path]
context: fork
agent: general-purpose
---

Add comprehensive tests for: **$0**

## Project Context
- Project: claudeskills (FastAPI + Temporal showcase)
- Test framework: pytest with pytest-asyncio
- Coverage target: >80%
- Follow patterns in existing tests

## Steps

1. **Read the target file** to understand what needs testing
2. **Identify test cases:**
   - Happy path scenarios
   - Error cases
   - Edge cases
   - Validation failures
   - Timeout scenarios (for Temporal)

3. **Create test file** in appropriate location:
   - API: `tests/api/test_*.py`
   - Workflows: `tests/workflows/test_*.py`
   - Activities: `tests/activities/test_*.py`
   - Core: `tests/core/test_*.py`

4. **Write tests following patterns:**
```python
import pytest
from unittest.mock import Mock, patch

# For async tests
@pytest.mark.asyncio
async def test_async_function() -> None:
    """Test description."""
    # Arrange
    # Act
    # Assert
    pass

# For API tests
def test_endpoint(client: TestClient) -> None:
    """Test description."""
    response = client.get("/endpoint")
    assert response.status_code == 200

# For Temporal workflows
@pytest.mark.asyncio
async def test_workflow() -> None:
    """Test workflow execution."""
    async with await WorkflowEnvironment.start_time_skipping() as env:
        # Setup and test
        pass
```

5. **Run tests and verify coverage:**
```bash
pytest tests/path/to/test_file.py -v --cov
```

## Requirements
- Use type hints
- Clear test names describing what's being tested
- Follow AAA pattern (Arrange, Act, Assert)
- Mock external dependencies
- Test both success and failure cases
- Add docstrings to tests
