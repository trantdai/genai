# Python Testing Rules

## Framework
- **Mandatory**: pytest exclusively (never unittest)
- **Dependencies**: pytest ≥7.4.0, pytest-mock ≥3.11.0, pytest-asyncio ≥0.21.0, pytest-cov ≥4.1.0

## Organization

```
tests/
├── conftest.py          # Shared fixtures
├── unit/                # Unit tests
├── integration/         # Integration tests
└── e2e/                # End-to-end tests
```

**Naming:**
- Files: `test_*.py` or `*_test.py`
- Functions: `test_<descriptive_name>()`
- Classes: `Test<ClassName>`

## Coverage Requirements
- **Overall**: 80% minimum (enforced by CI)
- **New Code**: 90% minimum
- **Critical Paths**: 95% minimum (auth, payment, data integrity)

## Best Practices

**Test Structure (AAA Pattern):**
```python
def test_user_creation():
    # Arrange
    email = "test@example.com"
    
    # Act
    user = create_user("Test User", email)
    
    # Assert
    assert user.email == email
```

**Descriptive Names:**
- ✅ `test_user_service_returns_none_when_user_not_found()`
- ❌ `test_user()`, `test_1()`

**Parametrized Tests:**
```python
@pytest.mark.parametrize("user_data,expected", [
    ({"email": "valid@test.com"}, True),
    ({"email": "invalid"}, False),
])
def test_validation(user_data, expected):
    assert validate_user(user_data) == expected
```

## Fixtures

```python
@pytest.fixture
def sample_user():
    return {"id": "123", "email": "test@example.com"}

@pytest.fixture
def mock_db(mocker):
    session = mocker.Mock()
    session.commit = mocker.Mock()
    return session
```

**Fixture Scopes:** `function` (default), `module`, `session`

## Mocking

✅ **DO**: Use pytest-mock
```python
def test_service(mocker, sample_user):
    mock_db = mocker.patch('src.services.database')
    mock_db.get_user.return_value = sample_user
    
    service = UserService()
    result = service.get_user("123")
    
    mock_db.get_user.assert_called_once_with("123")
```

❌ **DON'T**: Use unittest.mock directly

## Async Testing

```python
@pytest.mark.asyncio
async def test_async_creation(async_db):
    service = AsyncUserService(async_db)
    user = await service.create_user({"email": "test@example.com"})
    assert user.id is not None
```

Configure: `asyncio_mode = "auto"` in pyproject.toml

## Exception Testing

```python
def test_raises_error():
    with pytest.raises(UserNotFoundError) as exc_info:
        service.get_user("nonexistent")
    assert "nonexistent" in str(exc_info.value)
```

## Execution

```bash
pytest                                    # All tests
pytest --cov=src --cov-report=html       # With coverage
pytest -m unit                            # Unit tests only
pytest -n auto                            # Parallel (requires pytest-xdist)
```

## Key Principles

**DO:**
- Write tests before/with code (TDD)
- Test one behavior per test
- Use descriptive names
- Use AAA pattern
- Mock external dependencies
- Test edge cases and errors
- Keep tests independent

**DON'T:**
- Test implementation details
- Have dependent tests
- Use sleep() (use proper async/mocking)
- Ignore failing tests
- Skip tests for "simple" code
- Use production data

## Success Checklist
- [ ] All tests pass
- [ ] Coverage ≥ 80%
- [ ] Follows naming conventions
- [ ] Edge cases tested
- [ ] Error handling tested
- [ ] Async tests properly marked
- [ ] No flaky tests
