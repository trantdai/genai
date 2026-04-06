# Test-Driven Development (TDD) Workflow

## When to Use
Implementing new features or fixing bugs using Test-Driven Development methodology.

## Prerequisites
- pytest, pytest-cov, pytest-mock installed
- Virtual environment activated
- Tests mirror source structure in `tests/` directory

## Red Phase: Write Failing Test
- [ ] Understand requirements and acceptance criteria
- [ ] Identify testable units
- [ ] Write test describing desired behavior (Arrange-Act-Assert pattern)
- [ ] Run test to confirm it fails for the right reason

**Test should fail** because implementation doesn't exist yet.

## Green Phase: Minimal Implementation
- [ ] Write simplest code to make test pass
- [ ] Run test to verify it passes
- [ ] Add edge case tests (empty input, invalid types, None handling)
- [ ] Implement error handling to pass edge case tests

**All tests should pass** before moving to refactor.

## Refactor Phase: Improve Code Quality
- [ ] Extract complex logic into helper functions
- [ ] Improve variable names and readability
- [ ] Add/verify type hints
- [ ] Remove duplication
- [ ] Run tests after each change to ensure they stay green

**Tests must remain green** throughout refactoring.

## Quality Checks
- [ ] Check coverage: minimum 80% (`pytest --cov=src --cov-report=term-missing`)
- [ ] Run full test suite to ensure no regression
- [ ] Format code (Black, Ruff)
- [ ] Type check (mypy)

## Success Criteria
- ✅ All tests pass
- ✅ Coverage ≥ 80%
- ✅ No linting errors
- ✅ Type hints valid
- ✅ Edge cases tested
- ✅ Error handling tested

## Tools
- **pytest**: Test framework
- **pytest-cov**: Coverage reporting
- **pytest-mock**: Mocking (never unittest.mock)
- **pytest-asyncio**: Async test support
- **pytest-xdist**: Parallel test execution

## Best Practices
- Write test before implementation (Red-Green-Refactor cycle)
- One test per behavior
- Descriptive test names explaining what's tested
- Mock external dependencies
- Run tests frequently
- Commit after each green phase
