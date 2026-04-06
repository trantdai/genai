# Python Project Guide

## Project Overview

Modern Python project using src-layout pattern with strict standards for maintainability, security, and performance.

**Stack**: Python 3.13+, Black/Ruff, mypy, pytest, Pydantic v2+, asyncio

## Project Structure

```
project/
├── src/<package>/         # Application code (src-layout)
│   ├── models/           # Pydantic models
│   ├── services/         # Business logic
│   ├── repositories/     # Data access
│   └── utils/           # Utilities
├── tests/                # Test suite (mirrors src)
├── .claude/              # Project configuration
├── pyproject.toml        # Dependencies & tool config
└── requirements.txt      # Pinned dependencies
```

## Development Standards

### Code Quality
- **Type Hints**: Required for all functions and classes
- **Docstrings**: Google style for public APIs
- **Formatting**: Black (100-char lines), Ruff (linting/imports)
- **Type Checking**: mypy strict mode
- **Line Length**: 100 characters maximum
- **Testing**: pytest with 80%+ coverage minimum

See: [`.claude/rules/python-code-style.md`](.claude/rules/python-code-style.md)

### Testing Requirements
- **Framework**: pytest exclusively (never unittest)
- **Mocking**: pytest-mock plugin (never unittest.mock)
- **Coverage**: 80% minimum, 90%+ for critical paths
- **Async Tests**: pytest-asyncio with `@pytest.mark.asyncio`
- **Organization**: unit/, integration/, e2e/ structure

See: [`.claude/rules/python-testing.md`](.claude/rules/python-testing.md)

### Security Standards
- **Input Validation**: Pydantic models at all boundaries
- **Password Hashing**: bcrypt with 12+ rounds
- **Authentication**: JWT tokens with short expiry
- **HTTPS Only**: All production communications
- **Secrets**: Environment variables (never hardcoded)
- **SQL**: Parameterized queries only

See: [`.claude/rules/python-security.md`](.claude/rules/python-security.md)

### Async Patterns
- **I/O Operations**: Use async/await for database, HTTP, files
- **Concurrency**: asyncio.gather(), semaphores for rate limiting
- **Database**: AsyncPG (PostgreSQL) or SQLAlchemy async
- **HTTP**: httpx or aiohttp for async requests
- **Never Block**: Use async alternatives (asyncio.sleep, not time.sleep)

See: [`.claude/rules/python-async.md`](.claude/rules/python-async.md)

### Performance
- **Data Structures**: Choose optimal collections (set vs list)
- **Algorithms**: O(n log n) max for large datasets
- **Memory**: Use generators for large data, __slots__ for classes
- **Profiling**: Profile before optimizing
- **Caching**: LRU cache for expensive computations

See: [`.claude/rules/python-performance.md`](.claude/rules/python-performance.md)

## Workflows

### Development Workflow
1. Activate virtual environment: `source .venv/bin/activate`
2. Run tests frequently: `pytest -x` (fail fast)
3. Format before commit: `black src tests`
4. Type check: `mypy src`

### Before Committing
```bash
black src tests --check && ruff check src tests && mypy src && pytest --cov=src --cov-fail-under=80
```

### TDD Workflow
1. **Red**: Write failing test
2. **Green**: Minimal code to pass
3. **Refactor**: Improve while keeping tests green

See: [`.claude/workflows/tdd-workflow.md`](.claude/workflows/tdd-workflow.md)

### Code Review
- Security implications reviewed
- Test coverage maintained
- Performance impact assessed
- Breaking changes documented

See: [`.claude/workflows/code-review-workflow.md`](.claude/workflows/code-review-workflow.md)

### Safe Refactoring
- Write characterization tests first
- Refactor incrementally
- Run tests after each change
- Use IDE refactoring tools

See: [`.claude/workflows/safe-refactoring-workflow.md`](.claude/workflows/safe-refactoring-workflow.md)

## Common Commands

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

# Development
black src tests                    # Format code
ruff check src tests --fix         # Lint and fix
mypy src                           # Type check

# Testing
pytest                             # Run all tests
pytest --cov=src --cov-report=html # With coverage
pytest -k "test_user" -v           # Run specific tests

# Security
pip-audit                          # Vulnerability scan
bandit -r src/                     # Security linter
```

## Agents

**When to use specialized agents:**

- **python-specialist**: Code review, performance optimization, design patterns
- **testing-expert**: Test strategy, coverage improvement, test debugging
- **security-auditor**: Security review, vulnerability assessment, compliance

See: [`.claude/agents/`](.claude/agents/)

## Dependencies

- Use `>=` for version constraints (e.g., `pydantic>=2.5.0`)
- Pin versions in requirements.txt for reproducibility
- Update dependencies monthly, security patches immediately
- Audit new dependencies before adding
- Keep production dependencies minimal

## Key Principles

- **Simplicity**: Minimal code to achieve requirements
- **Type Safety**: Comprehensive type hints, mypy strict mode
- **Test First**: TDD approach for new features
- **Async I/O**: Use async patterns for all I/O operations
- **Security**: Validate inputs, encode outputs, never trust user data
- **Performance**: Profile before optimizing, use appropriate algorithms

## Checklist

Before completing any task:

- [ ] Type hints on all functions/methods
- [ ] Tests written and passing (80%+ coverage)
- [ ] Security reviewed (no hardcoded secrets, input validation)
- [ ] Error handling with specific exceptions
- [ ] Code formatted (Black, Ruff)
- [ ] Type checking passes (mypy)
- [ ] Documentation updated if public API changed

---

*For detailed guidelines, see `.claude/rules/` and `.claude/workflows/`*
