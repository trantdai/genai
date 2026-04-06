# Code Review Workflow

## When to Use
Before committing code, creating pull requests, or conducting code reviews.

## Prerequisites
- ruff, black, mypy, bandit, pytest, pytest-cov installed
- Virtual environment activated
- Code changes committed or staged

## Code Formatting
- [ ] Run Black to check formatting (`--check` flag first)
- [ ] Run isort to check import sorting
- [ ] Auto-format if needed and review changes
- [ ] Verify formatting matches project standards (100-char lines)

## Linting
- [ ] Run ruff with all rules enabled
- [ ] Review and fix unused imports/variables
- [ ] Address undefined names
- [ ] Fix code style violations
- [ ] Check complexity issues (functions too complex)
- [ ] Auto-fix safe issues with `--fix` flag

## Type Checking
- [ ] Run mypy in strict mode
- [ ] Add missing type hints on all functions
- [ ] Fix incorrect return types
- [ ] Add None checks for optional values
- [ ] Use `Optional[Type]` for nullable values
- [ ] Add type hints to class attributes

## Security Scan
- [ ] Run bandit security scanner
- [ ] Review hardcoded secrets (use environment variables)
- [ ] Check for SQL injection vulnerabilities (use parameterized queries)
- [ ] Verify no insecure functions (eval, exec, pickle)
- [ ] Confirm cryptographic randomness uses `secrets` module
- [ ] Validate all user inputs are sanitized
- [ ] Check for path traversal vulnerabilities

## Test Coverage
- [ ] Run pytest with coverage reporting
- [ ] Verify minimum 80% coverage achieved
- [ ] Check branch coverage for conditionals
- [ ] Ensure edge cases are tested
- [ ] Verify error handling paths are tested
- [ ] Add tests for any uncovered critical paths

## Code Quality
- [ ] Check cognitive complexity (≤15 per function)
- [ ] Verify function length (≤50 lines)
- [ ] Check parameter count (≤5 per function)
- [ ] Review nested depth (≤4 levels)
- [ ] Identify duplicate code blocks

## Documentation
- [ ] Verify all public modules have docstrings
- [ ] Check all public classes have docstrings
- [ ] Ensure all public functions have docstrings (Google style)
- [ ] Confirm docstrings include Args, Returns, Raises
- [ ] Review complex logic has inline comments
- [ ] Update README if API changed

## Success Criteria
- ✅ Code formatted (black, isort)
- ✅ No linting errors (ruff)
- ✅ No type errors (mypy)
- ✅ No security issues (bandit)
- ✅ All tests pass
- ✅ Coverage ≥ 80%
- ✅ Complexity ≤ 15 per function
- ✅ Public APIs documented
- ✅ No hardcoded secrets

## Tools
- **black**: Code formatting
- **isort**: Import sorting
- **ruff**: Fast linting
- **mypy**: Static type checking
- **bandit**: Security linting
- **pytest-cov**: Coverage reporting

## Best Practices
- Run checks frequently during development
- Fix issues incrementally
- Automate checks in pre-commit hooks
- Focus on high-severity issues first
- Review your own code before requesting peer review
