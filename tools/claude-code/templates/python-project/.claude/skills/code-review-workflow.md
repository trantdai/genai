# Code Review Workflow

## Format & Lint
- [ ] Run `black src tests --check` and `ruff check src tests`
- [ ] Auto-fix: `black src tests && ruff check src tests --fix`
- [ ] Verify 100-char line length, imports sorted

## Type Check
- [ ] Run `mypy src` in strict mode
- [ ] Add missing type hints on all functions
- [ ] Fix return types and None checks

## Security
- [ ] Run `bandit -r src/`
- [ ] No hardcoded secrets (use env vars)
- [ ] Parameterized SQL queries only
- [ ] No eval, exec, pickle
- [ ] Use `secrets` module for randomness
- [ ] Input validation present

## Test Coverage
- [ ] Run `pytest --cov=src --cov-report=term-missing`
- [ ] Coverage ≥ 80%
- [ ] Edge cases tested
- [ ] Error paths tested

## Code Quality
- [ ] Complexity ≤15 per function
- [ ] Function length ≤50 lines
- [ ] Parameters ≤5 per function
- [ ] No duplicate code

## Documentation
- [ ] Public APIs have docstrings (Google style)
- [ ] Docstrings include Args, Returns, Raises
- [ ] Complex logic has comments

## Success Checklist
- ✅ Formatted (black)
- ✅ No lint errors (ruff)
- ✅ No type errors (mypy)
- ✅ No security issues (bandit)
- ✅ Tests pass, coverage ≥80%
- ✅ Complexity within limits
- ✅ Documented
