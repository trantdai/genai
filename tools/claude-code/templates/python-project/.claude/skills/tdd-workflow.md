# Test-Driven Development (TDD) Workflow

## Red Phase: Write Failing Test
- [ ] Write test describing desired behavior (Arrange-Act-Assert)
- [ ] Run test to confirm it fails for the right reason

## Green Phase: Minimal Implementation
- [ ] Write simplest code to make test pass
- [ ] Run test to verify it passes
- [ ] Add edge case tests (empty input, invalid types, None)
- [ ] Implement error handling for edge cases

## Refactor Phase: Improve Code
- [ ] Extract complex logic into helpers
- [ ] Improve naming and readability
- [ ] Add type hints
- [ ] Remove duplication
- [ ] Run tests after each change

## Quality Gates
- [ ] Coverage ≥ 80% (`pytest --cov=src`)
- [ ] Format: `black src tests && ruff check src tests`
- [ ] Type check: `mypy src`
- [ ] All tests pass

## Success Checklist
- ✅ Tests pass
- ✅ Coverage ≥ 80%
- ✅ No lint errors
- ✅ Edge cases covered
- ✅ Error handling tested
