# Safe Refactoring Workflow

## Pre-Flight Check
- [ ] All tests pass, coverage ≥80%
- [ ] Clean git state
- [ ] Tests cover code being refactored
- [ ] Tests are reliable (not flaky)

## Common Code Smells
- Long Method (>50 lines), Large Class
- Long Parameter List (>5), Deep Nesting (>4 levels)
- Duplicate Code, Dead Code
- Magic Numbers, God Object

## Refactoring Patterns
- **Extract Method/Class**: Break down complexity
- **Replace Magic Numbers**: Use named constants
- **Simplify Conditional**: Extract to descriptive methods
- **Introduce Parameter Object**: Group related params
- **Rename**: Improve clarity
- **Remove Duplication**: Extract common code

## Refactoring Process
- [ ] Make one small change at a time
- [ ] Run tests after each change
- [ ] If tests pass → commit with clear message
- [ ] If tests fail → revert and try smaller change
- [ ] Check coverage hasn't decreased
- [ ] Update docstrings if needed

## Final Verification
- [ ] All tests pass
- [ ] Run `black src tests && ruff check src tests`
- [ ] Run `mypy src`
- [ ] Coverage maintained or improved
- [ ] No behavior changes
- [ ] Code more readable/maintainable

## Success Checklist
- ✅ Tests pass
- ✅ Coverage maintained
- ✅ Complexity reduced
- ✅ Readability improved
- ✅ No regressions
- ✅ Documentation updated
- ✅ Incremental commits
