# Safe Refactoring Workflow

## When to Use
Improving code structure, readability, or maintainability without changing external behavior.

## Prerequisites
- Comprehensive test suite (≥80% coverage)
- All tests passing
- Clean version control state
- Clear refactoring goal

## Pre-Refactoring Checks
- [ ] All tests pass
- [ ] Coverage ≥ 80%
- [ ] No pending git changes
- [ ] Tests cover code being refactored
- [ ] Tests are reliable (not flaky)

## Identify Code Smells
- [ ] **Long Method**: Functions >50 lines
- [ ] **Large Class**: Too many responsibilities
- [ ] **Long Parameter List**: >5 parameters
- [ ] **Duplicate Code**: Repeated code blocks
- [ ] **Dead Code**: Unused functions/variables
- [ ] **Magic Numbers**: Hardcoded values without explanation
- [ ] **Deep Nesting**: >4 indentation levels
- [ ] **God Object**: Class that knows/does too much
- [ ] **Feature Envy**: Method uses another class more than its own

## Choose Refactoring Pattern
- **Extract Method**: Break long functions into smaller ones
- **Extract Class**: Separate responsibilities into new classes
- **Replace Magic Numbers**: Use named constants
- **Simplify Conditional**: Extract complex conditions to methods with descriptive names
- **Replace Conditional with Polymorphism**: Use inheritance instead of type checking
- **Introduce Parameter Object**: Group related parameters into data class
- **Rename Method/Variable**: Make names more descriptive
- **Remove Duplication**: Extract common code
- **Inline Method**: Remove unnecessary indirection

## Refactoring Process
- [ ] Make one small change at a time
- [ ] Run tests after each change
- [ ] If tests pass → commit immediately
- [ ] If tests fail → revert and try smaller change
- [ ] Repeat incrementally

## After Each Change
- [ ] Run affected module tests first
- [ ] Run full test suite periodically
- [ ] Check coverage hasn't decreased
- [ ] Verify no behavior changes
- [ ] Commit with descriptive message (e.g., "refactor: extract calculate_total method")

## Update Documentation
- [ ] Update docstrings for refactored functions
- [ ] Update inline comments if logic changed
- [ ] Update README if public API changed
- [ ] Add examples to complex refactored code

## Check Quality Improvements
- [ ] Cognitive complexity reduced
- [ ] Function length reduced
- [ ] Duplicate code eliminated
- [ ] Magic numbers replaced with constants
- [ ] Deep nesting reduced
- [ ] Parameter count reduced
- [ ] Type hints added/improved
- [ ] Documentation updated

## Final Verification
- [ ] All tests pass
- [ ] Coverage maintained or improved
- [ ] Run full linting (ruff)
- [ ] Run type checking (mypy)
- [ ] Format code (black, isort)
- [ ] No regressions introduced
- [ ] Code more readable/maintainable

## Self-Review
- [ ] Code is more readable
- [ ] Code is more maintainable
- [ ] No behavior changes
- [ ] Follows project conventions
- [ ] No new complexity introduced

## Success Criteria
- ✅ All tests pass
- ✅ Coverage maintained/improved
- ✅ Complexity reduced
- ✅ Readability improved
- ✅ No behavior changes
- ✅ Documentation updated
- ✅ Incremental commits

## Best Practices
- Have tests before refactoring (write them first if needed)
- Make small, incremental changes
- Run tests after each change
- Commit frequently
- Use IDE refactoring tools (safer)
- Don't refactor and add features simultaneously
- Focus on one code smell at a time
- Pair program for complex refactoring
- Follow Boy Scout Rule: leave code better than you found it
