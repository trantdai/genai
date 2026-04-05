# Comprehensive Code Review Workflow

## When to Use
Use this skill before committing code, creating pull requests, or when conducting code reviews. This ensures code meets quality standards, follows best practices, and is free from common issues.

## Prerequisites
- Python project with pyproject.toml configuration
- Required tools installed:
  - `ruff` for linting
  - `black` for formatting
  - `mypy` for type checking
  - `bandit` for security scanning
  - `pytest` and `pytest-cov` for testing
- Virtual environment activated
- All code changes committed or staged

## Workflow Steps

### 1. Activate Environment and Navigate to Project
```bash
cd /path/to/project
source .venv/bin/activate
```

### 2. Run Code Formatting Check
```bash
# Check if code is formatted correctly (don't modify yet)
black --check src/ tests/

# Check import sorting
isort --check-only src/ tests/
```

**Expected Output**:
- ✅ "All done! ✨ 🍰 ✨" if formatted correctly
- ❌ "would reformat X files" if formatting needed

**If formatting needed**:
```bash
# Auto-format code
black src/ tests/

# Sort imports
isort src/ tests/

# Review changes
git diff
```

### 3. Run Linting (Ruff)
```bash
# Run ruff linter with all rules
ruff check src/ tests/ --output-format=full

# For detailed output with context
ruff check src/ tests/ --show-source --show-fixes
```

**Common Issues to Look For**:
- Unused imports and variables
- Undefined names
- Complexity issues (functions too complex)
- Code style violations
- Potential bugs (comparison issues, etc.)

**Fix Issues**:
```bash
# Auto-fix safe issues
ruff check src/ tests/ --fix

# Review remaining issues manually
ruff check src/ tests/
```

### 4. Run Type Checking (mypy)
```bash
# Run mypy with strict configuration
mypy src/ --strict --show-error-codes --pretty

# For specific module
mypy src/<package_name>/<module>.py
```

**Common Type Issues**:
- Missing type hints on functions
- Incorrect return types
- Missing None checks
- Incompatible types in assignments
- Missing type hints on class attributes

**Fix Type Issues**:
- Add type hints to all function signatures
- Use `Optional[Type]` for nullable values
- Use `Union[Type1, Type2]` for multiple types
- Add `-> None` for functions without return
- Use type aliases for complex types

### 5. Run Security Scan (Bandit)
```bash
# Run bandit security scanner
bandit -r src/ -f json -o bandit-report.json

# View results in terminal
bandit -r src/ -ll  # Only show medium and high severity

# Detailed report
bandit -r src/ -v
```

**Security Issues to Review**:
- Hardcoded passwords or secrets
- SQL injection vulnerabilities
- Use of insecure functions (eval, exec, pickle)
- Weak cryptography
- Insecure random number generation
- Path traversal vulnerabilities
- Command injection risks

**Fix Security Issues**:
- Remove hardcoded secrets (use environment variables)
- Use parameterized queries for SQL
- Replace insecure functions with safe alternatives
- Use `secrets` module for cryptographic randomness
- Validate and sanitize all inputs

### 6. Check Test Coverage
```bash
# Run tests with coverage report
pytest tests/ --cov=src --cov-report=term-missing --cov-report=html --cov-fail-under=80 -v

# View detailed HTML report
open htmlcov/index.html  # macOS
# or
xdg-open htmlcov/index.html  # Linux
```

**Coverage Analysis**:
- Identify uncovered lines
- Check branch coverage
- Ensure edge cases are tested
- Verify error handling is tested

**If Coverage Below 80%**:
```bash
# Identify specific uncovered lines
pytest tests/ --cov=src --cov-report=term-missing

# Add tests for uncovered code
# Focus on:
# - Error handling paths
# - Edge cases
# - Branch conditions
# - Exception handling
```

### 7. Check Code Quality Metrics
```bash
# Check cognitive complexity with ruff
ruff check src/ --select C901  # McCabe complexity

# Check for code smells
ruff check src/ --select ALL --ignore E,W,F
```

**Quality Metrics to Review**:
- Cognitive complexity (should be ≤15 per function)
- Function length (should be ≤50 lines)
- Number of parameters (should be ≤5)
- Nested depth (should be ≤4 levels)
- Duplicate code blocks

### 8. Review Documentation
```bash
# Check for missing docstrings
ruff check src/ --select D

# Verify docstring format (Google style)
pydocstyle src/ --convention=google
```

**Documentation Checklist**:
- [ ] All public modules have docstrings
- [ ] All public classes have docstrings
- [ ] All public functions have docstrings
- [ ] Docstrings include Args, Returns, Raises
- [ ] Complex logic has inline comments
- [ ] README is up-to-date
- [ ] API documentation is current

### 9. Generate Review Report
```bash
# Create comprehensive review report
cat > code-review-report.md << 'EOF'
# Code Review Report
**Date**: $(date +%Y-%m-%d)
**Reviewer**: $(git config user.name)
**Branch**: $(git branch --show-current)

## Summary
- Files Changed: $(git diff --name-only main...HEAD | wc -l)
- Lines Added: $(git diff --shortstat main...HEAD | grep -oE '[0-9]+ insertion' | grep -oE '[0-9]+')
- Lines Removed: $(git diff --shortstat main...HEAD | grep -oE '[0-9]+ deletion' | grep -oE '[0-9]+')

## Quality Checks
- [ ] Formatting: black --check passed
- [ ] Linting: ruff check passed
- [ ] Type Checking: mypy passed
- [ ] Security: bandit passed
- [ ] Tests: All tests passing
- [ ] Coverage: ≥80%

## Issues Found
<!-- List any issues that need attention -->

## Recommendations
<!-- List recommendations for improvement -->

## Approval Status
- [ ] Approved
- [ ] Approved with comments
- [ ] Changes requested
EOF
```

### 10. Run All Checks Together
```bash
# Create a comprehensive check script
cat > check-all.sh << 'EOF'
#!/bin/bash
set -e

echo "🔍 Running comprehensive code review..."
echo ""

echo "1️⃣ Formatting check..."
black --check src/ tests/
isort --check-only src/ tests/

echo ""
echo "2️⃣ Linting..."
ruff check src/ tests/

echo ""
echo "3️⃣ Type checking..."
mypy src/ --strict

echo ""
echo "4️⃣ Security scan..."
bandit -r src/ -ll

echo ""
echo "5️⃣ Running tests with coverage..."
pytest tests/ --cov=src --cov-fail-under=80 -v

echo ""
echo "✅ All checks passed!"
EOF

chmod +x check-all.sh
./check-all.sh
```

## Success Criteria
- ✅ Code is formatted correctly (black, isort)
- ✅ No linting errors (ruff)
- ✅ No type checking errors (mypy)
- ✅ No security issues (bandit)
- ✅ All tests pass
- ✅ Code coverage ≥ 80%
- ✅ Cognitive complexity ≤ 15 per function
- ✅ All public APIs documented
- ✅ No hardcoded secrets
- ✅ Proper error handling implemented

## Common Issues

### Issue: Black and isort conflict
**Solution**:
```toml
# pyproject.toml
[tool.isort]
profile = "black"
line_length = 100
```

### Issue: Mypy errors on third-party libraries
**Solution**:
```toml
# pyproject.toml
[tool.mypy]
ignore_missing_imports = true

[[tool.mypy.overrides]]
module = "problematic_module.*"
ignore_missing_imports = true
```

### Issue: Bandit false positives
**Solution**:
```python
# Suppress specific warnings with comments
result = eval(safe_expression)  # nosec B307

# Or configure in pyproject.toml
[tool.bandit]
exclude_dirs = ["tests/"]
skips = ["B101", "B601"]
```

### Issue: Coverage not counting all files
**Solution**:
```toml
# pyproject.toml
[tool.coverage.run]
source = ["src"]
omit = ["*/tests/*", "*/test_*.py"]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise AssertionError",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
]
```

### Issue: Ruff too strict
**Solution**:
```toml
# pyproject.toml
[tool.ruff]
line-length = 100
select = ["E", "F", "W", "I", "N", "D", "UP", "S", "B", "A", "C4", "T20", "SIM"]
ignore = ["D203", "D213"]  # Ignore specific rules

[tool.ruff.per-file-ignores]
"tests/*" = ["S101"]  # Allow assert in tests
```

## Examples

### Example 1: Pre-Commit Review
```bash
# Quick pre-commit check
black src/ tests/ && \
isort src/ tests/ && \
ruff check src/ tests/ --fix && \
mypy src/ && \
pytest tests/ --cov=src --cov-fail-under=80 -q

# If all pass, commit
git add .
git commit -m "feat(module): ✨ add new feature"
```

### Example 2: Pull Request Review
```bash
# Comprehensive PR review
echo "Reviewing PR changes..."

# Check only changed files
CHANGED_FILES=$(git diff --name-only main...HEAD | grep '\.py$')

# Run checks on changed files
black --check $CHANGED_FILES
ruff check $CHANGED_FILES
mypy $CHANGED_FILES

# Run full test suite
pytest tests/ --cov=src --cov-report=html -v

# Generate report
echo "Review complete. Check htmlcov/index.html for coverage report."
```

### Example 3: CI/CD Integration
```yaml
# .github/workflows/code-review.yml
name: Code Review
on: [pull_request]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install black isort ruff mypy bandit pytest pytest-cov
      - name: Format check
        run: |
          black --check src/ tests/
          isort --check-only src/ tests/
      - name: Lint
        run: ruff check src/ tests/
      - name: Type check
        run: mypy src/ --strict
      - name: Security scan
        run: bandit -r src/ -ll
      - name: Test with coverage
        run: pytest tests/ --cov=src --cov-fail-under=80
```

## Related Skills
- [`tdd-workflow.md`](./tdd-workflow.md) - Ensure tests exist before review
- [`security-audit.md`](./security-audit.md) - Deep security analysis
- [`refactoring-workflow.md`](./refactoring-workflow.md) - Address code quality issues
- [`performance-analysis.md`](./performance-analysis.md) - Check performance

## Best Practices
- Run checks frequently during development
- Fix issues incrementally, not all at once
- Automate checks in pre-commit hooks
- Use CI/CD for automated reviews
- Review your own code before requesting peer review
- Focus on high-severity issues first
- Document why certain warnings are suppressed
- Keep tool configurations in pyproject.toml
- Use consistent tool versions across team
- Update tools regularly for new checks
