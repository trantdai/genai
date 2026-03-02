---
name: review-code
description: Review code for best practices, bugs, and improvements in claudeskills
argument-hint: [file-or-directory]
context: fork
agent: general-purpose
allowed-tools: Read, Grep, Glob
---

Review code quality for: **$0**

## Project Context
- Project: claudeskills (FastAPI + Temporal showcase)
- Standards: Follow PRD requirements in `docs/prd.md`
- Type checking: mypy enabled
- Linting: ruff configured

## Review Checklist

### 1. Temporal-Specific Issues
- **Determinism**: No random(), no direct I/O, no threading
- **Time handling**: Use `workflow.now()` not `datetime.now()`
- **Activities**: Proper timeouts, retry policies, idempotency
- **Error handling**: Distinguish retryable vs non-retryable

### 2. FastAPI Best Practices
- **Route handlers**: Proper status codes, error handling
- **Pydantic models**: Validation rules, examples for docs
- **Dependencies**: Using dependency injection correctly
- **Documentation**: OpenAPI descriptions complete

### 3. Code Quality
- **Type hints**: All functions have return types
- **Error handling**: Try/except with specific exceptions
- **Logging**: Structured logging with context
- **Security**: No hardcoded secrets, input validation

### 4. Testing
- **Coverage**: Tests exist for the code
- **Test quality**: Both success and failure cases
- **Mocking**: External dependencies mocked properly

### 5. Python Best Practices
- **Async/await**: Used correctly
- **Dataclasses**: For simple data structures
- **Type safety**: No `Any` types without reason
- **Imports**: Organized and not unused

## Output Format

Provide review as:

### ✅ Good Practices Found
- List positive things

### ⚠️ Warnings (Should Fix)
- Issue description
- Location: file:line
- Recommendation
- Example fix

### 🚨 Critical Issues (Must Fix)
- Issue description
- Location: file:line
- Why it's critical
- Example fix

### 💡 Suggestions (Optional)
- Enhancement ideas
- Performance improvements
- Better patterns

## After Review
Provide actionable next steps to improve the code.
