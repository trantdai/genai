# Critical Core Standards

> **Purpose**: Essential principles that apply across ALL modes and tasks. Always loaded.

## 🚨 Task Splitting Rules (CRITICAL)

### Thresholds
- 🔴 **STOP**: >10 files, >1000 lines, >10 steps
- 🟡 **CAUTION**: 5-10 files, 500-1000 lines, 5-10 steps
- 🟢 **SAFE**: <5 files, <500 lines, <5 steps

### Pre-Task Checklist
Before ANY task:
- [ ] Is this >5 files OR >500 lines? → **SPLIT IT**
- [ ] Multiple independent steps? → **SPLIT IT**
- [ ] Can't describe in <3 sentences? → **SPLIT IT**
- [ ] Orchestrator mode? → **EXTRA CAUTION**
- [ ] PR review with >5 files? → **SPLIT IT** (see [PR Review Rules](./01-pr-reviews.md#pr-review-task-splitting))
- [ ] Will response exceed 2000 words? → **SPLIT IT**
- [ ] Context approaching 150k tokens? → **STOP & CHECKPOINT**

### Quick Reference
| Operation | Max Size | Recommended |
|-----------|----------|-------------|
| File creation | 5 files | 3 files |
| Code generation | 300 lines | 150-200 lines |
| File modification | 5 files | 2-3 files |
| PR review | 5 files | 3-5 files per phase |
| Analysis/docs | 2000 words | 1000 words |

## 🧠 Context Window Management (CRITICAL)

### Token Budget
- **Hard Limit**: 200,000 tokens
- **Safe Zone**: <150,000 tokens (75%)
- **Warning**: 150k-180k tokens (75-90%)
- **Danger**: >180,000 tokens (90%+)

### High-Risk Operations
- ❌ PR reviews (multi-file analysis)
- ❌ Large file analysis (>1000 lines)
- ❌ Multi-file refactoring (>5 files)
- ❌ Comprehensive documentation (>2000 words)

### Mandatory Checks Before Starting
- [ ] Will I read >3 large files? → **SPLIT IT**
- [ ] Will response exceed 2000 words? → **SPLIT IT**
- [ ] PR with >5 files? → **SPLIT IT**
- [ ] Generate >500 lines? → **SPLIT IT**

**Details**: See [Task Management](./11-task-management.md#context-window-emergency-protocol)

## 🔒 Security Fundamentals (NON-NEGOTIABLE)

### Critical Rules
- ✅ **Never hardcode secrets** - Use env vars or secret managers
- ✅ **Validate all inputs** - At trust boundaries (Pydantic/Zod)
- ✅ **Parameterized queries only** - Prevent SQL injection
- ✅ **No bare except/catch** - Specify exception classes
- ✅ **Sanitize error messages** - Never expose sensitive info
- ✅ **Use established crypto** - Never roll your own

### OWASP Top 10 Prevention
- **SQL Injection**: Parameterized queries/ORMs only
- **XSS**: Output encoding + CSP headers
- **CSRF**: Tokens for state-changing operations
- **Path Traversal**: Validate/sanitize file paths
- **Secrets Exposure**: Environment variables + Vault

## 🤝 Collaborative Planning (MANDATORY)

### Before Implementation
1. **Review** task scope/spec and `docs/` directory
2. **Identify** ambiguities and gaps
3. **Ask** clarification questions (use `ask_followup_question`)
4. **Document** updated scope
5. **Create** implementation plan
6. **Share** plan for approval
7. **Iterate** based on feedback

### When to Ask Questions
- **Always** when requirements are ambiguous
- **Always** when multiple interpretations exist
- **Always** when edge cases undefined
- **Before** architectural decisions
- **Before** breaking changes

## 📊 Quality Standards (UNIVERSAL)

### Testing
- ✅ **80% minimum coverage** - Non-negotiable
- ✅ **Test new behaviors** - All new code must have tests
- ✅ **Meaningful tests** - Isolated, reliable, edge cases

### Code Quality
- ✅ **Cognitive complexity ≤15** - Refactor if exceeded
- ✅ **Remove unused code** - Variables, functions, imports
- ✅ **DRY principle** - Don't repeat yourself
- ✅ **Meaningful names** - Clear variable/function names

### Documentation
- ✅ **Update with code** - Keep docs synchronized
- ✅ **Document "why" not "what"** - Explain reasoning
- ✅ **Public APIs documented** - Clear docstrings/JSDoc

## 🎯 Architecture Consistency

### Before Making Changes
- [ ] Review patterns in `docs/` directory
- [ ] Check existing architectural decisions
- [ ] Verify design pattern adherence
- [ ] Assess system architecture impact

## 🔄 Error Recovery Pattern

When errors occur:
1. **Acknowledge** error explicitly
2. **Summarize** what completed successfully
3. **List** what remains
4. **Propose** smaller, focused next steps
5. **Confirm** approach with user

## 📝 Commit Standards (Quick Reference)

Format: `<type>(<scope>): <icon> <description>`

Common types:
- `feat`: ✨ New feature
- `fix`: 🐛 Bug fix
- `docs`: 📚 Documentation
- `security`: 🔒 Security fix
- `refactor`: ♻️ Code refactor
- `test`: 🧪 Tests

## 🚀 Mode-Specific Rules

Detailed standards loaded based on active mode:
- **Code Mode**: See `.roo/rules-code/` for language-specific standards
- **Architect Mode**: See `.roo/rules-architect/` for design standards
- **Security Review**: See `.roo/rules-security-review/` for audit checklists
- **Documentation Writer**: See `.roo/rules-documentation-writer/` for doc standards
- **DevOps**: See `.roo/rules-devops/` for infrastructure standards

## Remember

> **"Small, focused, incremental progress is better than ambitious failures."**

When in doubt:
1. Split it smaller
2. Ask for clarification
3. Plan before implementing
4. Keep security first
