# Python Development Agents

Specialized AI agents providing expert assistance for Python development. Each agent maintains project context and offers domain-specific guidance.

## Available Agents

### 🐍 Python Specialist
**File**: [`python-specialist.md`](python-specialist.md)

Expert in Python best practices, async patterns, and modern Python features.

**Use for**: Code review, async implementation, design patterns, refactoring, performance optimization

### 🧪 Testing Expert
**File**: [`testing-expert.md`](testing-expert.md)

Pytest mastery and comprehensive testing strategies.

**Use for**: Test strategy, coverage improvement (80%+ target), fixture design, integration testing, flaky test resolution

### 🔒 Security Auditor
**File**: [`security-auditor.md`](security-auditor.md)

Vulnerability detection and OWASP compliance specialist.

**Use for**: Security reviews, authentication/authorization, secret management, dependency scanning, OWASP Top 10

### 📋 Code Reviewer
**File**: [`code-reviewer.md`](code-reviewer.md)

Code quality and design pattern evaluation expert.

**Use for**: Pull request reviews, architecture review, refactoring planning, technical debt assessment, SOLID principles

### ⚡ Performance Optimizer
**File**: [`performance-optimizer.md`](performance-optimizer.md)

Profiling, benchmarking, and optimization specialist.

**Use for**: Performance issues, database optimization, memory leaks, scalability planning, async optimization

## Usage

### Direct Invocation
```
"Python Specialist: review this async implementation"
"Security Auditor: check for vulnerabilities in auth code"
"Performance Optimizer: analyze this database query"
```

### Automatic Invocation
Agents are invoked based on context:
- Security issues → Security Auditor
- Performance problems → Performance Optimizer
- Test failures → Testing Expert
- Code reviews → Code Reviewer
- Python questions → Python Specialist

## Creating a New Agent

Use this template for new agents:

```markdown
---
name: Agent Name
description: Brief expertise description (one line)
tools: [read_file, write_to_file, apply_diff, search_files, execute_command]
model: sonnet
context_tracking: true
expertise_areas: [area1, area2, area3]
---

# Agent Name

## Expertise
- **Domain 1**: Key capabilities
- **Domain 2**: Key capabilities
- **Domain 3**: Key capabilities

## When to Invoke
- Scenario 1
- Scenario 2
- Scenario 3

## Approach
Brief description of how the agent analyzes problems and provides recommendations. Focus on methodology and deliverables.

Specific output format: what kind of recommendations, metrics, or code examples the agent provides.
```

## Agent Integration

Agents work with project rules in [`../rules/`](../rules/):

| Agent | Related Rules |
|-------|---------------|
| Python Specialist | `python-code-style.md`, `python-async.md`, `python-performance.md` |
| Testing Expert | `python-testing.md` |
| Security Auditor | `python-security.md` |
| Code Reviewer | All rules files |
| Performance Optimizer | `python-performance.md`, `python-async.md` |

## Best Practices

**Good use cases**:
- Complex problems requiring domain expertise
- Code reviews and quality assessments
- Security audits and performance optimization
- Architectural decisions

**Not ideal for**:
- Simple syntax questions (use rules instead)
- Basic documentation lookup
- Trivial code changes

**Effective interaction**:
1. Be specific with context and goals
2. Include relevant code snippets
3. Mention constraints and requirements
4. Request alternatives when appropriate

---

**Note**: Agents provide recommendations based on best practices and project context. Always review suggestions before implementation.
