# Python Development Agents

Specialized AI agents for domain-specific Python development assistance.

## Available Agents

| Agent | Use For |
|-------|---------|
| **Python Specialist** | Code review, async patterns, design patterns, refactoring |
| **Testing Expert** | Test strategy, coverage (80%+), fixtures, integration testing |
| **Security Auditor** | Vulnerability detection, auth/authz, secrets, OWASP Top 10 |
| **Code Reviewer** | Pull requests, architecture review, technical debt, SOLID |
| **Performance Optimizer** | Profiling, database optimization, memory leaks, scalability |

## Usage

```
"Python Specialist: review this async implementation"
"Security Auditor: check auth code for vulnerabilities"
"Performance Optimizer: analyze database queries"
```

## Integration with Rules

| Agent | Related Rules |
|-------|---------------|
| Python Specialist | `python-code-style.md`, `python-async.md`, `python-performance.md` |
| Testing Expert | `python-testing.md` |
| Security Auditor | `python-security.md` |
| Code Reviewer | All rules files |
| Performance Optimizer | `python-performance.md`, `python-async.md` |
