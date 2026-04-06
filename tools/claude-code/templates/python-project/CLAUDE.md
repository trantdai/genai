# Python Project Guide

## Project Overview

Modern Python project template with optimized Claude Code configuration. Emphasizes type safety, testing, security, and async patterns.

**Stack**: Python 3.13+, Black/Ruff, mypy, pytest, Pydantic v2+, asyncio

## Project Structure

```
project/
├── src/<package>/         # Application code (src-layout)
│   ├── models/           # Pydantic models
│   ├── services/         # Business logic
│   ├── repositories/     # Data access
│   └── utils/           # Utilities
├── tests/                # Test suite (mirrors src)
├── .claude/              # Claude Code configuration (~1,700 lines)
│   ├── settings.json    # Core permissions & restrictions
│   ├── rules/           # Development standards (5 files)
│   ├── skills/          # Workflow checklists (4 files)
│   ├── agents/          # Specialized AI agents (5 agents)
│   └── hooks/           # Git & Claude hooks
├── pyproject.toml        # Dependencies & tool config
└── requirements.txt      # Pinned dependencies
```

## Development Standards

All standards are defined in [`.claude/rules/`](.claude/rules/):

- **Code Style**: [python-code-style.md](.claude/rules/python-code-style.md) - PEP 8, type hints, 100-char lines
- **Testing**: [python-testing.md](.claude/rules/python-testing.md) - pytest, 80%+ coverage, fixtures
- **Security**: [python-security.md](.claude/rules/python-security.md) - Input validation, bcrypt, secrets management
- **Async**: [python-async.md](.claude/rules/python-async.md) - asyncio, asyncpg, httpx patterns
- **Performance**: [python-performance.md](.claude/rules/python-performance.md) - Data structures, profiling, caching

## Workflows

Workflow checklists in [`.claude/skills/`](.claude/skills/):

- **TDD**: [tdd-workflow.md](.claude/skills/tdd-workflow.md) - Red-Green-Refactor cycle
- **Code Review**: [code-review-workflow.md](.claude/skills/code-review-workflow.md) - Review checklist
- **Refactoring**: [refactoring-workflow.md](.claude/skills/refactoring-workflow.md) - Safe refactoring steps
- **Security Audit**: [security-audit.md](.claude/skills/security-audit.md) - Security scan workflow
- **Performance Analysis**: [performance-analysis.md](.claude/skills/performance-analysis.md) - Profiling workflow

## Development Commands

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

# Quality Checks
black src tests                    # Format
ruff check src tests --fix         # Lint
mypy src                           # Type check
pytest --cov=src --cov-fail-under=80  # Test

# Security
pip-audit                          # CVE scan
bandit -r src/                     # Security linter
detect-secrets scan                # Secret detection
```

## Specialized Agents

Available in [`.claude/agents/`](.claude/agents/):

- **python-specialist**: Code review, async patterns, design patterns
- **testing-expert**: Test strategy, coverage improvement (80%+ target)
- **security-auditor**: Vulnerability detection, OWASP compliance
- **code-reviewer**: Architecture review, SOLID principles
- **performance-optimizer**: Profiling, database optimization, memory leaks

## Configuration

**Settings**: [`.claude/settings.json`](.claude/settings.json)
- Permissions (file operations, commands, network)
- Command restrictions (allow/block lists)
- File patterns (editable/readonly/forbidden)
- Environment variables (allowed/blocked)

**Local Overrides**: Copy `.claude/settings.local.json.example` to `settings.local.json`

## Key Principles

- **Type Safety**: Type hints everywhere, mypy strict mode
- **Test First**: TDD approach, 80%+ coverage minimum
- **Async I/O**: Use async for all I/O operations
- **Security**: Validate inputs, Pydantic at boundaries, no hardcoded secrets
- **Performance**: Profile before optimizing, use appropriate data structures

## Task Checklist

- [ ] Type hints on all functions
- [ ] Tests passing (80%+ coverage)
- [ ] Security reviewed (input validation, no secrets)
- [ ] Code formatted (Black, Ruff)
- [ ] Type checking passes (mypy)
- [ ] Error handling with specific exceptions

---

*Configuration optimized to ~1,700 lines (28% reduction from baseline). See `.claude/rules/` for detailed standards.*
