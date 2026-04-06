# Python Project Template

## Purpose

Foundational Python project template for Claude Code with optimized configuration. Establishes modern Python patterns, development tools, and AI-assisted development workflows.

**Key Features:**
- Modern Python 3.13+ with src-layout structure
- Type-safe development (mypy strict mode)
- Comprehensive testing (pytest, 80%+ coverage)
- Security-first approach (Pydantic validation, secrets management)
- Async I/O patterns (asyncio, asyncpg, httpx)
- Performance optimization guidance
- Git hooks and automation

## Contents

### Core Structure
- **src-layout** package organization
- **pyproject.toml** - Modern Python tooling configuration
- **requirements.txt** - Pinned dependencies for reproducibility
- **tests/** - Test suite with unit/integration/e2e organization

### Development Tools
- **Black** (formatting, 100-char lines)
- **Ruff** (linting, import sorting)
- **mypy** (type checking, strict mode)
- **pytest** (testing framework)
- **pytest-cov** (coverage reporting)
- **pytest-mock** (mocking)
- **pytest-asyncio** (async testing)

### Security Tools
- **bandit** - Python security linter
- **safety** - Dependency vulnerability scanner
- **pip-audit** - CVE scanning
- **detect-secrets** - Secret detection

### Claude Code Configuration (~1,700 lines)

Optimized `.claude/` directory structure:

```
.claude/
├── settings.json                 # Core permissions & restrictions (251 lines)
├── settings.local.json.example   # Local override template (33 lines)
├── rules/                        # Development standards (894 lines)
│   ├── python-code-style.md     # PEP 8, type hints, formatting
│   ├── python-testing.md        # pytest, coverage, fixtures
│   ├── python-security.md       # Input validation, auth, secrets
│   ├── python-async.md          # asyncio patterns, best practices
│   └── python-performance.md    # Data structures, profiling, optimization
├── skills/                       # Workflow checklists (203 lines)
│   ├── tdd-workflow.md          # Test-driven development
│   ├── code-review-workflow.md  # Review checklist
│   ├── refactoring-workflow.md  # Safe refactoring steps
│   ├── security-audit.md        # Security scan workflow
│   └── performance-analysis.md  # Profiling workflow
├── agents/                       # Specialized AI agents (176 lines)
│   ├── README.md                # Agent usage guide
│   ├── python-specialist.md     # Code review, design patterns
│   ├── testing-expert.md        # Test strategy, coverage
│   ├── security-auditor.md      # Vulnerability detection
│   ├── code-reviewer.md         # Architecture review
│   └── performance-optimizer.md # Profiling, optimization
└── hooks/                        # Automation hooks (447 lines)
    ├── README.md                # Hook system overview
    ├── INSTALLATION.md          # Quick setup guide
    ├── TROUBLESHOOTING.md       # Common issues
    ├── git/                     # Git hooks (pre-commit, pre-push, etc.)
    ├── claude/                  # Claude Code hooks (JSON)
    └── utils/                   # Utility scripts
```

**Configuration Highlights:**
- **28% reduction** from baseline (663 lines removed)
- No duplication between files
- Generic for any Python project
- Cross-references using relative paths
- Concise, actionable guidance

### Git Hooks
- **pre-commit** - Format (Black), lint (Ruff), type check (mypy)
- **pre-push** - Run tests, coverage check (80%), security scan
- **commit-msg** - Conventional commit format validation
- **post-checkout/post-merge** - Auto-sync dependencies

## Usage

### Quick Start

```bash
# 1. Create project from template
cp -r python-project my-project
cd my-project

# 2. Setup environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

# 3. Install hooks
pip install pre-commit
pre-commit install
pre-commit install --hook-type commit-msg

# 4. Customize for your project
# Edit pyproject.toml, update package name in src/
# Copy .claude/settings.local.json.example to settings.local.json
```

### Development Workflow

```bash
# Format and lint
black src tests
ruff check src tests --fix

# Type check
mypy src

# Run tests
pytest --cov=src --cov-report=html

# Security scan
pip-audit
bandit -r src/
```

### Specialized Agents

Invoke Claude Code agents for domain-specific assistance:

```
"Python Specialist: review this async implementation"
"Security Auditor: check auth code for vulnerabilities"
"Testing Expert: improve test coverage for user service"
"Performance Optimizer: analyze database query performance"
```

## Integration

This base component combines with other templates:

- **FastAPI**: Add REST API functionality
- **Django**: Add web framework
- **Data Science**: Add pandas, jupyter, visualization
- **CLI Tools**: Add click, argparse patterns
- **ML/AI**: Add scikit-learn, torch, transformers

## Standards Reference

All development standards defined in `.claude/rules/`:

- **Code Style**: Type hints mandatory, 100-char lines, PEP 8
- **Testing**: pytest only, 80%+ coverage, AAA pattern
- **Security**: Pydantic validation, bcrypt passwords, no hardcoded secrets
- **Async**: Use async for I/O, connection pooling, rate limiting
- **Performance**: Profile first, O(n log n) max, use generators

## Documentation

- **[CLAUDE.md](CLAUDE.md)** - Quick reference for Claude Code
- **[SETTINGS-README.md](SETTINGS-README.md)** - Settings configuration guide
- **[.claude/rules/](. claude/rules/)** - Detailed development standards
- **[.claude/skills/](.claude/skills/)** - Workflow checklists
- **[.claude/agents/](.claude/agents/)** - Specialized agent descriptions

## Technical Specification

Based on **Section 1.2** (Core Architecture) and **Section 3** (Python Standards):
- PEP 8 compliance
- Type hints with mypy strict mode
- Modern Python 3.13+ features
- Async-first I/O patterns
- Security-first development
- 80%+ test coverage minimum

---

**Configuration Size**: ~1,700 lines (optimized)
**Python Version**: 3.13+
**License**: MIT
