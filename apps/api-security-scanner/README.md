# API Security Scanner MVP

> A command-line tool for detecting security vulnerabilities in REST APIs

**Version:** 0.1.0 (MVP)
**Status:** Planning & Documentation Phase
**Python:** 3.11+

---

## 📋 Documentation Index

This project follows a comprehensive documentation structure to support development using Claude Code capabilities.

### Core Documentation

#### 1. [Product Requirements Document (PRD)](docs/PRD.md)
**Purpose:** Defines what we're building and why

**Contents:**
- Executive summary and problem statement
- Target users and personas
- Product goals and success metrics
- Feature requirements (must-have, should-have, nice-to-have)
- User workflows and examples
- Technical requirements and dependencies
- Success criteria and timeline

**Read this first to understand:** The product vision, user needs, and business requirements.

#### 2. [Technical Specification - Part 1: Overview & Architecture](docs/TECHNICAL_SPEC_PART1.md)
**Purpose:** High-level system design and architecture

**Contents:**
- System overview and scope
- High-level architecture diagrams
- Technology stack decisions
- Design principles (SOLID, patterns)
- Async/await architecture
- Security-first design approach

**Read this to understand:** How the system is architected and why specific technologies were chosen.

#### 3. [Technical Specification - Part 2: System Components](docs/TECHNICAL_SPEC_PART2.md)
**Purpose:** Detailed component specifications and implementation

**Contents:**
- CLI module implementation
- Scanner engine architecture
- Vulnerability checker modules (SQL injection, XSS, Auth)
- Report generator implementation
- Project structure and module dependencies
- Class diagrams and relationships

**Read this to understand:** How each component works and how they interact.

### Additional Documentation (To Be Created)

#### 4. Technical Specification - Part 3: API & Data Models
- Pydantic models and schemas
- API interfaces and protocols
- Data validation rules
- Serialization/deserialization

#### 5. Technical Specification - Part 4: Security & Testing
- Security measures and threat model
- Test strategy and coverage requirements
- CI/CD pipeline configuration
- Quality assurance processes

#### 6. Technical Specification - Part 5: Deployment & Operations
- Installation and setup
- Configuration management
- Deployment procedures
- Monitoring and logging

#### 7. User Guide
- Installation instructions
- Quick start tutorial
- Usage examples
- Troubleshooting guide

#### 8. API Documentation
- CLI command reference
- Configuration options
- Report format specification
- Extension points

---

## 🎯 Project Overview

### What is API Security Scanner?

API Security Scanner is a developer-friendly CLI tool that automatically detects common security vulnerabilities in REST APIs. It performs black-box testing by sending crafted requests and analyzing responses to identify issues like SQL injection, XSS, and authentication weaknesses.

### Key Features (MVP)

✅ **SQL Injection Detection** - Identifies SQL injection vulnerabilities
✅ **XSS Detection** - Finds Cross-Site Scripting issues
✅ **Authentication Testing** - Checks auth/authorization weaknesses
✅ **JSON Reports** - Machine-readable output for CI/CD
✅ **Simple CLI** - Easy-to-use command-line interface
✅ **Async Architecture** - Fast concurrent scanning

### Why This Project?

This project serves as a **showcase for Claude Code capabilities**:

- **CLAUDE.md**: Enforces Python best practices and security standards
- **Settings.json**: Security-first configuration with restricted operations
- **Agents**: Security Auditor, Python Specialist, Testing Expert, Code Reviewer, Performance Optimizer
- **Hooks**: Automated quality checks (pre-commit, pre-push, post-tool-use)
- **Rules**: Python coding standards, security rules, testing requirements
- **Skills**: TDD workflow, security audit workflow, code review workflow

---

## 🏗️ Architecture at a Glance

```
┌─────────────┐
│     CLI     │  ← User interaction
└──────┬──────┘
       │
┌──────▼──────┐
│   Scanner   │  ← Orchestration
└──────┬──────┘
       │
┌──────▼──────────────────────┐
│  Vulnerability Checkers     │  ← Detection logic
│  • SQL Injection            │
│  • XSS                      │
│  • Authentication           │
└──────┬──────────────────────┘
       │
┌──────▼──────┐
│   Reports   │  ← Output generation
└─────────────┘
```

---

## 🚀 Quick Start (Planned)

```bash
# Install
pip install api-security-scanner

# Scan an API
api-scanner scan https://api.example.com

# Scan with authentication
api-scanner scan https://api.example.com \
  --auth-token "Bearer your-token-here" \
  --output report.json

# View results
cat report.json
```

---

## 📊 Development Timeline

### Phase 1: Documentation (Current) ✅
- [x] Product Requirements Document
- [x] Technical Specification Part 1 (Architecture)
- [x] Technical Specification Part 2 (Components)
- [ ] Technical Specification Part 3 (Data Models)
- [ ] Technical Specification Part 4 (Security & Testing)
- [ ] Technical Specification Part 5 (Deployment)
- [ ] User Guide
- [ ] API Documentation

### Phase 2: Implementation (4-6 hours)
- [ ] Project setup with Claude Code template
- [ ] Core scanner engine
- [ ] Vulnerability checkers
- [ ] CLI interface
- [ ] Report generation

### Phase 3: Testing (1-2 hours)
- [ ] Unit tests (80%+ coverage)
- [ ] Integration tests
- [ ] Security validation

### Phase 4: Documentation & Release (1 hour)
- [ ] User documentation
- [ ] Examples and tutorials
- [ ] PyPI package

**Total Estimated Time:** 8-12 hours with Claude Code assistance

---

## 🛠️ Technology Stack

### Core Technologies
- **Python 3.11+** - Modern async support, type hints
- **httpx** - Async HTTP client
- **Pydantic** - Data validation and serialization
- **Click** - CLI framework
- **Rich** - Terminal formatting

### Development Tools
- **pytest** - Testing framework
- **Black** - Code formatting
- **Ruff** - Fast linting
- **mypy** - Type checking
- **Bandit** - Security linting

### Claude Code Integration
- **CLAUDE.md** - Project standards
- **settings.json** - Security configuration
- **Agents** - AI specialists
- **Hooks** - Quality automation
- **Rules** - Coding standards
- **Skills** - Workflow templates

---

## 🎓 Learning Objectives

This project demonstrates:

1. **Security-First Development**
   - OWASP Top 10 vulnerability detection
   - Secure coding practices
   - Input validation and sanitization

2. **Modern Python Patterns**
   - Async/await architecture
   - Type hints and Pydantic models
   - Protocol-based interfaces

3. **Test-Driven Development**
   - 80%+ test coverage
   - pytest best practices
   - Mocking with pytest-mock

4. **CLI Development**
   - Click framework usage
   - Rich terminal output
   - User experience design

5. **Claude Code Capabilities**
   - AI-assisted development
   - Automated quality checks
   - Multi-agent collaboration

---

## 📁 Project Structure (Planned)

```
api-security-scanner/
├── docs/                          # Documentation
│   ├── PRD.md                    # Product requirements
│   ├── TECHNICAL_SPEC_PART1.md   # Architecture
│   ├── TECHNICAL_SPEC_PART2.md   # Components
│   └── ...                       # Additional docs
├── src/
│   └── api_security_scanner/
│       ├── cli/                  # CLI interface
│       ├── scanner/              # Scanner engine
│       ├── checkers/             # Vulnerability checkers
│       ├── reports/              # Report generation
│       ├── models/               # Data models
│       └── utils/                # Utilities
├── tests/                        # Test suite
│   ├── unit/                     # Unit tests
│   ├── integration/              # Integration tests
│   └── conftest.py               # Test configuration
├── .claude/                      # Claude Code configuration
│   ├── settings.json             # Security settings
│   ├── agents/                   # AI agents
│   ├── hooks/                    # Quality hooks
│   ├── rules/                    # Coding rules
│   └── skills/                   # Workflows
├── pyproject.toml                # Project configuration
├── requirements.txt              # Dependencies
├── requirements-dev.txt          # Dev dependencies
└── README.md                     # This file
```

---

## 🤝 Contributing

This project is built using Claude Code capabilities. To contribute:

1. **Review Documentation** - Read PRD and Technical Specs
2. **Follow Standards** - Check CLAUDE.md for coding standards
3. **Use Hooks** - Install pre-commit hooks for quality checks
4. **Write Tests** - Maintain 80%+ coverage
5. **Security First** - Follow security guidelines

---

## 📝 License

MIT License - See LICENSE file for details

---

## 🔗 Related Resources

### OWASP Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Python Resources
- [Python Async/Await](https://docs.python.org/3/library/asyncio.html)
- [Pydantic Documentation](https://docs.pydantic.dev/)
- [httpx Documentation](https://www.python-httpx.org/)

### Claude Code Resources
- [Claude Code Template](../../tools/claude-code/templates/python-project/)
- [Python Development Standards](../../tools/claude-code/templates/python-project/CLAUDE.md)

---

## 📧 Contact

For questions or feedback about this project, please open an issue in the repository.

---

**Status:** 📝 Documentation Phase Complete (Parts 1-2)
**Next Steps:** Complete remaining technical specification parts, then begin implementation

---

*Built with ❤️ using Claude Code capabilities*
