# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

API Security Scanner is a Python CLI tool for detecting security vulnerabilities in REST APIs. The project performs black-box testing to identify SQL injection, XSS, and authentication weaknesses.

**Current Status:** Documentation phase complete (PRD + Technical Specs Part 1-2). Implementation not yet started.

**Technology Stack:**
- Python 3.11+ (async/await, type hints)
- httpx (async HTTP client)
- Pydantic (data validation)
- Click (CLI framework)
- Rich (terminal formatting)

## Development Commands

### Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/api_security_scanner --cov-report=term-missing

# Run specific test file
pytest tests/unit/test_scanner.py

# Run with verbose output
pytest -v

# Run async tests
pytest -k "async" --asyncio-mode=auto
```

### Code Quality
```bash
# Format code
black src/ tests/

# Lint code
ruff check src/ tests/

# Type checking
mypy src/

# Security linting
bandit -r src/

# Run all quality checks
black src/ tests/ && ruff check src/ tests/ && mypy src/ && bandit -r src/
```

### Running the Tool (when implemented)
```bash
# Install in development mode
pip install -e .

# Basic scan
api-scanner scan https://api.example.com

# Scan with authentication
api-scanner scan https://api.example.com --auth-token "Bearer token"

# Custom output location
api-scanner scan https://api.example.com --output report.json
```

## Architecture Overview

### High-Level Structure
```
CLI Layer → Scanner Engine → Vulnerability Checkers → HTTP Client
                          ↓
                   Report Generator
```

### Core Components

**Scanner Engine** (`scanner/engine.py`)
- Orchestrates the scanning workflow
- Three phases: Discovery → Testing → Analysis
- Manages concurrent request execution with asyncio
- Coordinates all vulnerability checkers

**Vulnerability Checkers** (`checkers/`)
- Implement `VulnerabilityChecker` protocol
- Each checker is independent and focused on one vulnerability type
- SQL Injection: Tests with crafted payloads, detects SQL error patterns
- XSS: Tests reflected XSS, checks security headers
- Authentication: Tests missing auth, invalid tokens

**Endpoint Discovery** (`scanner/discovery.py`)
- Attempts OpenAPI/Swagger spec parsing
- Falls back to common path probing
- Deduplicates discovered endpoints

**Report Generator** (`reports/json_generator.py`)
- Generates structured JSON reports
- Includes severity classification, remediation guidance
- Maps to CWE IDs and OWASP categories

### Design Patterns

**Strategy Pattern:** Different vulnerability checkers as pluggable strategies
**Protocol-Based:** Uses Python protocols for interfaces (not abstract base classes)
**Async/Await:** All I/O operations are async with concurrency limits
**Factory Pattern:** CheckerFactory creates checkers based on config
**Builder Pattern:** ScanConfigBuilder for configuration assembly

### Key Design Principles

1. **SOLID Principles Enforced:**
   - Single Responsibility: Each checker handles one vulnerability type
   - Open/Closed: New checkers can be added without modifying Scanner
   - Interface Segregation: Small, focused protocols
   - Dependency Inversion: Depend on VulnerabilityChecker protocol

2. **Async-First Architecture:**
   - All HTTP operations use httpx.AsyncClient
   - Concurrent scanning with asyncio.gather()
   - Semaphore limits (max 10 concurrent requests)
   - Graceful error handling with return_exceptions=True

3. **Security-First:**
   - No credential storage
   - HTTPS-only for remote APIs
   - Safe test payloads (no destructive operations)
   - Output sanitization for sensitive data
   - Pydantic SecretStr for auth tokens

## Critical Implementation Notes

### Async/Await Requirements
- Always use `async def` for I/O operations
- Use `async with` for httpx.AsyncClient
- Properly await all async calls
- Use `asyncio.gather()` for concurrent operations
- Set appropriate timeouts on all HTTP requests

### Type Hints Standards
- Full type hints required (mypy strict mode)
- Use `list[Type]` not `List[Type]` (Python 3.11+)
- Use `Type | None` not `Optional[Type]`
- Protocol classes for interfaces, not ABCs
- Pydantic models for data validation

### Error Handling Strategy
- Graceful degradation: Continue scanning if one checker fails
- Log warnings for non-critical errors
- Retry transient HTTP failures (httpx.TransportError)
- Use structured logging with context

### Testing Requirements
- 80%+ test coverage mandatory
- Use pytest-asyncio for async tests
- Mock HTTP calls with pytest-mock
- Separate unit tests (checkers) from integration tests (scanner)
- Test both success and failure cases

## Project Structure (When Implemented)

```
src/api_security_scanner/
├── cli/                  # Click commands, Rich terminal output
├── scanner/              # Scanner engine, endpoint discovery, config
├── checkers/             # Vulnerability checkers (SQL, XSS, Auth)
├── reports/              # Report generators (JSON format)
├── models/               # Pydantic models (Endpoint, Finding, Results)
└── utils/                # HTTP utilities, logging setup

tests/
├── unit/                 # Unit tests for individual components
├── integration/          # Integration tests for full workflows
└── conftest.py           # Shared pytest fixtures
```

## Documentation Resources

- **PRD:** `docs/PRD.md` - Product vision, user personas, success metrics
- **Technical Spec Part 1:** `docs/TECHNICAL_SPEC_PART1.md` - Architecture, tech stack, design principles
- **Technical Spec Part 2:** `docs/TECHNICAL_SPEC_PART2.md` - Detailed component implementations, class diagrams

Read these documents before implementing features to understand the complete design.

## Security Considerations

### OWASP Focus
- SQL Injection (CWE-89, OWASP A03:2021)
- Cross-Site Scripting (CWE-79, OWASP A03:2021)
- Authentication Failures (CWE-287, OWASP A07:2021)

### Safe Testing Principles
- Use non-destructive test payloads
- Respect rate limits and timeouts
- No credential storage or logging
- Sanitize responses before storing in reports
- HTTPS-only for remote targets

### Security Linting
- Run bandit on all new code
- No hardcoded secrets or credentials
- Validate all user inputs with Pydantic
- Use SecretStr for sensitive strings

## Performance Constraints

- Maximum 10 concurrent requests (configurable)
- 60-second timeout per request (default 30s)
- 2-minute maximum scan time for 10 endpoints
- Maximum 100MB memory usage
- Connection pooling via httpx

## Dependencies Management

All dependencies specified in `pyproject.toml`:
- Use `requires-python = ">=3.11"`
- Pin major versions for stability
- Separate `[project.optional-dependencies]` for dev tools
- Run `pip-audit` to check for vulnerabilities

## Common Pitfalls to Avoid

1. **Don't use sync HTTP libraries** - Use httpx async client only
2. **Don't forget await** - All async functions must be awaited
3. **Don't block event loop** - Keep all I/O operations async
4. **Don't use generic Exception** - Catch specific exceptions (httpx.HTTPError)
5. **Don't concatenate SQL** - This is a security scanner; code must be exemplary
6. **Don't store credentials** - Accept as parameters only
7. **Don't use print()** - Use Rich console for output, logging for debug
8. **Don't skip type hints** - mypy strict mode is enforced
