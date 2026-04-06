# Technical Specification - Part 1
# API Security Scanner MVP
# Overview & Architecture

**Version:** 1.0
**Date:** April 4, 2026
**Status:** Draft

---

## Table of Contents

- [1. System Overview](#1-system-overview)
- [2. Architecture](#2-architecture)
- [3. Technology Stack](#3-technology-stack)
- [4. Design Principles](#4-design-principles)

---

## 1. System Overview

### 1.1 Purpose

API Security Scanner is a command-line tool that automates security vulnerability detection in REST APIs. It performs black-box testing by sending crafted requests and analyzing responses to identify common security issues.

### 1.2 Scope

**In Scope:**
- REST API security scanning
- SQL injection detection
- XSS vulnerability detection
- Authentication/authorization testing
- JSON report generation
- CLI interface
- Bearer token and API key authentication

**Out of Scope (MVP):**
- GraphQL API scanning
- SOAP API scanning
- Web application scanning
- Authenticated session management
- Database direct access
- Source code analysis
- Network-level scanning

### 1.3 Key Features

1. **Automated Vulnerability Detection**
   - SQL injection testing
   - XSS vulnerability detection
   - Authentication weakness identification

2. **Flexible Authentication**
   - Bearer token support
   - API key support
   - Custom header support

3. **Comprehensive Reporting**
   - JSON structured output
   - Severity classification
   - Remediation guidance

4. **Developer-Friendly CLI**
   - Simple command structure
   - Progress indicators
   - Clear error messages

### 1.4 System Constraints

**Performance Constraints:**
- Maximum 10 concurrent requests
- 60-second timeout per request
- 2-minute maximum scan time for 10 endpoints

**Resource Constraints:**
- Maximum 100MB memory usage
- Maximum 50MB report file size
- Minimum Python 3.13 required

**Security Constraints:**
- No credential storage
- HTTPS-only for remote APIs
- Safe test payloads only
- No destructive testing

---

## 2. Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Commands   │  │   Options    │  │   Output     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      Scanner Engine                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Discovery   │  │   Testing    │  │  Analysis    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Vulnerability Checkers                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ SQL Injection│  │     XSS      │  │     Auth     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      HTTP Client Layer                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Requests   │  │   Retries    │  │   Pooling    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      Report Generator                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │     JSON     │  │   Severity   │  │  Remediation │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Component Architecture

#### 2.2.1 CLI Layer
**Responsibility:** User interaction and command processing

**Components:**
- Command parser (Click framework)
- Argument validator
- Progress display
- Output formatter

**Interactions:**
- Receives user input
- Validates arguments
- Invokes scanner engine
- Displays results

#### 2.2.2 Scanner Engine
**Responsibility:** Orchestrate scanning workflow

**Components:**
- Endpoint discovery
- Test coordinator
- Result aggregator
- Error handler

**Interactions:**
- Discovers API endpoints
- Coordinates vulnerability checkers
- Aggregates findings
- Handles errors gracefully

#### 2.2.3 Vulnerability Checkers
**Responsibility:** Detect specific vulnerability types

**Components:**
- SQL injection checker
- XSS checker
- Authentication checker

**Interactions:**
- Receive endpoint information
- Generate test payloads
- Analyze responses
- Report findings

#### 2.2.4 HTTP Client Layer
**Responsibility:** HTTP communication

**Components:**
- Async HTTP client (httpx)
- Connection pooling
- Retry logic
- Rate limiting

**Interactions:**
- Send HTTP requests
- Handle responses
- Manage connections
- Respect rate limits

#### 2.2.5 Report Generator
**Responsibility:** Generate scan reports

**Components:**
- JSON formatter
- Severity classifier
- Remediation mapper

**Interactions:**
- Receive findings
- Format output
- Add metadata
- Write to file

### 2.3 Data Flow

```
1. User Input
   └─> CLI validates arguments
       └─> Scanner Engine initializes

2. Discovery Phase
   └─> HTTP Client fetches API
       └─> Scanner discovers endpoints
           └─> Endpoint list created

3. Testing Phase
   └─> For each endpoint:
       └─> SQL Injection Checker tests
       └─> XSS Checker tests
       └─> Auth Checker tests
           └─> Findings collected

4. Analysis Phase
   └─> Scanner aggregates findings
       └─> Severity assigned
           └─> Remediation added

5. Reporting Phase
   └─> Report Generator formats output
       └─> JSON file written
           └─> Summary displayed
```

### 2.4 Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Developer Machine                         │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │              Python Environment                     │    │
│  │  ┌──────────────────────────────────────────────┐  │    │
│  │  │        API Security Scanner                   │  │    │
│  │  │  - CLI executable                             │  │    │
│  │  │  - Python packages                            │  │    │
│  │  │  - Configuration files                        │  │    │
│  │  └──────────────────────────────────────────────┘  │    │
│  └────────────────────────────────────────────────────┘    │
│                          │                                   │
│                          │ HTTPS                             │
│                          ▼                                   │
└─────────────────────────────────────────────────────────────┘
                           │
                           │
┌──────────────────────────┼──────────────────────────────────┐
│                          │                                   │
│                          ▼                                   │
│  ┌────────────────────────────────────────────────────┐    │
│  │              Target API Server                      │    │
│  │  - REST API endpoints                               │    │
│  │  - Authentication layer                             │    │
│  │  - Business logic                                   │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Technology Stack

### 3.1 Core Technologies

#### Programming Language
- **Python 3.13+**
  - Rationale: Modern async support, type hints, performance
  - Features used: async/await, type hints, dataclasses

#### HTTP Client
- **httpx 0.25+**
  - Rationale: Async support, HTTP/2, connection pooling
  - Features used: AsyncClient, connection pooling, timeouts

#### Data Validation
- **Pydantic 2.5+**
  - Rationale: Type safety, validation, serialization
  - Features used: BaseModel, Field validation, JSON schema

#### CLI Framework
- **Click 8.1+**
  - Rationale: Simple API, good documentation, wide adoption
  - Features used: Commands, options, help text, colors

### 3.2 Development Tools

#### Code Quality
```python
# pyproject.toml
[tool.black]
line-length = 100
target-version = ['py313']

[tool.ruff]
line-length = 100
select = ["E", "F", "I", "N", "W", "UP"]

[tool.mypy]
python_version = "3.13"
strict = true
```

#### Testing
- **pytest 7.4+**: Test framework
- **pytest-asyncio 0.21+**: Async test support
- **pytest-mock 3.12+**: Mocking framework
- **pytest-cov**: Coverage reporting

#### Security
- **bandit**: Security linting
- **safety**: Dependency scanning
- **pip-audit**: Vulnerability checking

### 3.3 Dependencies

```toml
[project]
name = "api-security-scanner"
version = "0.1.0"
requires-python = ">=3.13"

dependencies = [
    "httpx>=0.25.0",
    "pydantic>=2.5.0",
    "click>=8.1.0",
    "rich>=13.0.0",  # Terminal formatting
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "pytest-mock>=3.12.0",
    "pytest-cov>=4.1.0",
    "black>=23.10.0",
    "ruff>=0.1.0",
    "mypy>=1.6.0",
    "bandit>=1.7.0",
    "safety>=2.3.0",
]
```

---

## 4. Design Principles

### 4.1 SOLID Principles

#### Single Responsibility Principle
Each class has one reason to change:
- `SQLInjectionChecker`: Only SQL injection detection
- `XSSChecker`: Only XSS detection
- `ReportGenerator`: Only report generation

#### Open/Closed Principle
Open for extension, closed for modification:
- New vulnerability checkers can be added without modifying scanner
- New report formats can be added without changing core logic

#### Liskov Substitution Principle
All checkers implement `VulnerabilityChecker` interface:
```python
class VulnerabilityChecker(Protocol):
    async def check(self, endpoint: Endpoint) -> list[Finding]:
        ...
```

#### Interface Segregation Principle
Small, focused interfaces:
- `VulnerabilityChecker`: Only checking logic
- `ReportFormatter`: Only formatting logic
- `HTTPClient`: Only HTTP operations

#### Dependency Inversion Principle
Depend on abstractions, not concretions:
- Scanner depends on `VulnerabilityChecker` interface
- Checkers depend on `HTTPClient` interface

### 4.2 Design Patterns

#### Strategy Pattern
Different vulnerability checking strategies:
```python
class Scanner:
    def __init__(self, checkers: list[VulnerabilityChecker]):
        self.checkers = checkers

    async def scan(self, endpoint: Endpoint) -> list[Finding]:
        findings = []
        for checker in self.checkers:
            findings.extend(await checker.check(endpoint))
        return findings
```

#### Factory Pattern
Create checkers based on configuration:
```python
class CheckerFactory:
    @staticmethod
    def create_checkers(config: ScanConfig) -> list[VulnerabilityChecker]:
        checkers = []
        if config.check_sql_injection:
            checkers.append(SQLInjectionChecker())
        if config.check_xss:
            checkers.append(XSSChecker())
        return checkers
```

#### Builder Pattern
Build scan configuration:
```python
class ScanConfigBuilder:
    def __init__(self):
        self._config = ScanConfig()

    def with_auth(self, token: str) -> Self:
        self._config.auth_token = token
        return self

    def with_timeout(self, timeout: int) -> Self:
        self._config.timeout = timeout
        return self

    def build(self) -> ScanConfig:
        return self._config
```

### 4.3 Async/Await Architecture

#### Async-First Design
All I/O operations are async:
```python
async def scan_endpoint(endpoint: Endpoint) -> list[Finding]:
    async with httpx.AsyncClient() as client:
        # Concurrent vulnerability checks
        tasks = [
            check_sql_injection(client, endpoint),
            check_xss(client, endpoint),
            check_auth(client, endpoint),
        ]
        results = await asyncio.gather(*tasks)
        return flatten(results)
```

#### Concurrency Control
Limit concurrent requests:
```python
semaphore = asyncio.Semaphore(10)  # Max 10 concurrent

async def check_with_limit(endpoint: Endpoint) -> Finding:
    async with semaphore:
        return await check_endpoint(endpoint)
```

### 4.4 Error Handling Strategy

#### Graceful Degradation
Continue scanning even if one check fails:
```python
async def scan_endpoint(endpoint: Endpoint) -> list[Finding]:
    findings = []
    for checker in checkers:
        try:
            result = await checker.check(endpoint)
            findings.extend(result)
        except CheckerError as e:
            logger.warning(f"Checker failed: {e}")
            # Continue with other checkers
    return findings
```

#### Retry Logic
Retry transient failures:
```python
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(httpx.TransportError)
)
async def make_request(url: str) -> httpx.Response:
    async with httpx.AsyncClient() as client:
        return await client.get(url)
```

### 4.5 Security-First Design

#### Safe by Default
- No credential storage
- HTTPS-only for remote APIs
- Safe test payloads
- No destructive operations

#### Input Validation
All inputs validated with Pydantic:
```python
class ScanRequest(BaseModel):
    url: HttpUrl  # Validates URL format
    auth_token: SecretStr | None = None  # Protects secrets
    timeout: int = Field(ge=1, le=300)  # Range validation
```

#### Output Sanitization
Sanitize sensitive data in reports:
```python
def sanitize_response(response: str) -> str:
    # Remove potential secrets from response
    return re.sub(
        r'(token|key|password)=[^&\s]+',
        r'\1=***REDACTED***',
        response
    )
```

---

## Next Parts

- **Part 2:** System Components (detailed component specifications)
- **Part 3:** API & Data Models (interfaces and data structures)
- **Part 4:** Security & Testing (security measures and test strategy)
- **Part 5:** Deployment & Operations (deployment and monitoring)

---

**Document Status:** ✅ Complete - Part 1 of 5
