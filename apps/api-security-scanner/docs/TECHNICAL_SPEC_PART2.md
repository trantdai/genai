# Technical Specification - Part 2
# API Security Scanner MVP
# System Components

**Version:** 1.0
**Date:** April 4, 2026
**Status:** Draft

---

## Table of Contents

- [5. System Components](#5-system-components)
- [6. Module Specifications](#6-module-specifications)
- [7. Class Diagrams](#7-class-diagrams)

---

## 5. System Components

### 5.1 CLI Module

**Location:** `src/api_security_scanner/cli/`

**Purpose:** Handle command-line interface and user interaction

#### 5.1.1 Command Structure

```python
# cli/main.py
import click
from rich.console import Console

@click.group()
@click.version_option(version="0.1.0")
def cli():
    """API Security Scanner - Detect vulnerabilities in REST APIs."""
    pass

@cli.command()
@click.argument("url")
@click.option("--auth-token", help="Bearer token for authentication")
@click.option("--api-key", help="API key for authentication")
@click.option("--output", "-o", help="Output file path", default="scan-report.json")
@click.option("--timeout", help="Request timeout in seconds", default=30)
@click.option("--concurrency", help="Max concurrent requests", default=10)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
async def scan(
    url: str,
    auth_token: str | None,
    api_key: str | None,
    output: str,
    timeout: int,
    concurrency: int,
    verbose: bool,
):
    """Scan an API for security vulnerabilities."""
    console = Console()

    # Validate inputs
    config = ScanConfig(
        url=url,
        auth_token=auth_token,
        api_key=api_key,
        timeout=timeout,
        concurrency=concurrency,
    )

    # Run scan
    scanner = Scanner(config)

    with console.status("[bold green]Scanning API..."):
        results = await scanner.scan()

    # Display results
    display_results(console, results)

    # Save report
    save_report(results, output)
    console.print(f"[green]✓[/green] Report saved to: {output}")
```

#### 5.1.2 Progress Display

```python
# cli/display.py
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

def display_results(console: Console, results: ScanResults):
    """Display scan results in terminal."""

    # Summary table
    table = Table(title="Scan Summary")
    table.add_column("Severity", style="cyan")
    table.add_column("Count", justify="right", style="magenta")

    table.add_row("Critical", str(results.critical_count), style="red")
    table.add_row("High", str(results.high_count), style="orange")
    table.add_row("Medium", str(results.medium_count), style="yellow")
    table.add_row("Low", str(results.low_count), style="green")

    console.print(table)

    # Detailed findings
    if results.findings:
        console.print("\n[bold]Findings:[/bold]")
        for finding in results.findings:
            display_finding(console, finding)

def display_finding(console: Console, finding: Finding):
    """Display individual finding."""
    severity_colors = {
        "critical": "red",
        "high": "orange",
        "medium": "yellow",
        "low": "green",
    }
    color = severity_colors.get(finding.severity, "white")

    console.print(f"\n[{color}]●[/{color}] {finding.title}")
    console.print(f"  Endpoint: {finding.endpoint}")
    console.print(f"  Severity: {finding.severity.upper()}")
    console.print(f"  Description: {finding.description}")
```

### 5.2 Scanner Engine Module

**Location:** `src/api_security_scanner/scanner/`

**Purpose:** Orchestrate the scanning workflow

#### 5.2.1 Scanner Class

```python
# scanner/engine.py
from typing import Protocol
import asyncio
import httpx

class Scanner:
    """Main scanner engine that orchestrates vulnerability detection."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = httpx.AsyncClient(
            timeout=config.timeout,
            limits=httpx.Limits(max_connections=config.concurrency),
        )
        self.checkers = self._create_checkers()

    def _create_checkers(self) -> list[VulnerabilityChecker]:
        """Create vulnerability checkers based on configuration."""
        return [
            SQLInjectionChecker(self.client),
            XSSChecker(self.client),
            AuthChecker(self.client),
        ]

    async def scan(self) -> ScanResults:
        """Execute complete security scan."""
        try:
            # Phase 1: Discovery
            endpoints = await self._discover_endpoints()

            # Phase 2: Testing
            findings = await self._test_endpoints(endpoints)

            # Phase 3: Analysis
            results = self._analyze_findings(findings)

            return results
        finally:
            await self.client.aclose()

    async def _discover_endpoints(self) -> list[Endpoint]:
        """Discover API endpoints."""
        discoverer = EndpointDiscoverer(self.client, self.config)
        return await discoverer.discover()

    async def _test_endpoints(self, endpoints: list[Endpoint]) -> list[Finding]:
        """Test all endpoints for vulnerabilities."""
        findings = []

        # Test endpoints concurrently
        tasks = [
            self._test_endpoint(endpoint)
            for endpoint in endpoints
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Test failed: {result}")
            else:
                findings.extend(result)

        return findings

    async def _test_endpoint(self, endpoint: Endpoint) -> list[Finding]:
        """Test single endpoint with all checkers."""
        findings = []

        for checker in self.checkers:
            try:
                result = await checker.check(endpoint)
                findings.extend(result)
            except CheckerError as e:
                logger.warning(f"Checker {checker.name} failed: {e}")

        return findings

    def _analyze_findings(self, findings: list[Finding]) -> ScanResults:
        """Analyze and categorize findings."""
        return ScanResults(
            findings=findings,
            total_endpoints=len(self.endpoints),
            scan_duration=self.duration,
            timestamp=datetime.now(),
        )
```

#### 5.2.2 Endpoint Discovery

```python
# scanner/discovery.py
class EndpointDiscoverer:
    """Discover API endpoints from base URL."""

    def __init__(self, client: httpx.AsyncClient, config: ScanConfig):
        self.client = client
        self.config = config

    async def discover(self) -> list[Endpoint]:
        """Discover endpoints from API."""
        endpoints = []

        # Try common discovery methods
        endpoints.extend(await self._discover_from_openapi())
        endpoints.extend(await self._discover_from_common_paths())

        return self._deduplicate(endpoints)

    async def _discover_from_openapi(self) -> list[Endpoint]:
        """Discover endpoints from OpenAPI/Swagger spec."""
        spec_urls = [
            f"{self.config.url}/openapi.json",
            f"{self.config.url}/swagger.json",
            f"{self.config.url}/api-docs",
        ]

        for spec_url in spec_urls:
            try:
                response = await self.client.get(spec_url)
                if response.status_code == 200:
                    return self._parse_openapi_spec(response.json())
            except httpx.HTTPError:
                continue

        return []

    async def _discover_from_common_paths(self) -> list[Endpoint]:
        """Discover endpoints by testing common paths."""
        common_paths = [
            "/api/users",
            "/api/auth/login",
            "/api/products",
            "/api/health",
        ]

        endpoints = []
        for path in common_paths:
            url = f"{self.config.url}{path}"
            if await self._endpoint_exists(url):
                endpoints.append(Endpoint(url=url, method="GET"))

        return endpoints

    async def _endpoint_exists(self, url: str) -> bool:
        """Check if endpoint exists."""
        try:
            response = await self.client.head(url)
            return response.status_code < 500
        except httpx.HTTPError:
            return False
```

### 5.3 Vulnerability Checker Modules

**Location:** `src/api_security_scanner/checkers/`

**Purpose:** Implement specific vulnerability detection logic

#### 5.3.1 Base Checker Interface

```python
# checkers/base.py
from typing import Protocol
from abc import ABC, abstractmethod

class VulnerabilityChecker(Protocol):
    """Interface for vulnerability checkers."""

    name: str

    async def check(self, endpoint: Endpoint) -> list[Finding]:
        """Check endpoint for vulnerabilities."""
        ...

class BaseChecker(ABC):
    """Base class for vulnerability checkers."""

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    @property
    @abstractmethod
    def name(self) -> str:
        """Checker name."""
        pass

    @abstractmethod
    async def check(self, endpoint: Endpoint) -> list[Finding]:
        """Check endpoint for vulnerabilities."""
        pass

    async def _send_payload(
        self,
        endpoint: Endpoint,
        payload: str,
        location: str = "query",
    ) -> httpx.Response:
        """Send test payload to endpoint."""
        if location == "query":
            params = {endpoint.param_name: payload}
            return await self.client.get(endpoint.url, params=params)
        elif location == "body":
            data = {endpoint.param_name: payload}
            return await self.client.post(endpoint.url, json=data)
        else:
            raise ValueError(f"Unknown location: {location}")
```

#### 5.3.2 SQL Injection Checker

```python
# checkers/sql_injection.py
class SQLInjectionChecker(BaseChecker):
    """Detect SQL injection vulnerabilities."""

    name = "SQL Injection"

    # Test payloads
    PAYLOADS = [
        "' OR '1'='1",
        "1' OR '1'='1' --",
        "' UNION SELECT NULL--",
        "1; DROP TABLE users--",
        "admin'--",
    ]

    # Error patterns indicating SQL injection
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"PostgreSQL.*ERROR",
        r"SQLite.*error",
        r"ORA-\d{5}",
        r"Microsoft SQL Server",
    ]

    async def check(self, endpoint: Endpoint) -> list[Finding]:
        """Check for SQL injection vulnerabilities."""
        findings = []

        for payload in self.PAYLOADS:
            try:
                response = await self._send_payload(endpoint, payload)

                if self._is_vulnerable(response):
                    finding = self._create_finding(endpoint, payload, response)
                    findings.append(finding)
                    break  # Stop after first confirmation

            except httpx.HTTPError as e:
                logger.debug(f"Request failed: {e}")

        return findings

    def _is_vulnerable(self, response: httpx.Response) -> bool:
        """Check if response indicates SQL injection vulnerability."""
        response_text = response.text

        # Check for SQL error messages
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        # Check for unusual response codes
        if response.status_code == 500:
            return True

        return False

    def _create_finding(
        self,
        endpoint: Endpoint,
        payload: str,
        response: httpx.Response,
    ) -> Finding:
        """Create finding for SQL injection vulnerability."""
        return Finding(
            title="SQL Injection Vulnerability",
            severity="critical",
            endpoint=endpoint.url,
            description=(
                f"The endpoint is vulnerable to SQL injection. "
                f"Test payload '{payload}' triggered a SQL error."
            ),
            evidence=response.text[:500],
            remediation=(
                "Use parameterized queries or prepared statements. "
                "Never concatenate user input directly into SQL queries."
            ),
            cwe_id="CWE-89",
            owasp_category="A03:2021 - Injection",
        )
```

#### 5.3.3 XSS Checker

```python
# checkers/xss.py
class XSSChecker(BaseChecker):
    """Detect Cross-Site Scripting vulnerabilities."""

    name = "XSS"

    # Test payloads
    PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
    ]

    async def check(self, endpoint: Endpoint) -> list[Finding]:
        """Check for XSS vulnerabilities."""
        findings = []

        # Test reflected XSS
        for payload in self.PAYLOADS:
            try:
                response = await self._send_payload(endpoint, payload)

                if self._is_reflected(payload, response):
                    finding = self._create_finding(endpoint, payload, "reflected")
                    findings.append(finding)
                    break

            except httpx.HTTPError as e:
                logger.debug(f"Request failed: {e}")

        # Check for missing security headers
        if self._missing_security_headers(response):
            finding = self._create_header_finding(endpoint, response)
            findings.append(finding)

        return findings

    def _is_reflected(self, payload: str, response: httpx.Response) -> bool:
        """Check if payload is reflected in response."""
        return payload in response.text

    def _missing_security_headers(self, response: httpx.Response) -> bool:
        """Check for missing security headers."""
        required_headers = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
        ]

        for header in required_headers:
            if header not in response.headers:
                return True

        return False
```

#### 5.3.4 Authentication Checker

```python
# checkers/authentication.py
class AuthChecker(BaseChecker):
    """Check authentication and authorization."""

    name = "Authentication"

    async def check(self, endpoint: Endpoint) -> list[Finding]:
        """Check authentication mechanisms."""
        findings = []

        # Test without authentication
        finding = await self._test_no_auth(endpoint)
        if finding:
            findings.append(finding)

        # Test with invalid token
        finding = await self._test_invalid_token(endpoint)
        if finding:
            findings.append(finding)

        return findings

    async def _test_no_auth(self, endpoint: Endpoint) -> Finding | None:
        """Test endpoint without authentication."""
        try:
            response = await self.client.get(endpoint.url)

            # Should return 401 or 403
            if response.status_code == 200:
                return Finding(
                    title="Missing Authentication",
                    severity="high",
                    endpoint=endpoint.url,
                    description=(
                        "Endpoint is accessible without authentication. "
                        "Sensitive operations should require authentication."
                    ),
                    remediation="Implement authentication for this endpoint.",
                    cwe_id="CWE-306",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                )
        except httpx.HTTPError:
            pass

        return None

    async def _test_invalid_token(self, endpoint: Endpoint) -> Finding | None:
        """Test with invalid authentication token."""
        headers = {"Authorization": "Bearer invalid_token_12345"}

        try:
            response = await self.client.get(endpoint.url, headers=headers)

            # Should return 401
            if response.status_code == 200:
                return Finding(
                    title="Weak Token Validation",
                    severity="high",
                    endpoint=endpoint.url,
                    description="Endpoint accepts invalid authentication tokens.",
                    remediation="Implement proper token validation.",
                    cwe_id="CWE-287",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                )
        except httpx.HTTPError:
            pass

        return None
```

### 5.4 Report Generator Module

**Location:** `src/api_security_scanner/reports/`

**Purpose:** Generate scan reports in various formats

#### 5.4.1 JSON Report Generator

```python
# reports/json_generator.py
import json
from datetime import datetime
from pathlib import Path

class JSONReportGenerator:
    """Generate JSON format reports."""

    def generate(self, results: ScanResults, output_path: str) -> None:
        """Generate and save JSON report."""
        report = self._build_report(results)
        self._save_report(report, output_path)

    def _build_report(self, results: ScanResults) -> dict:
        """Build report structure."""
        return {
            "scan_info": {
                "version": "0.1.0",
                "timestamp": results.timestamp.isoformat(),
                "duration_seconds": results.scan_duration,
                "target_url": results.target_url,
            },
            "summary": {
                "total_endpoints": results.total_endpoints,
                "total_findings": len(results.findings),
                "critical": results.critical_count,
                "high": results.high_count,
                "medium": results.medium_count,
                "low": results.low_count,
            },
            "findings": [
                self._serialize_finding(finding)
                for finding in results.findings
            ],
        }

    def _serialize_finding(self, finding: Finding) -> dict:
        """Serialize finding to dictionary."""
        return {
            "title": finding.title,
            "severity": finding.severity,
            "endpoint": finding.endpoint,
            "description": finding.description,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "cwe_id": finding.cwe_id,
            "owasp_category": finding.owasp_category,
        }

    def _save_report(self, report: dict, output_path: str) -> None:
        """Save report to file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w") as f:
            json.dump(report, f, indent=2)
```

---

## 6. Module Specifications

### 6.1 Project Structure

```
src/api_security_scanner/
├── __init__.py
├── cli/
│   ├── __init__.py
│   ├── main.py          # CLI commands
│   └── display.py       # Terminal output
├── scanner/
│   ├── __init__.py
│   ├── engine.py        # Main scanner
│   ├── discovery.py     # Endpoint discovery
│   └── config.py        # Configuration
├── checkers/
│   ├── __init__.py
│   ├── base.py          # Base checker
│   ├── sql_injection.py # SQL injection
│   ├── xss.py           # XSS detection
│   └── authentication.py # Auth testing
├── reports/
│   ├── __init__.py
│   └── json_generator.py # JSON reports
├── models/
│   ├── __init__.py
│   ├── endpoint.py      # Endpoint model
│   ├── finding.py       # Finding model
│   └── results.py       # Results model
└── utils/
    ├── __init__.py
    ├── http.py          # HTTP utilities
    └── logging.py       # Logging setup
```

### 6.2 Module Dependencies

```
cli → scanner → checkers → models
cli → reports → models
scanner → models
checkers → models
reports → models
```

---

## 7. Class Diagrams

### 7.1 Core Classes

```
┌─────────────────────┐
│      Scanner        │
├─────────────────────┤
│ - config            │
│ - client            │
│ - checkers          │
├─────────────────────┤
│ + scan()            │
│ - discover()        │
│ - test()            │
│ - analyze()         │
└─────────────────────┘
         │
         │ uses
         ▼
┌─────────────────────┐
│ VulnerabilityChecker│◄─────────────┐
├─────────────────────┤              │
│ + name              │              │
│ + check()           │              │
└─────────────────────┘              │
         △                           │
         │ implements                │
         │                           │
    ┌────┴────┬──────────┐          │
    │         │          │           │
┌───┴───┐ ┌──┴──┐  ┌────┴────┐     │
│  SQL  │ │ XSS │  │  Auth   │     │
│Checker│ │Check│  │ Checker │     │
└───────┘ └─────┘  └─────────┘     │
                                    │
                                    │
┌─────────────────────┐             │
│   ScanResults       │             │
├─────────────────────┤             │
│ - findings          │─────────────┘
│ - timestamp         │
│ - duration          │
├─────────────────────┤
│ + critical_count    │
│ + high_count        │
└─────────────────────┘
```

---

**Document Status:** ✅ Complete - Part 2 of 5

**Next:** Part 3 - API & Data Models
