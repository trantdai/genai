"""CLI entry point for API Security Scanner.

This module provides the command-line interface for the scanner.
Implementation will be completed in Phase 6.
"""

import click


@click.group()
@click.version_option(version="0.1.0", prog_name="api-scanner")
def cli() -> None:
    """API Security Scanner - Detect vulnerabilities in REST APIs.

    This is a placeholder CLI for Phase 1 setup.
    Full implementation coming in Phase 6.
    """
    pass


@cli.command()
@click.argument("url")
@click.option("--auth-token", help="Bearer token for authentication")
@click.option("--output", "-o", default="scan-report.json", help="Output file path")
def scan(url: str, auth_token: str | None, output: str) -> None:
    """Scan an API endpoint for security vulnerabilities.

    Args:
        url: The API base URL to scan
        auth_token: Optional authentication token
        output: Report output file path
    """
    click.echo("🚧 API Security Scanner v0.1.0 (Phase 1 - Setup)")
    click.echo(f"📍 Target: {url}")
    click.echo(f"📄 Output: {output}")
    click.echo()
    click.echo("⚠️  Scanner implementation not yet complete.")
    click.echo("This is a placeholder CLI for Phase 1 project setup.")
    click.echo()
    click.echo("Next phases will implement:")
    click.echo("  • Phase 2: Core Models (Pydantic schemas)")
    click.echo("  • Phase 3: HTTP Client (async httpx)")
    click.echo("  • Phase 4: Vulnerability Checkers (SQL, XSS, Auth)")
    click.echo("  • Phase 5: Scanner Engine (orchestration)")
    click.echo("  • Phase 6: Full CLI & Reports")


if __name__ == "__main__":
    cli()
