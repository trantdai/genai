# Python Development Standards

## Code Style
- Follow PEP 8 style guide strictly
- Use Black formatter with line length of 100 characters
- Use isort for import sorting with Black-compatible profile
- Use Ruff for linting (replaces flake8, pylint, etc.)
- Type hints are mandatory for all function signatures and class attributes
- Use Pydantic for data validation and settings management (latest stable version)

## Project Structure
- Follow src-layout: `src/<package_name>/` for application code
- Tests mirror source structure in `tests/` directory
- Use `pyproject.toml` for all project configuration
- Pin dependencies with minimum version constraints (e.g., `fastapi>=0.100.0`)
- Study and follow patterns established in `docs/` directory for architecture consistency

## Security - Secure Coding Practices
- **Input Validation**: Validate all inputs at boundaries using Pydantic or similar
- **Output Encoding**: Properly encode outputs to prevent injection attacks
- **Authentication/Authorization**: Implement proper access controls with JWT/OAuth2
- **Session Management**: Use secure session handling with proper timeouts
- **Error Handling**: Never expose sensitive information in error messages
- **Cryptography**: Use established libraries (cryptography, passlib) - never roll your own
- **SQL Injection Prevention**: Use parameterized queries or ORMs exclusively
- **Path Traversal Prevention**: Validate and sanitize all file paths
- **Dependency Security**: Regular security audits with `pip-audit` or `safety`
- **Secrets Management**: Never hardcode secrets, use environment variables or secret managers

## Testing
- When running pytest, always cd to the application directory in question and activate its virtual environment using the command: source .venv/bin/activate
- Use pytest exclusively (no unittest)
- Use pytest-mock for mocking (never unittest.mock)
- Minimum 80% code coverage required
- Test files must be named `test_*.py` or `*_test.py`
- Use pytest fixtures for reusable test setup
- Async tests must use pytest-asyncio
- Test security boundaries and error conditions

## FastAPI Specific
- Use dependency injection for database sessions, auth, etc.
- Implement proper exception handlers with secure error responses
- Use Pydantic models for request/response validation
- Document all endpoints with proper OpenAPI descriptions
- Use APIRouter for modular endpoint organization
- Implement proper CORS configuration for production
- Rate limiting and request throttling for API protection

## FastMCP Specific
- Follow FastMCP patterns for Model Context Protocol server implementation
- Use proper resource and tool definitions
- Implement proper error handling for MCP operations
- Document all MCP tools and resources clearly

## Error Handling
- Use custom exception classes inheriting from appropriate base exceptions
- Never use bare `except:` clauses
- Log exceptions with proper context using structlog or similar
- Return appropriate HTTP status codes in APIs
- Sanitize error messages before exposing to clients

## Async/Await
- Use async/await for I/O-bound operations
- Use asyncio.gather() for concurrent operations
- Properly handle async context managers
- Use aiohttp or httpx for async HTTP requests
