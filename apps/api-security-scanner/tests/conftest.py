"""Shared pytest fixtures for API Security Scanner tests."""

from unittest.mock import AsyncMock, Mock

import httpx
import pytest


@pytest.fixture
def sample_url() -> str:
    """Sample API URL for testing."""
    return "https://api.example.com"


@pytest.fixture
def sample_endpoint_url(sample_url: str) -> str:
    """Sample endpoint URL for testing."""
    return f"{sample_url}/api/users"


@pytest.fixture
def mock_httpx_response() -> Mock:
    """Mock httpx.Response object."""
    response = Mock(spec=httpx.Response)
    response.status_code = 200
    response.text = "Test response"
    response.headers = {}
    response.json = Mock(return_value={"status": "ok"})
    return response


@pytest.fixture
def mock_httpx_client() -> AsyncMock:
    """Mock httpx.AsyncClient."""
    client = AsyncMock(spec=httpx.AsyncClient)
    return client


@pytest.fixture
def mock_vulnerable_sql_response() -> Mock:
    """Mock response indicating SQL injection vulnerability."""
    response = Mock(spec=httpx.Response)
    response.status_code = 500
    response.text = "MySQL syntax error: You have an error in your SQL syntax"
    response.headers = {}
    return response


@pytest.fixture
def mock_xss_response() -> Mock:
    """Mock response reflecting XSS payload."""
    response = Mock(spec=httpx.Response)
    response.status_code = 200
    response.text = "<html><script>alert('XSS')</script></html>"
    response.headers = {
        "Content-Type": "text/html",
    }
    return response
