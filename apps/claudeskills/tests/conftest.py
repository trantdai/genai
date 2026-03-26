"""Shared test fixtures and utilities."""

import pytest
from fastapi.testclient import TestClient

from claudeskills.api.main import app


@pytest.fixture
def client() -> TestClient:
    """Create a test client for the FastAPI application.

    Returns:
        TestClient instance for making requests
    """
    return TestClient(app)


@pytest.fixture
def test_settings() -> dict[str, str]:
    """Provide test configuration settings.

    Returns:
        Dictionary of test settings
    """
    return {
        "env": "testing",
        "debug": "true",
        "temporal_host": "localhost",
        "temporal_port": "7233",
    }
