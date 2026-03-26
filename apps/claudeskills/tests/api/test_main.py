"""Tests for the main API application."""

from fastapi.testclient import TestClient


def test_root_endpoint(client: TestClient) -> None:
    """Test the root endpoint returns expected response."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "version" in data
    assert data["version"] == "0.1.0"


def test_docs_endpoint(client: TestClient) -> None:
    """Test that API documentation is accessible."""
    response = client.get("/docs")
    assert response.status_code == 200


def test_openapi_endpoint(client: TestClient) -> None:
    """Test that OpenAPI schema is accessible."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    data = response.json()
    assert "openapi" in data
    assert "info" in data
