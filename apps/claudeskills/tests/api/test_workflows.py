"""Tests for workflow API endpoints."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from temporalio.client import WorkflowFailureError
from temporalio.service import RPCError, RPCStatusCode


# ==================== CREATE WORKFLOW TESTS ====================


def test_create_workflow_success(client: TestClient) -> None:
    """Test creating a workflow returns successfully with all expected fields."""
    # Arrange
    mock_handle = MagicMock()
    mock_handle.run_id = "test-run-id-123"

    mock_client = AsyncMock()
    mock_client.start_workflow = AsyncMock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.post(
            "/api/workflows",
            json={
                "data": {"id": "test-123", "value": 100},
                "user_id": "user-001",
                "processing_options": {"num_steps": 2},
            },
        )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "workflow_id" in data
    assert data["workflow_id"].startswith("data-processing-")
    assert data["status"] == "running"
    assert data["run_id"] == "test-run-id-123"
    assert "created_at" in data
    # Verify workflow_id contains user_id
    assert "user-001" in data["workflow_id"]


def test_create_workflow_validation_error(client: TestClient) -> None:
    """Test creating workflow with missing required field returns validation error."""
    # Arrange & Act - Missing required field 'data'
    response = client.post(
        "/api/workflows",
        json={
            "user_id": "user-001",
        },
    )

    # Assert
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_create_workflow_missing_user_id(client: TestClient) -> None:
    """Test creating workflow without user_id fails validation."""
    # Arrange & Act
    response = client.post(
        "/api/workflows",
        json={
            "data": {"id": "test-123", "value": 100},
        },
    )

    # Assert
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_create_workflow_empty_data(client: TestClient) -> None:
    """Test creating workflow with empty data dict is accepted."""
    # Arrange
    mock_handle = MagicMock()
    mock_handle.run_id = "test-run-id-empty"

    mock_client = AsyncMock()
    mock_client.start_workflow = AsyncMock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.post(
            "/api/workflows",
            json={
                "data": {},
                "user_id": "user-001",
            },
        )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED


def test_create_workflow_temporal_connection_error(client: TestClient) -> None:
    """Test workflow creation handles Temporal connection errors gracefully."""
    # Arrange - Mock connection failure
    from fastapi import HTTPException

    mock_exception = HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Failed to connect to Temporal: Connection refused",
    )

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        side_effect=mock_exception,
    ):
        response = client.post(
            "/api/workflows",
            json={
                "data": {"id": "test-123", "value": 100},
                "user_id": "user-001",
            },
        )

    # Assert
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert "Temporal" in response.json()["detail"]


def test_create_workflow_with_processing_options(client: TestClient) -> None:
    """Test creating workflow with custom processing options."""
    # Arrange
    mock_handle = MagicMock()
    mock_handle.run_id = "test-run-id-456"

    mock_client = AsyncMock()
    mock_client.start_workflow = AsyncMock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.post(
            "/api/workflows",
            json={
                "data": {"id": "test-456", "value": 200, "metadata": {"source": "api"}},
                "user_id": "user-002",
                "processing_options": {"num_steps": 5, "step_duration": 2.0},
            },
        )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["status"] == "running"


def test_create_workflow_without_processing_options(client: TestClient) -> None:
    """Test creating workflow without processing options defaults to None."""
    # Arrange
    mock_handle = MagicMock()
    mock_handle.run_id = "test-run-id-no-opts"

    mock_client = AsyncMock()
    mock_client.start_workflow = AsyncMock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.post(
            "/api/workflows",
            json={
                "data": {"id": "test-789"},
                "user_id": "user-003",
            },
        )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED


def test_create_workflow_generates_unique_id(client: TestClient) -> None:
    """Test that each workflow gets a unique ID with timestamp and UUID."""
    # Arrange
    mock_handle = MagicMock()
    mock_handle.run_id = "test-run-id"

    mock_client = AsyncMock()
    mock_client.start_workflow = AsyncMock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response1 = client.post(
            "/api/workflows",
            json={
                "data": {"id": "test-1", "value": 100},
                "user_id": "user-001",
            },
        )

        response2 = client.post(
            "/api/workflows",
            json={
                "data": {"id": "test-2", "value": 200},
                "user_id": "user-001",
            },
        )

    # Assert
    assert response1.status_code == status.HTTP_201_CREATED
    assert response2.status_code == status.HTTP_201_CREATED

    id1 = response1.json()["workflow_id"]
    id2 = response2.json()["workflow_id"]

    # IDs should contain user_id and be unique
    assert "user-001" in id1
    assert "user-001" in id2
    assert "data-processing-" in id1
    assert "data-processing-" in id2
    assert id1 != id2  # Should be unique due to UUID


def test_create_workflow_start_workflow_failure(client: TestClient) -> None:
    """Test workflow creation handles start_workflow failures."""
    # Arrange
    mock_client = AsyncMock()
    mock_client.start_workflow = AsyncMock(
        side_effect=Exception("Failed to start workflow")
    )

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.post(
            "/api/workflows",
            json={
                "data": {"id": "test-fail"},
                "user_id": "user-fail",
            },
        )

    # Assert
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "Failed to create workflow" in response.json()["detail"]


def test_create_workflow_handle_none_run_id(client: TestClient) -> None:
    """Test workflow creation handles None run_id from Temporal."""
    # Arrange
    mock_handle = MagicMock()
    mock_handle.run_id = None  # Simulate None run_id

    mock_client = AsyncMock()
    mock_client.start_workflow = AsyncMock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.post(
            "/api/workflows",
            json={
                "data": {"id": "test-none"},
                "user_id": "user-none",
            },
        )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["run_id"] == ""  # Should provide empty string if None


# ==================== GET WORKFLOW STATUS TESTS ====================


def test_get_workflow_status_running(client: TestClient) -> None:
    """Test getting status of a running workflow."""
    # Arrange
    mock_description = MagicMock()
    mock_description.status.name = "RUNNING"

    mock_handle = MagicMock()
    mock_handle.describe = AsyncMock(return_value=mock_description)

    mock_client = AsyncMock()
    mock_client.get_workflow_handle = Mock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.get("/api/workflows/test-workflow-123")

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["workflow_id"] == "test-workflow-123"
    assert data["status"] == "running"
    assert data["result"] is None


def test_get_workflow_status_completed(client: TestClient) -> None:
    """Test getting status of a completed workflow with results."""
    # Arrange
    mock_result = MagicMock()
    mock_result.workflow_id = "test-workflow-123"
    mock_result.processed_data = {"result": "success"}
    mock_result.storage_location = "s3://bucket/data.json"
    mock_result.notification_sent = True

    mock_description = MagicMock()
    mock_description.status.name = "COMPLETED"

    mock_handle = MagicMock()
    mock_handle.describe = AsyncMock(return_value=mock_description)
    mock_handle.result = AsyncMock(return_value=mock_result)

    mock_client = AsyncMock()
    mock_client.get_workflow_handle = Mock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.get("/api/workflows/test-workflow-123")

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["workflow_id"] == "test-workflow-123"
    assert data["status"] == "completed"
    assert data["result"] is not None
    assert data["result"]["workflow_id"] == "test-workflow-123"
    assert data["result"]["processed_data"] == {"result": "success"}
    assert data["result"]["storage_location"] == "s3://bucket/data.json"
    assert data["result"]["notification_sent"] is True


def test_get_workflow_status_failed(client: TestClient) -> None:
    """Test getting status of a failed workflow."""
    # Arrange
    mock_description = MagicMock()
    mock_description.status.name = "FAILED"

    mock_handle = MagicMock()
    mock_handle.describe = AsyncMock(return_value=mock_description)

    mock_client = AsyncMock()
    mock_client.get_workflow_handle = Mock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.get("/api/workflows/test-workflow-failed")

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["workflow_id"] == "test-workflow-failed"
    assert data["status"] == "failed"
    assert data["result"] == {"error": "FAILED"}


def test_get_workflow_status_terminated(client: TestClient) -> None:
    """Test getting status of a terminated workflow."""
    # Arrange
    mock_description = MagicMock()
    mock_description.status.name = "TERMINATED"

    mock_handle = MagicMock()
    mock_handle.describe = AsyncMock(return_value=mock_description)

    mock_client = AsyncMock()
    mock_client.get_workflow_handle = Mock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.get("/api/workflows/test-workflow-terminated")

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "failed"
    assert data["result"] == {"error": "TERMINATED"}


def test_get_workflow_status_cancelled(client: TestClient) -> None:
    """Test getting status of a cancelled workflow."""
    # Arrange
    mock_description = MagicMock()
    mock_description.status.name = "CANCELLED"

    mock_handle = MagicMock()
    mock_handle.describe = AsyncMock(return_value=mock_description)

    mock_client = AsyncMock()
    mock_client.get_workflow_handle = Mock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.get("/api/workflows/test-workflow-cancelled")

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "failed"
    assert data["result"] == {"error": "CANCELLED"}


def test_get_workflow_status_not_found(client: TestClient) -> None:
    """Test getting status of a non-existent workflow."""
    # Arrange
    mock_client = AsyncMock()
    mock_handle = MagicMock()

    # Create RPCError with NOT_FOUND status
    rpc_error = RPCError("Workflow not found", RPCStatusCode.NOT_FOUND, None)
    mock_handle.describe = AsyncMock(side_effect=rpc_error)
    mock_client.get_workflow_handle = Mock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.get("/api/workflows/non-existent-workflow")

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


def test_get_workflow_status_workflow_failure_error(client: TestClient) -> None:
    """Test getting status when workflow failed with WorkflowFailureError."""
    # Arrange
    mock_handle = MagicMock()

    # Create WorkflowFailureError with a cause
    cause_exception = Exception("Workflow execution failed")
    workflow_error = WorkflowFailureError(cause=cause_exception)
    mock_handle.describe = AsyncMock(side_effect=workflow_error)

    mock_client = AsyncMock()
    mock_client.get_workflow_handle = Mock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.get("/api/workflows/test-workflow-error")

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["workflow_id"] == "test-workflow-error"
    assert data["status"] == "failed"
    assert "error" in data["result"]


def test_get_workflow_status_temporal_connection_error(client: TestClient) -> None:
    """Test getting status handles Temporal connection errors."""
    # Arrange
    from fastapi import HTTPException

    mock_exception = HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Failed to connect to Temporal",
    )

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        side_effect=mock_exception,
    ):
        response = client.get("/api/workflows/test-workflow-123")

    # Assert
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


def test_get_workflow_status_unexpected_error(client: TestClient) -> None:
    """Test getting status handles unexpected errors gracefully."""
    # Arrange
    mock_client = AsyncMock()
    mock_handle = MagicMock()
    mock_handle.describe = AsyncMock(side_effect=Exception("Unexpected error"))
    mock_client.get_workflow_handle = Mock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.get("/api/workflows/test-workflow-error")

    # Assert
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "Failed to get workflow status" in response.json()["detail"]


def test_get_workflow_status_unknown_status(client: TestClient) -> None:
    """Test getting status handles unknown workflow status."""
    # Arrange
    mock_description = MagicMock()
    mock_description.status.name = "UNKNOWN_STATUS"

    mock_handle = MagicMock()
    mock_handle.describe = AsyncMock(return_value=mock_description)

    mock_client = AsyncMock()
    mock_client.get_workflow_handle = Mock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.get("/api/workflows/test-workflow-unknown")

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "unknown_status"
    assert data["result"] is None


# ==================== CANCEL WORKFLOW TESTS ====================


def test_cancel_workflow_success(client: TestClient) -> None:
    """Test successfully cancelling a running workflow."""
    # Arrange
    mock_handle = MagicMock()
    mock_handle.cancel = AsyncMock()

    mock_client = AsyncMock()
    mock_client.get_workflow_handle = Mock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.delete("/api/workflows/test-workflow-cancel")

    # Assert
    assert response.status_code == status.HTTP_204_NO_CONTENT
    mock_handle.cancel.assert_called_once()


def test_cancel_workflow_not_found(client: TestClient) -> None:
    """Test cancelling a non-existent workflow returns 404."""
    # Arrange
    mock_handle = MagicMock()

    # Create RPCError with NOT_FOUND status
    rpc_error = RPCError("Workflow not found", RPCStatusCode.NOT_FOUND, None)
    mock_handle.cancel = AsyncMock(side_effect=rpc_error)

    mock_client = AsyncMock()
    mock_client.get_workflow_handle = Mock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.delete("/api/workflows/non-existent-workflow")

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


def test_cancel_workflow_temporal_connection_error(client: TestClient) -> None:
    """Test cancelling workflow handles Temporal connection errors."""
    # Arrange
    from fastapi import HTTPException

    mock_exception = HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Failed to connect to Temporal",
    )

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        side_effect=mock_exception,
    ):
        response = client.delete("/api/workflows/test-workflow-cancel")

    # Assert
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


def test_cancel_workflow_unexpected_error(client: TestClient) -> None:
    """Test cancelling workflow handles unexpected errors gracefully."""
    # Arrange
    mock_handle = MagicMock()
    mock_handle.cancel = AsyncMock(side_effect=Exception("Unexpected error"))

    mock_client = AsyncMock()
    mock_client.get_workflow_handle = Mock(return_value=mock_handle)

    # Act
    with patch(
        "claudeskills.api.routes.workflows.get_temporal_client",
        return_value=mock_client,
    ):
        response = client.delete("/api/workflows/test-workflow-error")

    # Assert
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "Failed to cancel workflow" in response.json()["detail"]


# ==================== GET TEMPORAL CLIENT TESTS ====================


@pytest.mark.asyncio
async def test_get_temporal_client_creates_new_client() -> None:
    """Test get_temporal_client creates a new client on first call."""
    # Arrange
    from claudeskills.api.routes import workflows

    # Reset singleton
    workflows._temporal_client = None

    mock_client = AsyncMock()

    # Act
    with patch("temporalio.client.Client.connect", return_value=mock_client):
        client = await workflows.get_temporal_client()

    # Assert
    assert client is mock_client
    assert workflows._temporal_client is mock_client


@pytest.mark.asyncio
async def test_get_temporal_client_reuses_existing_client() -> None:
    """Test get_temporal_client reuses existing client on subsequent calls."""
    # Arrange
    from claudeskills.api.routes import workflows

    existing_client = AsyncMock()
    workflows._temporal_client = existing_client

    # Act
    client = await workflows.get_temporal_client()

    # Assert
    assert client is existing_client


@pytest.mark.asyncio
async def test_get_temporal_client_connection_failure() -> None:
    """Test get_temporal_client handles connection failures."""
    # Arrange
    from claudeskills.api.routes import workflows

    workflows._temporal_client = None

    # Act & Assert
    with patch(
        "temporalio.client.Client.connect",
        side_effect=Exception("Connection refused"),
    ):
        with pytest.raises(Exception) as exc_info:
            await workflows.get_temporal_client()

        assert "Failed to connect to Temporal" in str(exc_info.value.detail)


# ==================== INTEGRATION WITH OPENAPI TESTS ====================



def test_root_endpoint(client: TestClient) -> None:
    """Test root endpoint returns API information."""
    # Act
    response = client.get("/")

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "message" in data
    assert "version" in data
    assert data["docs"] == "/docs"


def test_openapi_docs_accessible(client: TestClient) -> None:
    """Test that OpenAPI documentation is accessible."""
    # Act
    response = client.get("/docs")

    # Assert
    assert response.status_code == status.HTTP_200_OK


def test_openapi_schema_includes_workflow_endpoint(client: TestClient) -> None:
    """Test that OpenAPI schema includes all workflow endpoints."""
    # Act
    response = client.get("/openapi.json")

    # Assert
    assert response.status_code == status.HTTP_200_OK

    schema = response.json()
    assert "/api/workflows" in schema["paths"]
    assert "post" in schema["paths"]["/api/workflows"]
    assert "/api/workflows/{workflow_id}" in schema["paths"]
    assert "get" in schema["paths"]["/api/workflows/{workflow_id}"]
    assert "delete" in schema["paths"]["/api/workflows/{workflow_id}"]

