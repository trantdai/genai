"""Tests for DataProcessing workflow."""

import pytest
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from claudeskills.activities.data_processing_activities import (
    ValidationError,
    notify_completion,
    store_results,
    transform_data,
    validate_input,
)
from claudeskills.workflows.data_processing_workflow import (
    DataProcessingInput,
    DataProcessingWorkflow,
)


@pytest.mark.asyncio
async def test_data_processing_workflow_success() -> None:
    """Test DataProcessing workflow executes successfully with valid input."""
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue="test-queue",
            workflows=[DataProcessingWorkflow],
            activities=[validate_input, transform_data, store_results, notify_completion],
        ):
            # Execute workflow with valid input
            input_data = DataProcessingInput(
                data={"id": "test-123", "value": 100, "metadata": {"source": "test"}},
                user_id="user-001",
                processing_options={"num_steps": 2, "step_duration": 0.1},
            )

            result = await env.client.execute_workflow(
                DataProcessingWorkflow.run,
                input_data,
                id="test-workflow-success",
                task_queue="test-queue",
            )

            # Assert workflow completed successfully
            assert result is not None
            assert result.workflow_id == "test-workflow-success"
            assert result.processed_data["id"] == "test-123"
            assert result.validation_result["is_valid"] is True
            assert result.transformation_steps == 2
            assert result.storage_location.startswith("storage://user_user-001")
            assert result.notification_sent is True


@pytest.mark.asyncio
async def test_data_processing_workflow_with_validation_error() -> None:
    """Test workflow fails when validation rejects input."""
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue="test-queue",
            workflows=[DataProcessingWorkflow],
            activities=[validate_input, transform_data, store_results, notify_completion],
        ):
            # Execute workflow with invalid input (missing required field)
            input_data = DataProcessingInput(
                data={"value": 100},  # Missing 'id' field
                user_id="user-002",
            )

            with pytest.raises(Exception) as exc_info:
                await env.client.execute_workflow(
                    DataProcessingWorkflow.run,
                    input_data,
                    id="test-workflow-validation-error",
                    task_queue="test-queue",
                )

            # Should fail with validation error
            assert "ValidationError" in str(exc_info.value) or "Missing required field: id" in str(exc_info.value)


@pytest.mark.asyncio
async def test_data_processing_workflow_minimal_input() -> None:
    """Test workflow with minimal valid input (no options)."""
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue="test-queue",
            workflows=[DataProcessingWorkflow],
            activities=[validate_input, transform_data, store_results, notify_completion],
        ):
            # Minimal valid input
            input_data = DataProcessingInput(
                data={"id": "minimal-001", "value": "test"},
                user_id="user-003",
            )

            result = await env.client.execute_workflow(
                DataProcessingWorkflow.run,
                input_data,
                id="test-workflow-minimal",
                task_queue="test-queue",
            )

            # Assert workflow completed with defaults
            assert result is not None
            assert result.workflow_id == "test-workflow-minimal"
            assert result.transformation_steps == 3  # Default num_steps
            assert result.processed_data["value"] == "TEST"  # String uppercased


@pytest.mark.asyncio
async def test_validate_input_activity() -> None:
    """Test validate_input activity in isolation."""
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue="test-queue",
            workflows=[],
            activities=[validate_input],
        ):
            # Test valid input
            result = await env.client.execute_activity(
                validate_input,
                {"id": "test-123", "value": 42},
                task_queue="test-queue",
            )

            assert result["is_valid"] is True
            assert result["validated_data"]["id"] == "test-123"
            assert result["validated_data"]["value"] == 42
            assert result["validation_checks_passed"] == 3


@pytest.mark.asyncio
async def test_validate_input_activity_empty_data() -> None:
    """Test validate_input rejects empty data."""
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue="test-queue",
            workflows=[],
            activities=[validate_input],
        ):
            with pytest.raises(Exception) as exc_info:
                await env.client.execute_activity(
                    validate_input,
                    {},
                    task_queue="test-queue",
                )

            assert "Input data cannot be empty" in str(exc_info.value)


@pytest.mark.asyncio
async def test_transform_data_activity() -> None:
    """Test transform_data activity with custom options."""
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue="test-queue",
            workflows=[],
            activities=[transform_data],
        ):
            result = await env.client.execute_activity(
                transform_data,
                args=[
                    {"id": "test-456", "value": 100},
                    {"num_steps": 2, "step_duration": 0.1},
                ],
                task_queue="test-queue",
            )

            assert result["steps_completed"] == 2
            assert result["data"]["id"] == "test-456"
            assert result["data"]["value"] > 100  # Value increased
            assert result["data"]["step_1_completed"] is True
            assert result["data"]["step_2_completed"] is True


@pytest.mark.asyncio
async def test_store_results_activity() -> None:
    """Test store_results activity."""
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue="test-queue",
            workflows=[],
            activities=[store_results],
        ):
            result = await env.client.execute_activity(
                store_results,
                args=[
                    {"id": "test-789", "value": 200},
                    "user-123",
                ],
                task_queue="test-queue",
            )

            assert "location" in result
            assert result["location"].startswith("storage://user_user-123")
            assert "stored_at" in result
            assert result["size_bytes"] > 0


@pytest.mark.asyncio
async def test_notify_completion_activity() -> None:
    """Test notify_completion activity."""
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue="test-queue",
            workflows=[],
            activities=[notify_completion],
        ):
            result = await env.client.execute_activity(
                notify_completion,
                args=["user-456", "wf-123", "storage://test"],
                task_queue="test-queue",
            )

            assert result["success"] is True
            assert "wf-123" in result["message"]
            assert "storage://test" in result["message"]
