"""Activities for data processing workflow."""

import asyncio
from typing import Any

from temporalio import activity
from temporalio.exceptions import ApplicationError

from claudeskills.core.logging import get_logger

logger = get_logger(__name__)


class ValidationError(ApplicationError):
    """Raised when input validation fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message, details, type="ValidationError")


class NotificationError(ApplicationError):
    """Raised when notification fails (non-retryable)."""

    def __init__(self, message: str):
        super().__init__(message, type="NotificationError")


@activity.defn
async def validate_input(data: dict[str, Any]) -> dict[str, Any]:
    """Validate input data before processing.

    Args:
        data: Raw input data to validate

    Returns:
        dict containing validation result and validated data

    Raises:
        ValidationError: If data fails validation checks
    """
    activity_info = activity.info()
    logger.info(
        "activity_started",
        activity=activity_info.activity_type,
        attempt=activity_info.attempt,
    )

    try:
        # Validation rules
        if not data:
            raise ValidationError("Input data cannot be empty")

        if "id" not in data:
            raise ValidationError("Missing required field: id")

        if not isinstance(data.get("value"), (int, float, str)):
            raise ValidationError(
                "Field 'value' must be a number or string",
                details={"received_type": type(data.get("value")).__name__},
            )

        # Simulate validation processing
        await asyncio.sleep(0.5)

        validated_data = {
            "id": data["id"],
            "value": data["value"],
            "validated_at": activity_info.current_attempt_scheduled_time.isoformat(),
            "metadata": data.get("metadata", {}),
        }

        logger.info(
            "activity_completed",
            activity=activity_info.activity_type,
            record_id=validated_data["id"],
        )

        return {
            "is_valid": True,
            "validated_data": validated_data,
            "validation_checks_passed": 3,
        }

    except ValidationError:
        logger.error(
            "validation_failed",
            activity=activity_info.activity_type,
            attempt=activity_info.attempt,
        )
        raise
    except Exception as e:
        logger.error(
            "activity_failed",
            activity=activity_info.activity_type,
            error=str(e),
        )
        raise ApplicationError(f"Validation activity failed: {e}")


@activity.defn
async def transform_data(
    data: dict[str, Any],
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Transform data through multiple processing steps.

    This is a long-running activity that uses heartbeats to report progress.

    Args:
        data: Validated data to transform
        options: Optional processing configuration

    Returns:
        dict containing transformed data and metadata
    """
    activity_info = activity.info()
    logger.info(
        "activity_started",
        activity=activity_info.activity_type,
        attempt=activity_info.attempt,
        record_id=data.get("id"),
    )

    options = options or {}
    num_steps = options.get("num_steps", 3)
    step_duration = options.get("step_duration", 1.0)

    try:
        transformed_data = data.copy()

        # Multi-step transformation with heartbeats
        for step in range(1, num_steps + 1):
            logger.info(
                "transformation_step",
                step=step,
                total_steps=num_steps,
                record_id=data.get("id"),
            )

            # Report heartbeat to Temporal
            activity.heartbeat({"step": step, "total": num_steps})

            # Simulate processing
            await asyncio.sleep(step_duration)

            # Apply transformation
            if "value" in transformed_data:
                if isinstance(transformed_data["value"], (int, float)):
                    transformed_data["value"] = transformed_data["value"] * 1.1
                elif isinstance(transformed_data["value"], str):
                    transformed_data["value"] = transformed_data["value"].upper()

            transformed_data[f"step_{step}_completed"] = True

        # Add processing metadata
        transformed_data["processing_metadata"] = {
            "steps_completed": num_steps,
            "processed_at": activity_info.current_attempt_scheduled_time.isoformat(),
            "attempt": activity_info.attempt,
        }

        logger.info(
            "activity_completed",
            activity=activity_info.activity_type,
            record_id=data.get("id"),
            steps_completed=num_steps,
        )

        return {
            "data": transformed_data,
            "steps_completed": num_steps,
        }

    except Exception as e:
        logger.error(
            "activity_failed",
            activity=activity_info.activity_type,
            error=str(e),
            record_id=data.get("id"),
        )
        raise ApplicationError(f"Transformation activity failed: {e}")


@activity.defn
async def store_results(
    data: dict[str, Any],
    user_id: str,
    workflow_id: str,
    workflow_start_time: str,
) -> dict[str, Any]:
    """Store processed results with idempotency.

    Uses workflow_id and workflow_start_time to create a deterministic storage
    location. On retry, the same location is computed ensuring idempotent behavior.

    Args:
        data: Transformed data to store
        user_id: ID of user who owns this data
        workflow_id: Unique workflow identifier
        workflow_start_time: Workflow start time (ISO format) for idempotency

    Returns:
        dict containing storage location and metadata
    """
    activity_info = activity.info()
    logger.info(
        "activity_started",
        activity=activity_info.activity_type,
        attempt=activity_info.attempt,
        user_id=user_id,
        workflow_id=workflow_id,
        record_id=data.get("id"),
    )

    try:
        # Create deterministic storage location using workflow identifiers
        # This ensures idempotency - retries will compute the same location
        storage_location = (
            f"storage://user_{user_id}/"
            f"workflow_{workflow_id}/"
            f"data_{data.get('id')}"
        )

        # Log retry attempts for monitoring
        if activity_info.attempt > 1:
            logger.info(
                "activity_retry_detected",
                attempt=activity_info.attempt,
                workflow_id=workflow_id,
                storage_location=storage_location,
            )

        # Simulate storage operation
        # In real implementation:
        # - Check if storage_location already exists
        # - If exists and activity is retrying, return existing result (idempotent)
        # - If not exists, write data to storage
        await asyncio.sleep(0.8)

        logger.info(
            "activity_completed",
            activity=activity_info.activity_type,
            location=storage_location,
            record_id=data.get("id"),
            workflow_id=workflow_id,
        )

        return {
            "location": storage_location,
            "stored_at": workflow_start_time,  # Use workflow time, not activity time
            "size_bytes": len(str(data)),
        }

    except Exception as e:
        logger.error(
            "activity_failed",
            activity=activity_info.activity_type,
            error=str(e),
            user_id=user_id,
            workflow_id=workflow_id,
        )
        raise ApplicationError(f"Storage activity failed: {e}")


@activity.defn
async def notify_completion(
    user_id: str,
    workflow_id: str,
    storage_location: str,
) -> dict[str, str | bool]:
    """Send completion notification to user.

    Args:
        user_id: ID of user to notify
        workflow_id: ID of completed workflow
        storage_location: Where results are stored

    Returns:
        dict with success status and message
    """
    activity_info = activity.info()
    logger.info(
        "activity_started",
        activity=activity_info.activity_type,
        attempt=activity_info.attempt,
        user_id=user_id,
        workflow_id=workflow_id,
    )

    try:
        # Simulate notification service call
        await asyncio.sleep(0.3)

        # In real implementation, this would send email/webhook/etc.
        notification_message = (
            f"Workflow {workflow_id} completed. "
            f"Results available at: {storage_location}"
        )

        logger.info(
            "activity_completed",
            activity=activity_info.activity_type,
            user_id=user_id,
            workflow_id=workflow_id,
        )

        return {
            "success": True,
            "message": notification_message,
        }

    except Exception as e:
        # Log error but don't fail workflow
        logger.warning(
            "notification_failed",
            activity=activity_info.activity_type,
            error=str(e),
            user_id=user_id,
        )
        # Raise non-retryable error so workflow continues
        raise NotificationError(f"Failed to send notification: {e}")
