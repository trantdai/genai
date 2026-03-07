"""Data processing workflow demonstrating long-running operations."""

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

from claudeskills.activities.data_processing_activities import (
    notify_completion,
    store_results,
    transform_data,
    validate_input,
)

# Workflow logger will be used for structured logging
logger = workflow.logger


@dataclass
class DataProcessingInput:
    """Input for DataProcessing workflow.

    Attributes:
        data: Raw input data to process
        user_id: ID of user who initiated the workflow
        processing_options: Optional configuration for processing
    """

    data: dict[str, Any]
    user_id: str
    processing_options: dict[str, Any] | None = None


@dataclass
class DataProcessingOutput:
    """Output from DataProcessing workflow.

    Attributes:
        workflow_id: ID of the completed workflow
        processed_data: Final processed data
        validation_result: Summary of validation step
        transformation_steps: Number of transformation steps completed
        storage_location: Where results were stored
        notification_sent: Whether notification was successful
    """

    workflow_id: str
    processed_data: dict[str, Any]
    validation_result: dict[str, Any]
    transformation_steps: int
    storage_location: str
    notification_sent: bool


@workflow.defn
class DataProcessingWorkflow:
    """Long-running workflow for processing data through multiple stages.

    This workflow demonstrates:
    - Multi-step data processing (validate → transform → store → notify)
    - Proper timeout and retry configurations
    - Structured logging at each stage
    - Error handling with domain-specific exceptions
    """

    @workflow.run
    async def run(self, input: DataProcessingInput) -> DataProcessingOutput:
        """Execute the complete data processing workflow.

        Args:
            input: DataProcessingInput containing raw data and configuration

        Returns:
            DataProcessingOutput with results from all processing stages
        """
        workflow_id = workflow.info().workflow_id
        logger.info(
            "workflow_started",
            workflow_id=workflow_id,
            user_id=input.user_id,
            data_size=len(input.data),
        )

        # Step 1: Validate input data
        logger.info("starting_validation", workflow_id=workflow_id)
        validation_result = await workflow.execute_activity(
            validate_input,
            input.data,
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=10),
                maximum_attempts=3,
                non_retryable_error_types=["ValidationError"],
            ),
        )
        logger.info(
            "validation_completed",
            workflow_id=workflow_id,
            is_valid=validation_result["is_valid"],
        )

        # Step 2: Transform data through multiple steps
        logger.info("starting_transformation", workflow_id=workflow_id)
        transformed_data = await workflow.execute_activity(
            transform_data,
            args=[validation_result["validated_data"], input.processing_options],
            start_to_close_timeout=timedelta(minutes=10),
            heartbeat_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=2),
                maximum_interval=timedelta(seconds=30),
                maximum_attempts=5,
            ),
        )
        logger.info(
            "transformation_completed",
            workflow_id=workflow_id,
            steps_completed=transformed_data["steps_completed"],
        )

        # Step 3: Store results
        logger.info("starting_storage", workflow_id=workflow_id)
        storage_result = await workflow.execute_activity(
            store_results,
            args=[transformed_data["data"], input.user_id],
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=20),
                maximum_attempts=5,
            ),
        )
        logger.info(
            "storage_completed",
            workflow_id=workflow_id,
            location=storage_result["location"],
        )

        # Step 4: Send completion notification
        logger.info("sending_notification", workflow_id=workflow_id)
        notification_result = await workflow.execute_activity(
            notify_completion,
            args=[input.user_id, workflow_id, storage_result["location"]],
            start_to_close_timeout=timedelta(minutes=1),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=10),
                maximum_attempts=3,
                # Don't fail the workflow if notification fails
                non_retryable_error_types=["NotificationError"],
            ),
        )
        notification_sent = notification_result.get("success", False)
        logger.info(
            "notification_completed",
            workflow_id=workflow_id,
            success=notification_sent,
        )

        # Workflow completed successfully
        logger.info(
            "workflow_completed",
            workflow_id=workflow_id,
            total_steps=4,
        )

        return DataProcessingOutput(
            workflow_id=workflow_id,
            processed_data=transformed_data["data"],
            validation_result=validation_result,
            transformation_steps=transformed_data["steps_completed"],
            storage_location=storage_result["location"],
            notification_sent=notification_sent,
        )
