"""Data processing workflow demonstrating long-running operations."""

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from temporalio import workflow
with workflow.unsafe.imports_passed_through():
    from temporalio.common import RetryPolicy
    from temporalio.exceptions import CancelledError

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
    - Progress tracking via queries
    - Graceful cancellation via signals
    """

    def __init__(self) -> None:
        """Initialize workflow state for queries and signals."""
        self._current_step = "initializing"
        self._progress_percentage = 0
        self._cancel_requested = False
        self._error_message: str | None = None

    @workflow.query
    def get_progress(self) -> dict[str, Any]:
        """Query current workflow progress.

        Returns:
            dict with current_step, progress_percentage, cancel status, and error
        """
        return {
            "current_step": self._current_step,
            "progress_percentage": self._progress_percentage,
            "cancel_requested": self._cancel_requested,
            "error": self._error_message,
        }

    @workflow.query
    def get_current_step(self) -> str:
        """Query current processing step name.

        Returns:
            Name of current step
        """
        return self._current_step

    @workflow.signal
    async def cancel(self) -> None:
        """Signal to request workflow cancellation.

        The workflow will complete current activity then exit gracefully.
        """
        logger.warning("cancel_signal_received")
        self._cancel_requested = True
        self._current_step = "cancelling"

    @workflow.run
    async def run(self, input: DataProcessingInput) -> DataProcessingOutput:
        """Execute the complete data processing workflow.

        Args:
            input: DataProcessingInput containing raw data and configuration

        Returns:
            DataProcessingOutput with results from all processing stages

        Raises:
            CancelledError: If workflow is cancelled via signal
        """
        workflow_id = workflow.info().workflow_id
        self._current_step = "started"
        self._progress_percentage = 0

        logger.info(
            "workflow_started",
            workflow_id=workflow_id,
            user_id=input.user_id,
            data_size=len(input.data),
        )

        try:
            # Step 1: Validate input data (0-25% progress)
            self._current_step = "validating"
            self._progress_percentage = 10

            # Check for cancellation
            if self._cancel_requested:
                self._current_step = "cancelled"
                self._progress_percentage = 0
                logger.warning("workflow_cancelled_before_validation")
                raise CancelledError("Workflow cancelled before validation")

            logger.info("starting_validation", workflow_id=workflow_id)
            validation_result = await workflow.execute_activity(
                "validate_input",
                input.data,
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=10),
                    maximum_attempts=3,
                    non_retryable_error_types=["ValidationError"],
                ),
            )
            self._progress_percentage = 25
            logger.info(
                "validation_completed",
                workflow_id=workflow_id,
                is_valid=validation_result["is_valid"],
            )

            # Step 2: Transform data (25-60% progress)
            self._current_step = "transforming"
            self._progress_percentage = 30

            # Check for cancellation
            if self._cancel_requested:
                self._current_step = "cancelled"
                logger.warning("workflow_cancelled_after_validation")
                raise CancelledError("Workflow cancelled after validation")

            logger.info("starting_transformation", workflow_id=workflow_id)
            transformed_data = await workflow.execute_activity(
                "transform_data",
                args=[validation_result["validated_data"], input.processing_options],
                start_to_close_timeout=timedelta(minutes=10),
                heartbeat_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=2),
                    maximum_interval=timedelta(seconds=30),
                    maximum_attempts=5,
                ),
            )
            self._progress_percentage = 60
            logger.info(
                "transformation_completed",
                workflow_id=workflow_id,
                steps_completed=transformed_data["steps_completed"],
            )

            # Step 3: Store results (60-85% progress)
            self._current_step = "storing"
            self._progress_percentage = 65

            # Check for cancellation
            if self._cancel_requested:
                self._current_step = "cancelled"
                logger.warning("workflow_cancelled_after_transformation")
                raise CancelledError("Workflow cancelled after transformation")

            logger.info("starting_storage", workflow_id=workflow_id)
            # Pass workflow execution time for idempotency
            workflow_start_time = workflow.info().start_time.isoformat()

            storage_result = await workflow.execute_activity(
                "store_results",
                args=[transformed_data["data"], input.user_id, workflow_id, workflow_start_time],
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_interval=timedelta(seconds=20),
                    maximum_attempts=5,
                ),
            )
            self._progress_percentage = 85
            logger.info(
                "storage_completed",
                workflow_id=workflow_id,
                location=storage_result["location"],
            )

            # Step 4: Send notification (85-100% progress)
            self._current_step = "notifying"
            self._progress_percentage = 90

            # Check for cancellation (notification is optional, so we continue)
            if self._cancel_requested:
                self._current_step = "cancelled_completing"
                logger.warning("workflow_cancelled_skipping_notification")
                notification_sent = False
            else:
                logger.info("sending_notification", workflow_id=workflow_id)
                notification_result = await workflow.execute_activity(
                    "notify_completion",
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
                notification_sent = bool(notification_result.get("success", False))
                logger.info(
                    "notification_completed",
                    workflow_id=workflow_id,
                    success=notification_sent,
                )

            # Workflow completed successfully
            self._current_step = "completed"
            self._progress_percentage = 100

            logger.info(
                "workflow_completed",
                workflow_id=workflow_id,
                total_steps=4,
                cancelled=self._cancel_requested,
            )

            return DataProcessingOutput(
                workflow_id=workflow_id,
                processed_data=transformed_data["data"],
                validation_result=validation_result,
                transformation_steps=transformed_data["steps_completed"],
                storage_location=storage_result["location"],
                notification_sent=notification_sent,
            )

        except CancelledError:
            # Workflow was cancelled - this is expected
            self._current_step = "cancelled"
            logger.warning("workflow_cancelled", workflow_id=workflow_id)
            raise

        except Exception as e:
            # Unexpected error
            self._current_step = "failed"
            self._error_message = str(e)
            logger.error("workflow_failed", workflow_id=workflow_id, error=str(e))
            raise
