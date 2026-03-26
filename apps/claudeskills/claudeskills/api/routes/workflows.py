"""API routes for workflow management."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status
from temporalio.client import Client, WorkflowFailureError
from temporalio.service import RPCError, RPCStatusCode

from claudeskills.api.schemas.workflows import (
    WorkflowCreateRequest,
    WorkflowResponse,
    WorkflowStatusResponse,
)
from claudeskills.core.config import settings
from claudeskills.core.logging import get_logger
from claudeskills.workflows.data_processing_workflow import (
    DataProcessingInput,
    DataProcessingWorkflow,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/workflows", tags=["workflows"])

# Singleton Temporal client for connection pooling
_temporal_client: Client | None = None


async def get_temporal_client() -> Client:
    """Get or create cached Temporal client connection.

    Uses a singleton pattern to reuse the same connection across requests,
    avoiding connection overhead on every API call.

    Returns:
        Connected Temporal client

    Raises:
        HTTPException: If connection to Temporal fails
    """
    global _temporal_client

    if _temporal_client is None:
        try:
            logger.info("creating_temporal_client", address=settings.temporal_address)
            _temporal_client = await Client.connect(
                settings.temporal_address,
                namespace=settings.temporal_namespace,
            )
            logger.info("temporal_client_created")
        except Exception as e:
            logger.error("temporal_connection_failed", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Failed to connect to Temporal: {e}",
            )

    return _temporal_client


@router.post("", response_model=WorkflowResponse, status_code=status.HTTP_201_CREATED)
async def create_workflow(request: WorkflowCreateRequest) -> WorkflowResponse:
    """Create and start a new data processing workflow.

    Args:
        request: Workflow creation request with input data

    Returns:
        WorkflowResponse with workflow ID and status

    Raises:
        HTTPException: If workflow creation fails
    """
    logger.info(
        "create_workflow_called",
        user_id=request.user_id,
        data_keys=list(request.data.keys()),
    )

    try:
        # Connect to Temporal
        client = await get_temporal_client()

        # Generate unique workflow ID with UUID to prevent collisions
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        unique_id = uuid.uuid4().hex[:8]
        workflow_id = f"data-processing-{timestamp}-{request.user_id}-{unique_id}"

        # Create workflow input
        workflow_input = DataProcessingInput(
            data=request.data,
            user_id=request.user_id,
            processing_options=request.processing_options,
        )

        # Start the workflow
        handle = await client.start_workflow(
            DataProcessingWorkflow.run,
            workflow_input,
            id=workflow_id,
            task_queue=settings.temporal_task_queue,
        )

        logger.info(
            "workflow_started",
            workflow_id=workflow_id,
            run_id=handle.run_id,
            user_id=request.user_id,
        )

        return WorkflowResponse(
            workflow_id=workflow_id,
            status="running",
            run_id=handle.run_id or "",  # Provide empty string if None
            created_at=datetime.now(timezone.utc),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "create_workflow_failed",
            error=str(e),
            user_id=request.user_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create workflow: {e}",
        )


@router.get("/{workflow_id}", response_model=WorkflowStatusResponse)
async def get_workflow_status(workflow_id: str) -> WorkflowStatusResponse:
    """Get the status and result of a specific workflow.

    Args:
        workflow_id: The workflow identifier

    Returns:
        WorkflowStatusResponse with current status and result (if completed)

    Raises:
        HTTPException: If workflow not found or status query fails
    """
    logger.info("get_workflow_status_called", workflow_id=workflow_id)

    try:
        # Connect to Temporal
        client = await get_temporal_client()

        # Get workflow handle
        handle = client.get_workflow_handle(workflow_id)

        # Check if workflow is running
        try:
            # Try to describe the workflow
            description = await handle.describe()

            # Check status exists
            if description.status is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Workflow status is unavailable",
                )

            # Determine status based on workflow state
            if description.status.name == "RUNNING":
                status_str = "running"
                result = None
            elif description.status.name == "COMPLETED":
                # Get workflow result
                workflow_result = await handle.result()
                status_str = "completed"
                result = {
                    "workflow_id": workflow_result.workflow_id,
                    "processed_data": workflow_result.processed_data,
                    "storage_location": workflow_result.storage_location,
                    "notification_sent": workflow_result.notification_sent,
                }
            elif description.status.name in ["FAILED", "TERMINATED", "CANCELLED"]:
                status_str = "failed"
                result = {"error": description.status.name}
            else:
                status_str = description.status.name.lower()
                result = None

            logger.info(
                "workflow_status_retrieved",
                workflow_id=workflow_id,
                status=status_str,
            )

            return WorkflowStatusResponse(
                workflow_id=workflow_id,
                status=status_str,
                result=result,
            )

        except WorkflowFailureError as e:
            # Workflow failed
            logger.warning("workflow_failed", workflow_id=workflow_id, error=str(e))
            return WorkflowStatusResponse(
                workflow_id=workflow_id,
                status="failed",
                result={"error": str(e)},
            )

    except RPCError as e:
        if e.status == RPCStatusCode.NOT_FOUND:
            logger.warning("workflow_not_found", workflow_id=workflow_id)
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Workflow {workflow_id} not found",
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"RPC error: {e}",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "get_workflow_status_failed",
            workflow_id=workflow_id,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get workflow status: {e}",
        )


@router.delete("/{workflow_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_workflow(workflow_id: str) -> None:
    """Cancel a running workflow.

    Args:
        workflow_id: The workflow identifier

    Raises:
        HTTPException: If workflow not found or cancellation fails
    """
    logger.info("cancel_workflow_called", workflow_id=workflow_id)

    try:
        # Connect to Temporal
        client = await get_temporal_client()

        # Get workflow handle
        handle = client.get_workflow_handle(workflow_id)

        # Cancel the workflow
        await handle.cancel()

        logger.info("workflow_cancelled", workflow_id=workflow_id)

    except RPCError as e:
        if e.status == RPCStatusCode.NOT_FOUND:
            logger.warning("workflow_not_found_for_cancel", workflow_id=workflow_id)
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Workflow {workflow_id} not found",
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "cancel_workflow_failed",
            workflow_id=workflow_id,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cancel workflow: {e}",
        )
