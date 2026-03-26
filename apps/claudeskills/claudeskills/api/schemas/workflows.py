"""Pydantic schemas for workflow API endpoints."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class WorkflowCreateRequest(BaseModel):
    """Request schema for creating a new workflow.

    Attributes:
        data: Input data to be processed by the workflow
        user_id: ID of the user initiating the workflow
        processing_options: Optional configuration for processing
    """

    data: dict[str, Any] = Field(
        ...,
        description="Input data to process",
        examples=[{"id": "record-123", "value": 100, "metadata": {"source": "api"}}],
    )
    user_id: str = Field(..., description="User ID", examples=["user-001"])
    processing_options: dict[str, Any] | None = Field(
        default=None,
        description="Optional processing configuration",
        examples=[{"num_steps": 3, "step_duration": 1.0}],
    )


class WorkflowResponse(BaseModel):
    """Response schema for workflow operations.

    Attributes:
        workflow_id: Unique workflow identifier
        status: Current workflow status
        run_id: Temporal run ID
        created_at: When the workflow was created
    """

    workflow_id: str = Field(..., description="Unique workflow identifier")
    status: str = Field(..., description="Workflow status", examples=["running"])
    run_id: str = Field(..., description="Temporal run ID")
    created_at: datetime = Field(..., description="Creation timestamp")

    class Config:
        json_schema_extra = {
            "example": {
                "workflow_id": "data-processing-20240101-abc123",
                "status": "running",
                "run_id": "abc123-def456-ghi789",
                "created_at": "2024-01-01T12:00:00Z",
            }
        }


class WorkflowStatusResponse(BaseModel):
    """Response schema for workflow status queries.

    Attributes:
        workflow_id: Unique workflow identifier
        status: Current workflow status
        result: Workflow result if completed
    """

    workflow_id: str = Field(..., description="Unique workflow identifier")
    status: str = Field(
        ..., description="Workflow status", examples=["running", "completed", "failed"]
    )
    result: dict[str, Any] | None = Field(
        default=None, description="Workflow result if completed"
    )


class WorkflowListResponse(BaseModel):
    """Response schema for listing workflows.

    Attributes:
        workflows: List of workflow summaries
        total: Total number of workflows
        page: Current page number
        page_size: Number of items per page
    """

    workflows: list[WorkflowResponse]
    total: int
    page: int = 1
    page_size: int = 10
