---
name: temporal-workflow
description: Generate a new Temporal workflow with activities for the claudeskills application
argument-hint: [workflow-name] [description]
disable-model-invocation: true
---

Create a new Temporal workflow named **$0** that: $1

## Project Context
- Project: claudeskills (FastAPI + Temporal showcase)
- Location: `/Users/dai.tran/Developer/personal/genai/apps/claudeskills`
- Structure follows PRD at `docs/prd.md`

## Generate These Files

### 1. Workflow Definition: `claudeskills/workflows/$0_workflow.py`
```python
from datetime import timedelta
from temporalio import workflow
from temporalio.common import RetryPolicy
from dataclasses import dataclass

from claudeskills.activities.$0_activities import (
    # Import your activities here
)
from claudeskills.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ${0}Input:
    """Input for $0 workflow."""
    # Add your input fields
    pass


@dataclass
class ${0}Output:
    """Output from $0 workflow."""
    # Add your output fields
    pass


@workflow.defn
class ${0}Workflow:
    """$1"""

    @workflow.run
    async def run(self, input: ${0}Input) -> ${0}Output:
        """Execute the workflow."""
        workflow.logger.info("workflow_started", input=input)

        # Execute activities with proper timeouts and retries
        # Example:
        # result = await workflow.execute_activity(
        #     your_activity,
        #     input,
        #     start_to_close_timeout=timedelta(minutes=5),
        #     retry_policy=RetryPolicy(
        #         initial_interval=timedelta(seconds=1),
        #         maximum_attempts=3,
        #     ),
        # )

        workflow.logger.info("workflow_completed")
        return ${0}Output()
```

### 2. Activities: `claudeskills/activities/$0_activities.py`
```python
from temporalio import activity
from temporalio.exceptions import ApplicationError

from claudeskills.core.logging import get_logger

logger = get_logger(__name__)


@activity.defn
async def sample_activity(input_data: str) -> str:
    """Sample activity - replace with your actual activities."""
    activity_info = activity.info()
    logger.info(
        "activity_started",
        activity=activity_info.activity_type,
        attempt=activity_info.attempt,
    )

    try:
        # Your activity logic here
        result = f"Processed: {input_data}"

        logger.info("activity_completed", result=result)
        return result

    except Exception as e:
        logger.error("activity_failed", error=str(e))
        raise ApplicationError(f"Activity failed: {e}")
```

### 3. Tests: `tests/workflows/test_$0_workflow.py`
```python
import pytest
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from claudeskills.workflows.$0_workflow import ${0}Workflow, ${0}Input
from claudeskills.activities.$0_activities import sample_activity


@pytest.mark.asyncio
async def test_${0}_workflow_success() -> None:
    """Test $0 workflow executes successfully."""
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue="test-queue",
            workflows=[${0}Workflow],
            activities=[sample_activity],
        ):
            # Execute workflow
            result = await env.client.execute_workflow(
                ${0}Workflow.run,
                ${0}Input(),
                id="test-workflow-id",
                task_queue="test-queue",
            )

            # Assert results
            assert result is not None
```

### 4. Update Worker: `claudeskills/worker/main.py`

Add your workflow and activities to the worker registration:
```python
from claudeskills.workflows.$0_workflow import ${0}Workflow
from claudeskills.activities.$0_activities import sample_activity

# In the Worker initialization, add:
workflows=[${0}Workflow],  # Add to existing list
activities=[sample_activity],  # Add to existing list
```

## Requirements
- Follow async/await patterns
- Use dataclasses for input/output
- Include comprehensive logging
- Add proper error handling
- Write unit tests
- Update worker registration

## After Creating

### 1. Setup Virtual Environment (if not already done)
```bash
cd /Users/dai.tran/Developer/personal/genai/apps/claudeskills
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

### 2. Run Tests
```bash
source .venv/bin/activate  # Ensure venv is activated
pytest tests/workflows/test_$0_workflow.py -v
```

### 3. Verify Code Quality
```bash
ruff check claudeskills/workflows/$0_workflow.py
mypy claudeskills/workflows/$0_workflow.py
```
