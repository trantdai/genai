"""Temporal worker entry point."""

import asyncio

from temporalio.client import Client
from temporalio.worker import Worker

from claudeskills.core.config import settings
from claudeskills.core.logging import get_logger, setup_logging

logger = get_logger(__name__)


async def main() -> None:
    """Start the Temporal worker."""
    setup_logging(settings.log_level)

    logger.info(
        "worker_starting",
        temporal_address=settings.temporal_address,
        task_queue=settings.temporal_task_queue,
    )

    # Connect to Temporal server
    client = await Client.connect(
        settings.temporal_address,
        namespace=settings.temporal_namespace,
    )

    # Create worker (activities and workflows to be added)
    worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[],  # Add workflow classes here
        activities=[],  # Add activity functions here
    )

    logger.info("worker_started", task_queue=settings.temporal_task_queue)

    # Run worker
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
