"""FastAPI application entry point."""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from claudeskills.core.config import settings
from claudeskills.core.logging import get_logger, setup_logging

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan manager.

    Handles startup and shutdown events.
    """
    # Startup
    setup_logging(settings.log_level)
    logger.info(
        "application_starting",
        app_name=settings.app_name,
        version=settings.app_version,
        env=settings.env,
    )

    yield

    # Shutdown
    logger.info("application_stopping")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application instance
    """
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Claude Code Skills Showcase - REST API + Temporal Workflows + MCP Integration",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.debug else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers
    from claudeskills.api.routes import workflows

    app.include_router(workflows.router, prefix="/api", tags=["workflows"])

    return app


# Create application instance
app = create_app()


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint."""
    return {
        "message": "Claude Code Skills Showcase API",
        "version": settings.app_version,
        "docs": "/docs",
    }
