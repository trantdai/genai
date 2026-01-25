import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv

from .utils.logger import get_logger
from .utils.http_client import TodoAPIClient
from .utils.context import TodoContext

logger = get_logger()

SERVER_NAME = "Todo MCP Server"
SERVER_DESCRIPTION = "A learning-focused MCP server for Todo API operations"


@asynccontextmanager
async def todo_lifespan(mcp_server: FastMCP) -> AsyncIterator[TodoContext]:
    """Manage server lifecycle and provide context to tools"""

    # Startup: Initialize API client
    api_url = os.getenv("TODO_API_URL", "http://localhost:8000")
    logger.info(f"Initializing Todo API client for {api_url}")

    api_client = TodoAPIClient(base_url=api_url)
    context = TodoContext(api_client=api_client, api_url=api_url)

    # Register tools dynamically
    try:
        from .tools import register_tools

        register_tools(mcp_server)
        logger.info("Tools registered successfully")
    except Exception as e:
        logger.error(f"Error registering tools: {e}")
        raise

    yield context

    # Shutdown: Clean up resources
    logger.info("Shutting down Todo MCP Server")
    await api_client.close()


def create_server(
    env_file_path: str = None, host: str = "127.0.0.1", port: int = 8000
) -> FastMCP:
    """Create and configure the FastMCP server instance"""

    # Load environment variables
    if env_file_path:
        load_dotenv(env_file_path)
    else:
        load_dotenv()

    # Create FastMCP server with lifespan and network configuration
    mcp = FastMCP(
        name=SERVER_NAME,
        lifespan=todo_lifespan,
        host=host,
        port=port,
    )

    return mcp


# Create server instance
server = create_server()

if __name__ == "__main__":
    from .cli import main

    main()
