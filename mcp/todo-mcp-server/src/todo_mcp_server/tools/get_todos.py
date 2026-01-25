from typing import Optional
from mcp.server.fastmcp import FastMCP, Context
from ..utils.logger import get_logger

logger = get_logger()

def register_get_todos_tool(mcp: FastMCP) -> None:
    """Register the get_todos tool with FastMCP"""

    @mcp.tool()
    async def get_todos(
        limit: int = 10,
        status: str = "all",
        search: Optional[str] = None,
        ctx: Context = None
    ) -> dict:
        """
        Retrieve todos from the Todo API with optional filtering.

        Args:
            limit: Maximum number of todos to return (1-100, default: 10)
            status: Filter by status - 'pending', 'completed', or 'all' (default: 'all')
            search: Optional search term to filter todos by title
            ctx: MCP context (injected automatically)

        Returns:
            Dictionary containing todos list and metadata

        Example:
            get_todos(limit=5, status="pending")
            get_todos(search="learn")
        """
        logger.info(f"get_todos called: limit={limit}, status={status}, search={search}")

        # Get context from lifespan
        todo_ctx = ctx.request_context.lifespan_context

        try:
            # Call the API
            result = await todo_ctx.api_client.get_todos(
                limit=limit,
                status=status,
                search=search
            )

            logger.info(f"Retrieved {len(result.get('todos', []))} todos")
            return result

        except Exception as e:
            logger.error(f"Error retrieving todos: {e}")
            return {
                "error": str(e),
                "todos": [],
                "total": 0
            }
