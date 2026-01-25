from mcp.server.fastmcp import FastMCP, Context
from ..utils.logger import get_logger

logger = get_logger()

def register_create_todo_tool(mcp: FastMCP) -> None:
    """Register the create_todo tool with FastMCP"""

    @mcp.tool()
    async def create_todo(
        title: str,
        description: str = "",
        status: str = "pending",
        ctx: Context = None
    ) -> dict:
        """
        Create a new todo item in the Todo API.

        Args:
            title: Todo title (required, 1-200 characters)
            description: Todo description (optional, max 1000 characters)
            status: Initial status - 'pending' or 'completed' (default: 'pending')
            ctx: MCP context (injected automatically)

        Returns:
            Dictionary containing the created todo item with id and timestamps

        Example:
            create_todo(title="Learn FastMCP", description="Study the framework")
            create_todo(title="Build MCP server", status="pending")
        """
        logger.info(f"create_todo called: title='{title}', status={status}")

        # Validate inputs
        if not title or len(title) == 0:
            return {"error": "Title is required"}

        if status not in ["pending", "completed"]:
            return {"error": "Status must be 'pending' or 'completed'"}

        # Get context from lifespan
        todo_ctx = ctx.request_context.lifespan_context

        try:
            # Call the API
            result = await todo_ctx.api_client.create_todo(
                title=title,
                description=description,
                status=status
            )

            logger.info(f"Created todo with id: {result.get('id')}")
            return result

        except Exception as e:
            logger.error(f"Error creating todo: {e}")
            return {"error": str(e)}
