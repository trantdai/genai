from mcp.server.fastmcp import FastMCP
from .get_todos import register_get_todos_tool
from .create_todo import register_create_todo_tool

def register_tools(mcp: FastMCP) -> None:
    """Register all tools with the FastMCP server"""
    register_get_todos_tool(mcp)
    register_create_todo_tool(mcp)
