from dataclasses import dataclass
from .http_client import TodoAPIClient

@dataclass
class TodoContext:
    """Context object passed to MCP tools"""
    api_client: TodoAPIClient
    api_url: str
