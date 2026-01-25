import httpx
from typing import Optional, Dict, Any
from .logger import get_logger

logger = get_logger()


class TodoAPIClient:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(base_url=base_url, timeout=30.0)

    async def get_todos(
        self, limit: int = 10, status: str = "all", search: Optional[str] = None
    ) -> Dict[str, Any]:
        params = {"limit": limit, "status": status}
        if search:
            params["search"] = search

        response = await self.client.get("/api/todos", params=params)
        response.raise_for_status()
        return response.json()

    async def create_todo(
        self, title: str, description: str = "", status: str = "pending"
    ) -> Dict[str, Any]:
        data = {"title": title, "description": description, "status": status}
        response = await self.client.post("/api/todos", json=data)
        response.raise_for_status()
        return response.json()

    async def close(self):
        await self.client.aclose()
