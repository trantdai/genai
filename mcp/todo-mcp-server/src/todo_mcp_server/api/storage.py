from typing import List, Optional
from datetime import datetime
import uuid


class TodoStorage:
    def __init__(self):
        self.todos: List[dict] = []

    def create_todo(self, title: str, description: str, status: str) -> dict:
        todo = {
            "id": str(uuid.uuid4()),
            "title": title,
            "description": description,
            "status": status,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        }
        self.todos.append(todo)
        return todo

    def get_todos(
        self, limit: int = 10, status: str = "all", search: Optional[str] = None
    ) -> List[dict]:
        filtered = self.todos

        # Filter by status
        if status != "all":
            filtered = [t for t in filtered if t["status"] == status]

        # Filter by search term
        if search:
            filtered = [t for t in filtered if search.lower() in t["title"].lower()]

        return filtered[:limit]
