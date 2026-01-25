from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class TodoCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="", max_length=1000)
    status: str = Field(default="pending", pattern="^(pending|completed)$")

class Todo(TodoCreate):
    id: str
    created_at: datetime
    updated_at: datetime
