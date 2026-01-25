from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from .models import Todo, TodoCreate
from .storage import TodoStorage

app = FastAPI(title="Todo API", version="1.0.0")
storage = TodoStorage()

# CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/todos")
async def get_todos(
    limit: int = Query(10, ge=1, le=100),
    status: str = Query("all", pattern="^(pending|completed|all)$"),
    search: Optional[str] = None,
):
    todos = storage.get_todos(limit=limit, status=status, search=search)
    return {"todos": todos, "total": len(todos), "limit": limit, "offset": 0}


@app.post("/api/todos", status_code=201)
async def create_todo(todo: TodoCreate):
    created = storage.create_todo(
        title=todo.title, description=todo.description, status=todo.status
    )
    return created


@app.get("/health")
async def health():
    return {"status": "healthy"}
