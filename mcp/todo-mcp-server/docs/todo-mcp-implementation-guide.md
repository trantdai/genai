# Todo MCP Server - Implementation Guide

## 🎯 Quick Start Summary

This guide provides a step-by-step implementation roadmap for building a learning-focused MCP server that follows CBA standards.

---

## 📦 What You'll Build

A complete MCP server system with:
- **Backend API**: Simple FastAPI REST service with 2 endpoints (GET/POST)
- **MCP Server**: FastMCP server with streamable-http transport
- **MCP Tools**: Two tools that wrap the API endpoints
- **Documentation**: Complete setup and usage guides

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Client (Roo/Cline)                    │
│                                                             │
│  User: "Show me all pending todos"                         │
└─────────────────┬───────────────────────────────────────────┘
                  │ streamable-http
                  ▼
┌─────────────────────────────────────────────────────────────┐
│              FastMCP Server (Port 8080)                     │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐                       │
│  │  get_todos   │  │ create_todo  │  MCP Tools            │
│  └──────┬───────┘  └──────┬───────┘                       │
│         │                  │                                │
│         └──────────┬───────┘                                │
│                    │ HTTP Client                            │
└────────────────────┼────────────────────────────────────────┘
                     │ REST API calls
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Todo API (FastAPI - Port 8000)                 │
│                                                             │
│  GET  /api/todos     →  List todos                         │
│  POST /api/todos     →  Create todo                        │
│                                                             │
│  Storage: In-Memory List                                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Implementation Phases

### Phase 1: Backend API (FastAPI) ⏱️ ~2-3 hours

**Goal**: Create a working REST API for todo operations

#### Step 1.1: Project Setup
```bash
# Create project directory
mkdir -p src/todo_mcp_server/api
cd todo-mcp-server

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install fastapi uvicorn pydantic httpx python-dotenv
```

#### Step 1.2: Create Data Models
**File**: [`src/todo_mcp_server/api/models.py`](src/todo_mcp_server/api/models.py:1)

```python
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
```

#### Step 1.3: Create Storage Layer
**File**: [`src/todo_mcp_server/api/storage.py`](src/todo_mcp_server/api/storage.py:1)

```python
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
            "updated_at": datetime.utcnow().isoformat()
        }
        self.todos.append(todo)
        return todo

    def get_todos(self, limit: int = 10, status: str = "all",
                  search: Optional[str] = None) -> List[dict]:
        filtered = self.todos

        # Filter by status
        if status != "all":
            filtered = [t for t in filtered if t["status"] == status]

        # Filter by search term
        if search:
            filtered = [t for t in filtered
                       if search.lower() in t["title"].lower()]

        return filtered[:limit]
```

#### Step 1.4: Create API Endpoints
**File**: [`src/todo_mcp_server/api/main.py`](src/todo_mcp_server/api/main.py:1)

```python
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
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
    search: Optional[str] = None
):
    todos = storage.get_todos(limit=limit, status=status, search=search)
    return {
        "todos": todos,
        "total": len(todos),
        "limit": limit,
        "offset": 0
    }

@app.post("/api/todos", status_code=201)
async def create_todo(todo: TodoCreate):
    created = storage.create_todo(
        title=todo.title,
        description=todo.description,
        status=todo.status
    )
    return created

@app.get("/health")
async def health():
    return {"status": "healthy"}
```

#### Step 1.5: Test the API
```bash
# Run the API server
uvicorn src.todo_mcp_server.api.main:app --reload --port 8000

# Test in another terminal
curl http://localhost:8000/api/todos
curl -X POST http://localhost:8000/api/todos \
  -H "Content-Type: application/json" \
  -d '{"title":"Learn MCP","description":"Study MCP protocol"}'
```

**✅ Phase 1 Complete**: You now have a working REST API!

---

### Phase 2: FastMCP Server Core ⏱️ ~2-3 hours

**Goal**: Set up the MCP server infrastructure

#### Step 2.1: Install FastMCP
```bash
pip install "mcp[cli]"
```

#### Step 2.2: Create Utilities

**File**: [`src/todo_mcp_server/utils/logger.py`](src/todo_mcp_server/utils/logger.py:1)
```python
import logging
import os

def get_logger(name: str = "todo_mcp_server") -> logging.Logger:
    logger = logging.getLogger(name)
    level = os.getenv("LOG_LEVEL", "INFO")
    logger.setLevel(getattr(logging, level))

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
```

**File**: [`src/todo_mcp_server/utils/http_client.py`](src/todo_mcp_server/utils/http_client.py:1)
```python
import httpx
from typing import Optional, Dict, Any
from .logger import get_logger

logger = get_logger()

class TodoAPIClient:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(base_url=base_url, timeout=30.0)

    async def get_todos(self, limit: int = 10, status: str = "all",
                       search: Optional[str] = None) -> Dict[str, Any]:
        params = {"limit": limit, "status": status}
        if search:
            params["search"] = search

        response = await self.client.get("/api/todos", params=params)
        response.raise_for_status()
        return response.json()

    async def create_todo(self, title: str, description: str = "",
                         status: str = "pending") -> Dict[str, Any]:
        data = {
            "title": title,
            "description": description,
            "status": status
        }
        response = await self.client.post("/api/todos", json=data)
        response.raise_for_status()
        return response.json()

    async def close(self):
        await self.client.aclose()
```

**File**: [`src/todo_mcp_server/utils/context.py`](src/todo_mcp_server/utils/context.py:1)
```python
from dataclasses import dataclass
from .http_client import TodoAPIClient

@dataclass
class TodoContext:
    """Context object passed to MCP tools"""
    api_client: TodoAPIClient
    api_url: str
```

#### Step 2.3: Create Main Server

**File**: [`src/todo_mcp_server/server.py`](src/todo_mcp_server/server.py:1)
```python
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
```

**Note**: The `SERVER_DESCRIPTION` constant is defined but not passed to FastMCP as the current version of FastMCP does not accept a `description` parameter. The server name is sufficient for identification. The host and port parameters allow flexible network configuration, with the port being passed from the CLI to the server creation function rather than to `server.run()`.

**✅ Phase 2 Complete**: MCP server infrastructure is ready!

---

### Phase 3: MCP Tools ⏱️ ~2-3 hours

**Goal**: Create the two MCP tools

#### Step 3.1: Create get_todos Tool

**File**: [`src/todo_mcp_server/tools/get_todos.py`](src/todo_mcp_server/tools/get_todos.py:1)
```python
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
```

#### Step 3.2: Create create_todo Tool

**File**: [`src/todo_mcp_server/tools/create_todo.py`](src/todo_mcp_server/tools/create_todo.py:1)
```python
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
```

#### Step 3.3: Create Tool Registry

**File**: [`src/todo_mcp_server/tools/__init__.py`](src/todo_mcp_server/tools/__init__.py:1)
```python
from mcp.server.fastmcp import FastMCP
from .get_todos import register_get_todos_tool
from .create_todo import register_create_todo_tool

def register_tools(mcp: FastMCP) -> None:
    """Register all tools with the FastMCP server"""
    register_get_todos_tool(mcp)
    register_create_todo_tool(mcp)
```

**✅ Phase 3 Complete**: MCP tools are implemented!

---

### Phase 4: CLI & Configuration ⏱️ ~1 hour

#### Step 4.1: Create CLI

**File**: [`src/todo_mcp_server/cli.py`](src/todo_mcp_server/cli.py:1)
```python
#!/usr/bin/env python3
import argparse
import os
from .server import create_server
from .utils.logger import get_logger

logger = get_logger()

def parse_args():
    parser = argparse.ArgumentParser(description="Todo MCP Server")
    parser.add_argument("--api-url", help="Todo API URL",
                       default="http://localhost:8000")
    parser.add_argument("--env-file", help="Path to .env file")
    parser.add_argument("--log-level", help="Log level",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       default="INFO")
    parser.add_argument("--transport", help="Transport type",
                       choices=["stdio", "streamable-http"],
                       default="streamable-http")
    parser.add_argument("--port", help="Port for streamable-http",
                       type=int, default=8080)
    return parser.parse_args()

def main():
    args = parse_args()

    # Set environment variables
    os.environ["TODO_API_URL"] = args.api_url
    os.environ["LOG_LEVEL"] = args.log_level

    logger.info(f"Starting Todo MCP Server with {args.transport} transport")

    # Create and run server with port configuration
    server = create_server(
        env_file_path=args.env_file, host="127.0.0.1", port=args.port
    )

    if args.transport == "streamable-http":
        server.run(transport="streamable-http")
    else:
        server.run(transport="stdio")

if __name__ == "__main__":
    main()
```

**Note**: The port configuration is passed to `create_server()` rather than `server.run()`. This allows the FastMCP server to bind to the specified port during initialization, which is the recommended approach for streamable-http transport.

#### Step 4.2: Create Configuration Files

**File**: [`.env.example`](.env.example:1)
```bash
# Todo API Configuration
TODO_API_URL=http://localhost:8000

# Logging
LOG_LEVEL=INFO

# MCP Server
MCP_PORT=8080
```

**File**: [`requirements.txt`](requirements.txt:1)
```
fastapi>=0.104.0
uvicorn>=0.24.0
pydantic>=2.0.0
httpx>=0.25.0
python-dotenv>=1.0.0
mcp[cli]>=1.0.0
```

**✅ Phase 4 Complete**: Server is ready to run!

---

## 🧪 Testing Your Implementation

### Test 1: Start the Backend API
```bash
# Terminal 1: Start the Todo API
uvicorn src.todo_mcp_server.api.main:app --reload --port 8000
```

### Test 2: Start the MCP Server
```bash
# Terminal 2: Start the MCP Server
python -m src.todo_mcp_server.cli --transport streamable-http --port 8080
```

### Test 3: Configure AI Client

**For Roo Code** - Add to MCP settings:
```json
{
  "mcpServers": {
    "Todo MCP Server": {
      "type": "streamable-http",
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

### Test 4: Use the Tools

In your AI client, try:
```
"Use the Todo MCP Server to create a new todo: 'Learn MCP Protocol'"
"Show me all pending todos"
"Create a todo for 'Build production app' with status completed"
```

---

## 📚 Key Learning Points

### 1. **FastMCP Simplifies Development**
- No manual endpoint management
- Automatic tool discovery
- Built-in context management

### 2. **Streamable-HTTP is Modern**
- Single `/mcp` endpoint
- Better reliability than SSE
- Easier to deploy and scale

### 3. **Dynamic Tool Registration**
- Tools are Python functions with decorators
- Automatic parameter validation
- Type hints provide documentation

### 4. **Context Management**
- Lifespan manager handles startup/shutdown
- Context passed to all tools
- Clean resource management

### 5. **Network Configuration**
- Host and port are configured at server creation time
- Port is passed to `create_server()` not `server.run()`
- This allows proper binding during initialization
- Provides flexibility for different deployment scenarios

---

## 💡 Tips for Success

- **Start with Phase 1**: Get the API working first
- **Test incrementally**: Test each phase before moving on
- **Use logging**: Add logger statements to understand flow
- **Read error messages**: They usually tell you what's wrong
- **Refer to wiz-mcp**: Use it as a reference implementation

---

## 🆘 Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Port already in use | Change port or kill existing process |
| Module not found | Check PYTHONPATH and package structure |
| Connection refused | Ensure API server is running |
| Tool not found | Check tool registration in `__init__.py` |
| Context error | Verify lifespan manager is working |

---

Ready to start building? Let me know if you have any questions about the implementation plan!
