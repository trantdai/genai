# Todo MCP Server

A learning-focused MCP (Model Context Protocol) server that provides tools for managing todos through a REST API backend.

## Architecture

This project consists of two main components:

1. **Backend API (FastAPI)**: A simple REST API with in-memory storage for todo items
2. **MCP Server (FastMCP)**: An MCP server that exposes tools to interact with the Todo API

## Project Structure

```
todo-mcp-server/
├── src/
│   └── todo_mcp_server/
│       ├── api/                 # FastAPI backend
│       │   ├── __init__.py
│       │   ├── main.py         # API endpoints
│       │   ├── models.py       # Pydantic models
│       │   └── storage.py      # In-memory storage
│       ├── tools/              # MCP tools
│       │   ├── __init__.py
│       │   ├── get_todos.py    # Tool to retrieve todos
│       │   └── create_todo.py  # Tool to create todos
│       ├── utils/              # Utilities
│       │   ├── __init__.py
│       │   ├── logger.py       # Logging configuration
│       │   ├── http_client.py  # HTTP client for API
│       │   └── context.py      # Context management
│       ├── server.py           # MCP server setup
│       └── cli.py              # Command-line interface
├── docs/                       # Documentation
├── .env.example               # Environment variables template
└── requirements.txt           # Python dependencies
```

## Quick Start

Choose your preferred deployment method:

### 🐳 Docker (Recommended)

The fastest way to get started - runs both services with a single command:

```bash
cd todo-mcp-server
docker compose up -d
```

That's it! The services are now running:
- Backend API: `http://localhost:8000`
- MCP Server: `http://localhost:8080/mcp`

See the [Docker Deployment Guide](docs/DOCKER_DEPLOYMENT.md) for detailed instructions on:
- Local container deployment
- Remote container deployment
- Production configurations
- Troubleshooting

### 🐍 Python Virtual Environment

For development or if you prefer running without Docker:

1. Create a virtual environment:
```bash
cd todo-mcp-server
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file (optional):
```bash
cp .env.example .env
# Edit .env with your configuration
```

See the [Getting Started Guide](docs/GETTING_STARTED.md) for detailed step-by-step instructions.

## Usage

### Step 1: Start the Backend API

In one terminal, start the FastAPI backend:

```bash
uvicorn src.todo_mcp_server.api.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`

### Step 2: Start the MCP Server

In another terminal, start the MCP server:

```bash
python -m src.todo_mcp_server.cli --transport streamable-http --port 8080
```

The MCP server will be available at `http://localhost:8080/mcp`

### Step 3: Configure Your AI Client

Add the MCP server to your AI client configuration (e.g., Roo Code):

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

### Step 4: Use the Tools

In your AI client, you can now use the todo tools:

- **Create a todo**: "Use the Todo MCP Server to create a new todo: 'Learn MCP Protocol'"
- **List todos**: "Show me all pending todos"
- **Search todos**: "Find todos containing 'learn'"

## Available Tools

### `get_todos`

Retrieve todos from the API with optional filtering.

**Parameters:**
- `limit` (int, default: 10): Maximum number of todos to return (1-100)
- `status` (str, default: "all"): Filter by status - 'pending', 'completed', or 'all'
- `search` (str, optional): Search term to filter todos by title

**Example:**
```python
get_todos(limit=5, status="pending")
get_todos(search="learn")
```

### `create_todo`

Create a new todo item.

**Parameters:**
- `title` (str, required): Todo title (1-200 characters)
- `description` (str, default: ""): Todo description (max 1000 characters)
- `status` (str, default: "pending"): Initial status - 'pending' or 'completed'

**Example:**
```python
create_todo(title="Learn FastMCP", description="Study the framework")
create_todo(title="Build MCP server", status="pending")
```

## API Endpoints

The backend API provides the following endpoints:

- `GET /api/todos` - List todos with optional filtering
  - Query params: `limit`, `status`, `search`
- `POST /api/todos` - Create a new todo
  - Body: `{"title": "...", "description": "...", "status": "..."}`
- `GET /health` - Health check endpoint

## Configuration

Environment variables (can be set in `.env` file):

- `TODO_API_URL`: URL of the Todo API (default: `http://localhost:8000`)
- `LOG_LEVEL`: Logging level (default: `INFO`)
- `MCP_PORT`: Port for MCP server (default: `8080`)

## CLI Options

```bash
python -m src.todo_mcp_server.cli [OPTIONS]

Options:
  --api-url TEXT          Todo API URL (default: http://localhost:8000)
  --env-file TEXT         Path to .env file
  --log-level TEXT        Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)
  --transport TEXT        Transport type: stdio, streamable-http (default: streamable-http)
  --port INTEGER          Port for streamable-http (default: 8080)
```

## Testing

### Test the API directly

```bash
# List todos
curl http://localhost:8000/api/todos

# Create a todo
curl -X POST http://localhost:8000/api/todos \
  -H "Content-Type: application/json" \
  -d '{"title":"Learn MCP","description":"Study MCP protocol"}'

# Search todos
curl "http://localhost:8000/api/todos?search=learn&status=pending"
```

### Test the MCP Server

Once configured in your AI client, try these prompts:

1. "Create a todo to learn Python"
2. "Show me all my todos"
3. "Find todos about learning"

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Port already in use | Change the port using `--port` option or kill the existing process |
| Module not found | Ensure you're in the project root and virtual environment is activated |
| Connection refused | Make sure the API server is running on port 8000 |
| Tool not found | Check that both servers are running and properly configured |

## Documentation

- **[Getting Started Guide](docs/GETTING_STARTED.md)** - Detailed step-by-step setup with Python virtual environment
- **[Docker Deployment Guide](docs/DOCKER_DEPLOYMENT.md)** - Complete guide for Docker deployment (local and remote)
- **[Architecture Documentation](docs/todo-mcp-server-architecture.md)** - System architecture and design decisions
- **[Implementation Guide](docs/todo-mcp-implementation-guide.md)** - Technical implementation details

## Learning Resources

- [MCP Documentation](https://modelcontextprotocol.io/)
- [FastMCP Documentation](https://github.com/jlowin/fastmcp)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Docker Documentation](https://docs.docker.com/)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

This is a learning project created for educational purposes to demonstrate MCP server implementation best practices.
