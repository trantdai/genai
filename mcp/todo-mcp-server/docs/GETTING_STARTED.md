# Getting Started with Todo MCP Server

Welcome! This guide will help you get the Todo MCP Server up and running in minutes.

## 🎯 Choose Your Setup Method

### 🐳 Docker (Fastest - Recommended)

If you have Docker installed, you can start both services with a single command:

```bash
cd todo-mcp-server
docker compose up -d
```

**Done!** Skip to [Step 7: Configure Roo Code](#step-7-configure-roo-code-vs-code-extension)

See the [Docker Quick Start Guide](../DOCKER_QUICK_START.md) or [Docker Deployment Guide](./DOCKER_DEPLOYMENT.md) for more details.

### 🐍 Python Virtual Environment (This Guide)

This guide covers the traditional Python setup. Continue reading below.

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.8+** - Check with `python3 --version`
- **pip** - Python package installer
- **curl** (optional) - For testing API endpoints
- **VS Code with Roo Code extension** (optional) - For using the MCP tools

## 🚀 Quick Start (5 Minutes)

### Step 1: Navigate to Project Directory

```bash
cd todo-mcp-server
```

### Step 2: Set Up Python Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
# On macOS/Linux:
source venv/bin/activate

# On Windows:
# venv\Scripts\activate

# Verify activation (you should see (venv) in your prompt)
which python  # Should point to venv/bin/python
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

Expected output:
```
Successfully installed fastapi-0.104.0 uvicorn-0.24.0 pydantic-2.0.0 httpx-0.25.0 python-dotenv-1.0.0 mcp-1.0.0
```

### Step 4: Start the Backend API

Open a **new terminal window** (Terminal 1):

```bash
cd todo-mcp-server
source venv/bin/activate  # Activate venv
uvicorn src.todo_mcp_server.api.main:app --reload --port 8000
```

You should see:
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

✅ **Backend API is now running on http://localhost:8000**

### Step 5: Test the Backend API (Optional)

Open a **third terminal** to test:

```bash
# Test health endpoint
curl http://localhost:8000/health

# Expected: {"status":"healthy"}

# List todos (empty initially)
curl http://localhost:8000/api/todos

# Expected: {"todos":[],"total":0,"limit":10,"offset":0}

# Create a todo
curl -X POST http://localhost:8000/api/todos \
  -H "Content-Type: application/json" \
  -d '{"title":"Learn MCP","description":"Study MCP protocol"}'

# Expected: {"id":"...","title":"Learn MCP",...}

# List todos again
curl http://localhost:8000/api/todos

# Expected: {"todos":[{...}],"total":1,"limit":10,"offset":0}
```

### Step 6: Start the MCP Server

Open **another new terminal window** (Terminal 2):

```bash
cd todo-mcp-server
source venv/bin/activate  # Activate venv
python -m src.todo_mcp_server.cli --transport streamable-http --port 8080
```

You should see:
```
2024-01-04 10:00:00 - todo_mcp_server - INFO - Starting Todo MCP Server with streamable-http transport
2024-01-04 10:00:00 - todo_mcp_server - INFO - Initializing Todo API client for http://localhost:8000
2024-01-04 10:00:00 - todo_mcp_server - INFO - Tools registered successfully
INFO:     Uvicorn running on http://127.0.0.1:8080 (Press CTRL+C to quit)
```

✅ **MCP Server is now running on http://localhost:8080/mcp**

### Step 7: Configure Roo Code (VS Code Extension)

You can configure the Todo MCP Server in Roo Code using either of these methods:

#### Method 1: Project-Level Configuration (Recommended)

Create a `.roo/mcp.json` file in your project root directory:

```bash
# From the project root (groupsec-playground)
mkdir -p .roo
cat > .roo/mcp.json << 'EOF'
{
  "mcpServers": {
    "todo": {
      "type": "streamable-http",
      "url": "http://localhost:8080/mcp",
      "disabled": true,
      "alwaysAllow": []
    }
  }
}
EOF
```

**Benefits:**
- Configuration is project-specific
- Can be committed to version control
- Easy to share with team members
- Automatically loaded when opening the project

#### Method 2: Global Configuration

1. Open VS Code
2. Open Settings (Cmd/Ctrl + ,)
3. Search for "MCP"
4. Click "Edit in settings.json"
5. Add the Todo MCP Server configuration:

```json
{
  "mcpServers": {
    "todo": {
      "type": "streamable-http",
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

**Benefits:**
- Available across all projects
- Persists across VS Code sessions

#### Verify Configuration

After configuring using either method:
1. Save the configuration file
2. Restart VS Code (or reload the window with Cmd/Ctrl + Shift + P → "Developer: Reload Window")
3. Open Roo Code chat
4. The Todo MCP Server should appear in the available tools

### Step 8: Use the MCP Tools

In Roo Code chat, try these commands:

```
"Use the Todo MCP Server to create a new todo: 'Learn FastMCP'"
```

```
"Show me all my todos"
```

```
"Create a todo for 'Build production app' with description 'Deploy to cloud'"
```

```
"Find todos containing 'learn'"
```

🎉 **Congratulations! Your Todo MCP Server is fully operational!**

---

## 📚 Understanding the Architecture

### System Overview

```
┌─────────────────┐
│   Roo Code      │  ← You interact here
│   (VS Code)     │
└────────┬────────┘
         │ HTTP (streamable-http)
         ▼
┌─────────────────┐
│  MCP Server     │  ← Port 8080
│  (FastMCP)      │
└────────┬────────┘
         │ HTTP REST API
         ▼
┌─────────────────┐
│  Backend API    │  ← Port 8000
│  (FastAPI)      │
└─────────────────┘
```

### Component Breakdown

1. **Backend API (Port 8000)**
   - FastAPI REST service
   - In-memory todo storage
   - Endpoints: GET/POST /api/todos, GET /health

2. **MCP Server (Port 8080)**
   - FastMCP server with streamable-http transport
   - Exposes two tools: `get_todos` and `create_todo`
   - Communicates with Backend API via HTTP

3. **AI Client (Roo Code)**
   - Connects to MCP Server
   - Uses natural language to invoke tools
   - Displays results to user

---

## 🔧 Configuration Options

### Environment Variables

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Edit `.env`:

```bash
# Todo API Configuration
TODO_API_URL=http://localhost:8000

# Logging
LOG_LEVEL=INFO  # Options: DEBUG, INFO, WARNING, ERROR

# MCP Server
MCP_PORT=8080
```

### CLI Options

The MCP server supports various command-line options:

```bash
python -m src.todo_mcp_server.cli --help
```

Options:
- `--api-url TEXT` - Todo API URL (default: http://localhost:8000)
- `--env-file TEXT` - Path to .env file
- `--log-level TEXT` - Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)
- `--transport TEXT` - Transport type: stdio, streamable-http (default: streamable-http)
- `--port INTEGER` - Port for streamable-http (default: 8080)

Example with custom settings:

```bash
python -m src.todo_mcp_server.cli \
  --api-url http://localhost:8000 \
  --log-level DEBUG \
  --transport streamable-http \
  --port 8080
```

---

## 🧪 Testing & Development

### Manual API Testing

```bash
# Health check
curl http://localhost:8000/health

# List all todos
curl http://localhost:8000/api/todos

# List pending todos only
curl "http://localhost:8000/api/todos?status=pending"

# Search todos
curl "http://localhost:8000/api/todos?search=learn"

# Limit results
curl "http://localhost:8000/api/todos?limit=5"

# Create a todo
curl -X POST http://localhost:8000/api/todos \
  -H "Content-Type: application/json" \
  -d '{
    "title": "My Todo",
    "description": "Todo description",
    "status": "pending"
  }'
```

### Testing MCP Tools

**Prerequisites**: Ensure you have completed [Step 7: Configure Roo Code](#step-7-configure-roo-code-vs-code-extension) to add the Todo MCP Server to your Roo Code settings.

Once the MCP server is configured in Roo Code (see Step 7 above), test with these prompts:

**Create Todos:**
```
"Create a todo: 'Learn Python'"
"Add a new todo 'Build MCP server' with description 'Follow the guide'"
"Create a completed todo: 'Setup environment'"
```

**List Todos:**
```
"Show me all todos"
"List all pending todos"
"What todos do I have?"
```

**Search Todos:**
```
"Find todos about learning"
"Search for todos containing 'MCP'"
```

### Development Mode

For development with auto-reload:

```bash
# Backend API with auto-reload (already enabled with --reload)
uvicorn src.todo_mcp_server.api.main:app --reload --port 8000

# MCP Server (restart manually after code changes)
python -m src.todo_mcp_server.cli --log-level DEBUG
```

---

## 🐛 Troubleshooting

### Issue: Port Already in Use

**Error:** `Address already in use`

**Solution:**
```bash
# Find process using port 8000
lsof -i :8000

# Kill the process
kill -9 <PID>

# Or use a different port
uvicorn src.todo_mcp_server.api.main:app --reload --port 8001
```

### Issue: Module Not Found

**Error:** `ModuleNotFoundError: No module named 'fastapi'`

**Solution:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### Issue: Connection Refused

**Error:** `Connection refused` when MCP server tries to reach API

**Solution:**
1. Ensure Backend API is running on port 8000
2. Check API URL in configuration
3. Test API directly: `curl http://localhost:8000/health`

### Issue: MCP Server Not Found in Roo Code

**Solution:**
1. Verify MCP server is running: `curl http://localhost:8080/mcp`
2. Check Roo Code settings.json configuration
3. Restart VS Code
4. Check Roo Code logs for connection errors

### Issue: Tools Not Working

**Solution:**
1. Check both servers are running
2. Verify logs for errors in both terminals
3. Test API directly with curl
4. Restart both servers

---

## 📖 Next Steps

### Learn More

1. **Explore the Code**
   - [`api/main.py`](../src/todo_mcp_server/api/main.py) - API endpoints
   - [`server.py`](../src/todo_mcp_server/server.py) - MCP server setup
   - [`tools/`](../src/todo_mcp_server/tools/) - MCP tool implementations

2. **Read Documentation**
   - [`README.md`](../README.md) - Project overview
   - [`todo-mcp-implementation-guide.md`](./todo-mcp-implementation-guide.md) - Implementation details
   - [`todo-mcp-server-architecture.md`](./todo-mcp-server-architecture.md) - Architecture deep dive

3. **Extend the Server**
   - Add update/delete todo operations
   - Implement persistent storage (SQLite, PostgreSQL)
   - Add authentication
   - Create additional MCP tools

### Common Development Tasks

**Add a New Tool:**
1. Create `src/todo_mcp_server/tools/my_tool.py`
2. Implement `register_my_tool(mcp: FastMCP)`
3. Add to `src/todo_mcp_server/tools/__init__.py`
4. Restart MCP server

**Add a New API Endpoint:**
1. Add endpoint to `src/todo_mcp_server/api/main.py`
2. Add method to `TodoAPIClient` in `utils/http_client.py`
3. Create corresponding MCP tool
4. Restart both servers

**Change Storage Backend:**
1. Modify `src/todo_mcp_server/api/storage.py`
2. Keep the same interface (create_todo, get_todos)
3. Restart API server

---

## 💡 Tips for Success

1. **Keep Both Servers Running** - The MCP server needs the API server
2. **Check Logs** - Both servers provide helpful debug information
3. **Test Incrementally** - Test API first, then MCP server, then tools
4. **Use DEBUG Logging** - Set `LOG_LEVEL=DEBUG` for detailed logs
5. **Restart After Changes** - Code changes require server restarts

---

## 🆘 Getting Help

If you encounter issues:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Review server logs for error messages
3. Test each component independently
4. Verify all prerequisites are installed
5. Ensure ports 8000 and 8080 are available

---

## ✅ Checklist

Before reporting issues, verify:

- [ ] Python 3.8+ is installed
- [ ] Virtual environment is activated
- [ ] All dependencies are installed (`pip list`)
- [ ] Backend API is running on port 8000
- [ ] MCP Server is running on port 8080
- [ ] Roo Code is configured correctly
- [ ] Both servers show no errors in logs
- [ ] API responds to curl requests
- [ ] Ports 8000 and 8080 are not blocked by firewall

---

Happy coding! 🚀
