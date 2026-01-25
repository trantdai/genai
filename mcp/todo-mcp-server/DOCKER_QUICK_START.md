# Docker Quick Start Guide

A quick reference for running the Todo MCP Server with Docker.

## 🚀 One-Command Start

```bash
cd todo-mcp-server
docker compose up -d
```

**Services Available:**
- Backend API: http://localhost:8000
- MCP Server: http://localhost:8080/mcp

## 📋 Essential Commands

### Start Services

```bash
# Start in background (detached)
docker compose up -d

# Start in foreground (see logs)
docker compose up

# Start production mode
docker compose -f docker-compose.prod.yml up -d
```

### Stop Services

```bash
# Stop services (keep containers)
docker compose stop

# Stop and remove containers
docker compose down

# Stop, remove containers and volumes
docker compose down -v
```

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f api
docker compose logs -f mcp

# Last 100 lines
docker compose logs --tail=100
```

### Check Status

```bash
# Container status
docker compose ps

# Resource usage
docker stats todo-api todo-mcp

# Health check
curl http://localhost:8000/health
curl http://localhost:8080/mcp
```

### Rebuild After Code Changes

```bash
# Rebuild and restart
docker compose up -d --build

# Rebuild specific service
docker compose build api
docker compose up -d api
```

### Troubleshooting

```bash
# View container details
docker inspect todo-api

# Execute shell in container
docker compose exec api /bin/sh
docker compose exec mcp /bin/sh

# View network details
docker network inspect todo-mcp-server_todo-network

# Clean up everything
docker compose down -v
docker system prune -a
```

## 🌐 Configure Roo Code

### Local Docker

Add to `.roo/mcp.json`:

```json
{
  "mcpServers": {
    "todo": {
      "type": "streamable-http",
      "url": "http://localhost:8080/mcp",
      "disabled": false,
      "alwaysAllow": []
    }
  }
}
```

### Remote Docker

Replace `localhost` with your server address:

```json
{
  "mcpServers": {
    "todo": {
      "type": "streamable-http",
      "url": "http://your-server.com:8080/mcp",
      "disabled": false,
      "alwaysAllow": []
    }
  }
}
```

## 🧪 Test the Services

```bash
# Test API
curl http://localhost:8000/health
curl http://localhost:8000/api/todos

# Create a todo
curl -X POST http://localhost:8000/api/todos \
  -H "Content-Type: application/json" \
  -d '{"title":"Test Docker","description":"Testing containerized setup"}'

# Test MCP server
curl http://localhost:8080/mcp
```

## ⚙️ Environment Variables

Create `.env` file:

```bash
# Logging
LOG_LEVEL=INFO

# Ports (for production)
API_PORT=8000
MCP_PORT=8080
```

## 🔧 Common Issues

### Port Already in Use

```bash
# Find process using port
lsof -i :8000
lsof -i :8080

# Kill process
kill -9 <PID>

# Or use different ports
API_PORT=9000 MCP_PORT=9080 docker compose up -d
```

### Container Won't Start

```bash
# Check logs
docker compose logs api
docker compose logs mcp

# Restart services
docker compose restart

# Rebuild from scratch
docker compose down -v
docker compose up -d --build
```

### MCP Can't Connect to API

```bash
# Check API health
docker compose exec mcp curl http://api:8000/health

# Verify network
docker network inspect todo-mcp-server_todo-network

# Restart MCP
docker compose restart mcp
```

## 📚 Full Documentation

For detailed information, see:
- [Docker Deployment Guide](docs/DOCKER_DEPLOYMENT.md) - Complete Docker guide
- [Getting Started Guide](docs/GETTING_STARTED.md) - Python virtual environment setup
- [README](README.md) - Project overview

## 🎯 Quick Tips

1. **Always use `-d` flag** for background execution
2. **Check logs first** when troubleshooting: `docker compose logs -f`
3. **Rebuild after code changes**: `docker compose up -d --build`
4. **Clean up regularly**: `docker system prune` to free space
5. **Use production compose** for deployment: `docker compose -f docker-compose.prod.yml up -d`

---

Happy containerizing! 🐳
