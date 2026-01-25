# Docker Deployment Guide

This guide explains how to run the Todo MCP Server using Docker containers, both locally and as a remote service.

## 📋 Table of Contents

- [Prerequisites](#-prerequisites)
- [Quick Start with Docker Compose](#-quick-start-with-docker-compose)
- [Local Container Deployment](#-local-container-deployment)
- [Remote Container Deployment](#-remote-container-deployment)
- [Building Individual Images](#-building-individual-images)
- [Configuration](#-configuration)
- [Networking](#-networking)
- [Troubleshooting](#-troubleshooting)
- [Production Considerations](#-production-considerations)

---

## 📋 Prerequisites

Before you begin, ensure you have:

- **Docker** 20.10+ - Check with `docker --version`
- **Docker Compose** 2.0+ - Check with `docker compose version`
- Basic understanding of Docker concepts

### Install Docker

**macOS:**
```bash
brew install --cask docker
# Or download Docker Desktop from https://www.docker.com/products/docker-desktop
```

**Linux (Ubuntu/Debian):**
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

**Windows:**
Download and install Docker Desktop from https://www.docker.com/products/docker-desktop

---

## 🚀 Quick Start with Docker Compose

The fastest way to run both services together.

### Step 1: Navigate to Project Directory

```bash
cd todo-mcp-server
```

### Step 2: Start All Services

```bash
# Start in foreground (see logs)
docker compose up

# Or start in background (detached mode)
docker compose up -d
```

Expected output:
```
[+] Running 3/3
 ✔ Network todo-mcp-server_todo-network  Created
 ✔ Container todo-api                     Started
 ✔ Container todo-mcp                     Started
```

### Step 3: Verify Services are Running

```bash
# Check container status
docker compose ps

# Expected output:
# NAME       IMAGE                    STATUS         PORTS
# todo-api   todo-mcp-server-api      Up (healthy)   0.0.0.0:8000->8000/tcp
# todo-mcp   todo-mcp-server-mcp      Up             0.0.0.0:8080->8080/tcp

# Test the API
curl http://localhost:8000/health
# Expected: {"status":"healthy"}

# Test the MCP server
curl http://localhost:8080/mcp
# Expected: MCP server response
```

### Step 4: View Logs

```bash
# View all logs
docker compose logs

# Follow logs in real-time
docker compose logs -f

# View logs for specific service
docker compose logs -f api
docker compose logs -f mcp
```

### Step 5: Stop Services

```bash
# Stop services (keeps containers)
docker compose stop

# Stop and remove containers
docker compose down

# Stop, remove containers, and remove volumes
docker compose down -v
```

🎉 **Your Todo MCP Server is now running in Docker!**

---

## 🏠 Local Container Deployment

Run containers locally for development and testing.

### Architecture

```
┌─────────────────────────────────────────────────┐
│              Docker Host (localhost)            │
│                                                 │
│  ┌──────────────┐         ┌──────────────┐    │
│  │  todo-api    │         │  todo-mcp    │    │
│  │  Port: 8000  │◄────────│  Port: 8080  │    │
│  └──────────────┘         └──────────────┘    │
│         │                         │            │
└─────────┼─────────────────────────┼────────────┘
          │                         │
          ▼                         ▼
    localhost:8000            localhost:8080
```

### Development Mode (docker-compose.yml)

**Features:**
- Auto-restart on failure
- Health checks enabled
- Logs at INFO level
- Suitable for development and testing

```bash
# Start services
docker compose up -d

# Rebuild after code changes
docker compose up -d --build

# View logs
docker compose logs -f
```

### Production Mode (docker-compose.prod.yml)

**Features:**
- Resource limits (CPU/Memory)
- Always restart policy
- Logs at WARNING level
- Optimized for production

```bash
# Start production services
docker compose -f docker-compose.prod.yml up -d

# With custom ports
API_PORT=9000 MCP_PORT=9080 docker compose -f docker-compose.prod.yml up -d

# View logs
docker compose -f docker-compose.prod.yml logs -f
```

### Configure Roo Code for Local Docker

Update your [`.roo/mcp.json`](../../../.roo/mcp.json):

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

---

## 🌐 Remote Container Deployment

Deploy containers to a remote server and access them from your local machine.

### Scenario 1: Deploy to Remote Server (Cloud VM)

#### On Remote Server

```bash
# SSH into your remote server
ssh user@your-server.com

# Clone repository
git clone <your-repo-url>
cd todo-mcp-server

# Start services
docker compose -f docker-compose.prod.yml up -d

# Verify services
docker compose ps
curl http://localhost:8000/health
```

#### Configure Firewall

```bash
# Allow incoming traffic on ports 8000 and 8080
# Ubuntu/Debian with UFW
sudo ufw allow 8000/tcp
sudo ufw allow 8080/tcp
sudo ufw reload

# CentOS/RHEL with firewalld
sudo firewall-cmd --permanent --add-port=8000/tcp
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

#### On Local Machine (Roo Code)

Update [`.roo/mcp.json`](../../../.roo/mcp.json):

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

### Scenario 2: Deploy with Reverse Proxy (Recommended)

Use Nginx or Traefik to expose services securely with HTTPS.

#### Nginx Configuration

Create [`nginx.conf`](../nginx.conf):

```nginx
server {
    listen 80;
    server_name your-domain.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/ssl/certs/your-cert.pem;
    ssl_certificate_key /etc/ssl/private/your-key.pem;

    # MCP Server
    location /mcp {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # API (optional, if you want to expose it)
    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Docker Compose with Nginx

Create [`docker-compose.nginx.yml`](../docker-compose.nginx.yml):

```yaml
version: '3.8'

services:
  api:
    build:
      context: .
      dockerfile: Dockerfile.api
    container_name: todo-api
    expose:
      - "8000"
    environment:
      - LOG_LEVEL=${LOG_LEVEL:-WARNING}
    networks:
      - todo-network
    restart: always

  mcp:
    build:
      context: .
      dockerfile: Dockerfile.mcp
    container_name: todo-mcp
    expose:
      - "8080"
    environment:
      - TODO_API_URL=http://api:8000
      - LOG_LEVEL=${LOG_LEVEL:-WARNING}
    depends_on:
      - api
    networks:
      - todo-network
    restart: always

  nginx:
    image: nginx:alpine
    container_name: todo-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./ssl:/etc/ssl:ro
    depends_on:
      - api
      - mcp
    networks:
      - todo-network
    restart: always

networks:
  todo-network:
    driver: bridge
```

#### On Local Machine

```json
{
  "mcpServers": {
    "todo": {
      "type": "streamable-http",
      "url": "https://your-domain.com/mcp",
      "disabled": false,
      "alwaysAllow": []
    }
  }
}
```

### Scenario 3: SSH Tunnel (Development/Testing)

Access remote containers securely without exposing ports.

```bash
# Create SSH tunnel from local to remote
ssh -L 8080:localhost:8080 -L 8000:localhost:8000 user@your-server.com

# Keep terminal open, then in Roo Code use:
# http://localhost:8080/mcp
```

Update [`.roo/mcp.json`](../../../.roo/mcp.json):

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

---

## 🏗️ Building Individual Images

Build and run containers separately for more control.

### Build Images

```bash
# Build API image
docker build -f Dockerfile.api -t todo-api:latest .

# Build MCP image
docker build -f Dockerfile.mcp -t todo-mcp:latest .

# List images
docker images | grep todo
```

### Run API Container

```bash
# Run API container
docker run -d \
  --name todo-api \
  -p 8000:8000 \
  -e LOG_LEVEL=INFO \
  --network todo-network \
  todo-api:latest

# View logs
docker logs -f todo-api

# Test
curl http://localhost:8000/health
```

### Run MCP Container

```bash
# Create network first (if not exists)
docker network create todo-network

# Run MCP container
docker run -d \
  --name todo-mcp \
  -p 8080:8080 \
  -e TODO_API_URL=http://todo-api:8000 \
  -e LOG_LEVEL=INFO \
  --network todo-network \
  todo-mcp:latest

# View logs
docker logs -f todo-mcp

# Test
curl http://localhost:8080/mcp
```

### Push to Registry

```bash
# Tag images
docker tag todo-api:latest your-registry.com/todo-api:latest
docker tag todo-mcp:latest your-registry.com/todo-mcp:latest

# Push to registry
docker push your-registry.com/todo-api:latest
docker push your-registry.com/todo-mcp:latest

# Pull on remote server
docker pull your-registry.com/todo-api:latest
docker pull your-registry.com/todo-mcp:latest
```

---

## ⚙️ Configuration

### Environment Variables

Create a [`.env`](../.env) file:

```bash
# Logging
LOG_LEVEL=INFO

# Ports (for production compose)
API_PORT=8000
MCP_PORT=8080

# API URL (internal Docker network)
TODO_API_URL=http://api:8000
```

Load environment file:

```bash
# Docker Compose automatically loads .env
docker compose up -d

# Or specify explicitly
docker compose --env-file .env up -d
```

### Custom Configuration

Override default settings:

```bash
# Custom ports
docker run -d \
  --name todo-api \
  -p 9000:8000 \
  -e LOG_LEVEL=DEBUG \
  todo-api:latest

# Custom API URL for MCP
docker run -d \
  --name todo-mcp \
  -p 9080:8080 \
  -e TODO_API_URL=http://todo-api:8000 \
  -e LOG_LEVEL=DEBUG \
  todo-mcp:latest
```

---

## 🌐 Networking

### Docker Network Types

**Bridge Network (Default):**
- Containers can communicate using container names
- Isolated from host network
- Used in docker-compose.yml

```bash
# Create custom bridge network
docker network create todo-network

# Inspect network
docker network inspect todo-network

# Connect container to network
docker network connect todo-network todo-api
```

**Host Network:**
- Container shares host's network stack
- Better performance, less isolation

```bash
docker run -d \
  --name todo-api \
  --network host \
  todo-api:latest
```

### Service Discovery

Containers in the same Docker network can communicate using service names:

```yaml
services:
  api:
    # Accessible as 'api' from other containers
    container_name: todo-api

  mcp:
    environment:
      # Use service name 'api' instead of localhost
      - TODO_API_URL=http://api:8000
```

---

## 🐛 Troubleshooting

### Issue: Container Won't Start

```bash
# Check container status
docker compose ps

# View logs
docker compose logs api
docker compose logs mcp

# Check for port conflicts
lsof -i :8000
lsof -i :8080

# Restart services
docker compose restart
```

### Issue: MCP Can't Connect to API

```bash
# Verify API is healthy
docker compose ps
# Should show 'Up (healthy)' for api

# Check network connectivity
docker compose exec mcp curl http://api:8000/health

# Check environment variables
docker compose exec mcp env | grep TODO_API_URL

# Restart MCP service
docker compose restart mcp
```

### Issue: Connection Refused from Host

```bash
# Verify ports are exposed
docker compose ps
# Should show 0.0.0.0:8000->8000/tcp

# Check firewall
sudo ufw status
sudo firewall-cmd --list-all

# Test from inside container
docker compose exec api curl http://localhost:8000/health

# Test from host
curl http://localhost:8000/health
```

### Issue: Out of Memory

```bash
# Check container resource usage
docker stats

# Set memory limits in docker-compose.prod.yml
deploy:
  resources:
    limits:
      memory: 512M
```

### Issue: Image Build Fails

```bash
# Clean build cache
docker builder prune

# Rebuild without cache
docker compose build --no-cache

# Check Dockerfile syntax
docker build -f Dockerfile.api --progress=plain .
```

### Debugging Commands

```bash
# Execute shell in running container
docker compose exec api /bin/sh
docker compose exec mcp /bin/sh

# View container details
docker inspect todo-api
docker inspect todo-mcp

# View network details
docker network inspect todo-mcp-server_todo-network

# Check container logs with timestamps
docker compose logs -f --timestamps

# Monitor resource usage
docker stats todo-api todo-mcp
```

---

## 🚀 Production Considerations

### Security

**1. Use Non-Root User:**

Update Dockerfiles:

```dockerfile
# Add to Dockerfile.api and Dockerfile.mcp
RUN adduser -D -u 1000 appuser
USER appuser
```

**2. Scan Images for Vulnerabilities:**

```bash
# Using Docker Scout
docker scout cves todo-api:latest
docker scout cves todo-mcp:latest

# Using Trivy
trivy image todo-api:latest
trivy image todo-mcp:latest
```

**3. Use Secrets Management:**

```bash
# Docker secrets (Swarm mode)
echo "my-secret-value" | docker secret create api_key -

# Or use environment files
docker compose --env-file .env.prod up -d
```

**4. Enable TLS/HTTPS:**

Use reverse proxy (Nginx/Traefik) with Let's Encrypt certificates.

### Monitoring

**1. Health Checks:**

Already configured in [`docker-compose.yml`](../docker-compose.yml):

```yaml
healthcheck:
  test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
  interval: 30s
  timeout: 3s
  retries: 3
```

**2. Logging:**

```bash
# Configure log driver
services:
  api:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

**3. Metrics:**

Integrate with Prometheus/Grafana:

```yaml
services:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
```

### High Availability

**1. Docker Swarm:**

```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.prod.yml todo

# Scale services
docker service scale todo_mcp=3
```

**2. Kubernetes:**

Convert to Kubernetes manifests:

```bash
# Using kompose
kompose convert -f docker-compose.prod.yml
kubectl apply -f .
```

### Backup and Recovery

```bash
# Backup container data
docker compose exec api tar czf /tmp/backup.tar.gz /app/data
docker cp todo-api:/tmp/backup.tar.gz ./backup.tar.gz

# Restore data
docker cp ./backup.tar.gz todo-api:/tmp/
docker compose exec api tar xzf /tmp/backup.tar.gz -C /
```

### CI/CD Integration

**GitHub Actions Example:**

```yaml
name: Build and Push Docker Images

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build images
        run: |
          docker build -f Dockerfile.api -t todo-api:${{ github.sha }} .
          docker build -f Dockerfile.mcp -t todo-mcp:${{ github.sha }} .

      - name: Push to registry
        run: |
          echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
          docker push todo-api:${{ github.sha }}
          docker push todo-mcp:${{ github.sha }}
```

---

## 📊 Performance Optimization

### Multi-Stage Builds

Optimize image size:

```dockerfile
# Dockerfile.api (optimized)
FROM python:3.11-slim as builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY src/ ./src/
ENV PATH=/root/.local/bin:$PATH
EXPOSE 8000
CMD ["uvicorn", "src.todo_mcp_server.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Resource Limits

Set appropriate limits in [`docker-compose.prod.yml`](../docker-compose.prod.yml):

```yaml
deploy:
  resources:
    limits:
      cpus: '1.0'
      memory: 512M
    reservations:
      cpus: '0.5'
      memory: 256M
```

---

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Getting Started Guide](./GETTING_STARTED.md)
- [Architecture Documentation](./todo-mcp-server-architecture.md)

---

## ✅ Quick Reference

### Common Commands

```bash
# Start services
docker compose up -d

# Stop services
docker compose down

# View logs
docker compose logs -f

# Rebuild and restart
docker compose up -d --build

# Check status
docker compose ps

# Execute command in container
docker compose exec api /bin/sh

# View resource usage
docker stats

# Clean up
docker compose down -v
docker system prune -a
```

### Port Mapping

| Service | Container Port | Host Port | Purpose |
|---------|---------------|-----------|---------|
| API     | 8000          | 8000      | REST API |
| MCP     | 8080          | 8080      | MCP Server |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | INFO | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `TODO_API_URL` | http://api:8000 | Backend API URL |
| `API_PORT` | 8000 | API port (prod compose) |
| `MCP_PORT` | 8080 | MCP port (prod compose) |

---

Happy containerizing! 🐳
