# Claude Code Skills Showcase

A demonstration application showcasing mastery of Claude Code Skills through a production-grade implementation combining REST API, Temporal workflows, and MCP integration.

## Features

- **REST API**: FastAPI-based service with workflow management endpoints
- **Temporal Workflows**: Orchestration of long-running, reliable business processes
- **MCP Integration**: Custom Model Context Protocol server for Claude integration
- **Comprehensive Testing**: Unit, integration, and end-to-end tests with >80% coverage
- **CI/CD Pipeline**: Automated testing, linting, and deployment
- **Production-Ready**: Logging, metrics, health checks, and containerization

## Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Git

## Quick Start

### 1. Clone and Setup

```bash
cd apps/claudeskills
cp .env.example .env
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
```

### 2. Start Temporal Server

```bash
docker-compose up -d temporal postgresql
```

Wait for Temporal to be ready (check http://localhost:8233)

### 3. Run the Application

```bash
# Terminal 1: Start the API server
uvicorn claudeskills.api.main:app --reload

# Terminal 2: Start the Temporal worker
python -m claudeskills.worker.main
```

### 4. Access the Application

- API Documentation: http://localhost:8000/docs
- Temporal UI: http://localhost:8233
- Health Check: http://localhost:8000/health

## Development

### Run Tests

```bash
pytest
```

### Run Linting

```bash
ruff check .
mypy claudeskills
```

### Run with Docker

```bash
docker-compose up
```

## Project Structure

```
claudeskills/
├── claudeskills/          # Main application package
│   ├── api/              # FastAPI application
│   ├── workflows/        # Temporal workflows
│   ├── activities/       # Temporal activities
│   ├── mcp/             # MCP server implementation
│   └── core/            # Shared utilities and config
├── tests/               # Test suite
├── docs/                # Documentation
├── docker-compose.yml   # Local development environment
└── requirements.txt     # Python dependencies
```

## Documentation

See [docs/prd.md](docs/prd.md) for the complete Product Requirements Document.

## License

MIT License
