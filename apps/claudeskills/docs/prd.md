# Claude Code Skills Showcase - Product Requirements Document

## 1. Project Overview

### 1.1 Purpose
Build a demonstration application that showcases mastery of Claude Code Skills through a real-world implementation. The application serves as both a learning exercise and a portfolio piece demonstrating proficiency in modern software development practices with AI assistance.

### 1.2 Goals
- **Primary Goal**: Learn and master Claude Code Skills by building a production-grade application
- **Secondary Goal**: Create a reusable reference implementation for REST API + Temporal Workflow patterns
- **Tertiary Goal**: Demonstrate best practices in testing, CI/CD, and architectural design

### 1.3 Scope
The application will consist of:
- **REST API Frontend**: FastAPI-based service handling HTTP requests
- **Temporal Workflow Backend**: Orchestrating long-running, reliable business processes
- **MCP Integration**: Custom Model Context Protocol server for extending Claude's capabilities
- **Comprehensive Testing**: Unit, integration, and end-to-end tests
- **CI/CD Pipeline**: Automated testing, linting, and deployment
- **Documentation**: Architecture diagrams, API documentation, deployment guides

## 2. Target Audience

### 2.1 Primary Users
- Developers learning Claude Code Skills
- Teams evaluating Temporal for workflow orchestration
- Engineers studying modern Python API architecture patterns

### 2.2 Use Cases
1. **Learning Reference**: Study how to structure a multi-tier Python application
2. **Template Project**: Fork and adapt for similar REST API + workflow projects
3. **Skills Demonstration**: Portfolio piece showing comprehensive development capabilities

## 3. Functional Requirements

### 3.1 REST API Layer (FastAPI)
- **REQ-API-001**: Expose RESTful endpoints for workflow management
  - `POST /workflows` - Create and start a new workflow
  - `GET /workflows/{id}` - Get workflow status and results
  - `GET /workflows` - List all workflows with filtering/pagination
  - `DELETE /workflows/{id}` - Cancel a running workflow

- **REQ-API-002**: Provide health check and metrics endpoints
  - `GET /health` - Service health status
  - `GET /metrics` - Prometheus-compatible metrics

- **REQ-API-003**: Support API documentation
  - Auto-generated OpenAPI/Swagger documentation
  - Interactive API explorer

### 3.2 Temporal Workflow Backend
- **REQ-WF-001**: Implement sample workflows demonstrating key patterns
  - Long-running data processing workflow (minutes to hours)
  - Multi-step approval workflow with human-in-the-loop
  - Saga pattern for distributed transactions

- **REQ-WF-002**: Implement workflow activities
  - Data validation activities
  - External API integration activities
  - Notification activities

- **REQ-WF-003**: Support workflow monitoring
  - Query workflow state via Temporal APIs
  - Handle workflow timeouts and retries
  - Track workflow history and execution logs

### 3.3 MCP Server Integration
- **REQ-MCP-001**: Create custom MCP server exposing workflow tools
  - `create_workflow` - Start a new workflow from Claude
  - `get_workflow_status` - Query workflow state
  - `list_workflows` - Browse active workflows
  - `cancel_workflow` - Stop a running workflow

- **REQ-MCP-002**: Integrate with existing MCP infrastructure
  - Follow patterns from todo-mcp-server reference implementation
  - Support both stdio and HTTP transports
  - Include proper tool schemas and descriptions

### 3.4 Testing & Quality Assurance
- **REQ-TEST-001**: Unit tests with >80% code coverage
  - Test all API endpoints
  - Test workflow logic in isolation
  - Test utility functions and helpers

- **REQ-TEST-002**: Integration tests
  - Test API → Temporal integration
  - Test MCP → API integration
  - Test end-to-end workflows

- **REQ-TEST-003**: Code quality checks
  - Linting with flake8/ruff
  - Type checking with mypy
  - Security scanning with bandit

### 3.5 CI/CD Pipeline
- **REQ-CICD-001**: Automated testing on pull requests
  - Run all tests on PR creation
  - Block merge if tests fail
  - Report coverage metrics

- **REQ-CICD-002**: Automated deployment
  - Deploy to staging on merge to main
  - Manual approval for production deployment
  - Rollback capability

## 4. Non-Functional Requirements

### 4.1 Performance
- **NFR-PERF-001**: API response time <200ms for status queries
- **NFR-PERF-002**: Support 100 concurrent workflow executions
- **NFR-PERF-003**: Handle 1000 requests/minute on API layer

### 4.2 Reliability
- **NFR-REL-001**: 99.9% uptime for API service
- **NFR-REL-002**: Workflow state persistence survives service restarts
- **NFR-REL-003**: Automatic retry for transient failures

### 4.3 Scalability
- **NFR-SCALE-001**: Horizontal scaling for API workers
- **NFR-SCALE-002**: Temporal cluster supports multiple workers
- **NFR-SCALE-003**: Stateless API design for load balancing

### 4.4 Security
- **NFR-SEC-001**: API authentication via JWT tokens
- **NFR-SEC-002**: Input validation on all endpoints
- **NFR-SEC-003**: Rate limiting to prevent abuse
- **NFR-SEC-004**: Secrets management via environment variables

### 4.5 Observability
- **NFR-OBS-001**: Structured logging (JSON format)
- **NFR-OBS-002**: Distributed tracing for request flows
- **NFR-OBS-003**: Metrics for monitoring (Prometheus format)
- **NFR-OBS-004**: Health checks for service dependencies

## 5. Technical Stack

### 5.1 Core Technologies
- **Language**: Python 3.11+
- **API Framework**: FastAPI 0.109+
- **Workflow Engine**: Temporal 1.5+
- **MCP Framework**: FastMCP (following todo-mcp-server pattern)

### 5.2 Supporting Technologies
- **Database**: PostgreSQL (for Temporal state) or in-memory for demo
- **Testing**: pytest, pytest-asyncio, pytest-cov
- **Linting**: ruff, mypy
- **Documentation**: Sphinx, OpenAPI/Swagger
- **Containerization**: Docker, Docker Compose
- **CI/CD**: GitHub Actions

### 5.3 Development Tools
- **Package Management**: pip + requirements.txt (or Poetry)
- **Version Control**: Git + GitHub
- **IDE**: VS Code with Python extensions
- **Local Development**: Docker Compose for Temporal server

## 6. System Architecture (High-Level)

```
┌─────────────────────────────────────────────────────────────┐
│                        Client Layer                          │
│  (HTTP Clients, Claude via MCP, Web UI, CLI)                │
└───────────────────┬─────────────────────────────────────────┘
                    │
                    │ HTTP/REST
                    │
┌───────────────────▼─────────────────────────────────────────┐
│                   REST API Layer (FastAPI)                   │
│  • Workflow Management Endpoints                            │
│  • Health & Metrics                                         │
│  • Authentication & Validation                              │
└───────────────────┬─────────────────────────────────────────┘
                    │
                    │ Temporal Client
                    │
┌───────────────────▼─────────────────────────────────────────┐
│              Temporal Workflow Engine                        │
│  • Workflow Orchestration                                   │
│  • State Persistence                                        │
│  • Retry Logic                                              │
│  • Activity Execution                                       │
└───────────────────┬─────────────────────────────────────────┘
                    │
                    │ Activity Workers
                    │
┌───────────────────▼─────────────────────────────────────────┐
│                  Activity Layer                              │
│  • Data Processing Activities                               │
│  • External API Integration                                 │
│  • Notification Services                                    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   MCP Server (Parallel)                     │
│  • Claude Integration Tools                                 │
│  • Workflow Management via MCP Protocol                     │
└─────────────────────────────────────────────────────────────┘
```

## 7. Success Criteria

### 7.1 Learning Objectives Met
- ✅ Demonstrate proficiency with Claude Code Skills
- ✅ Understand REST API design with FastAPI
- ✅ Master Temporal workflow patterns
- ✅ Implement custom MCP server
- ✅ Set up comprehensive testing and CI/CD

### 7.2 Technical Achievements
- ✅ All functional requirements implemented
- ✅ >80% test coverage
- ✅ Passing CI/CD pipeline
- ✅ Complete documentation
- ✅ Docker containerization working

### 7.3 Code Quality
- ✅ Type hints throughout codebase
- ✅ Clean, readable code following Python best practices
- ✅ No critical security vulnerabilities
- ✅ Performance requirements met

## 8. Project Phases

### Phase 1: Foundation (Week 1)
- Set up project structure
- Configure development environment
- Implement basic REST API skeleton
- Set up Temporal development environment

### Phase 2: Core Implementation (Week 2-3)
- Implement REST API endpoints
- Create sample Temporal workflows
- Build activity implementations
- Integrate API with Temporal

### Phase 3: MCP Integration (Week 4)
- Develop custom MCP server
- Implement workflow management tools
- Test MCP integration with Claude

### Phase 4: Testing & Quality (Week 5)
- Write comprehensive unit tests
- Add integration tests
- Set up code quality checks
- Achieve coverage targets

### Phase 5: CI/CD & Documentation (Week 6)
- Configure GitHub Actions
- Write documentation
- Create deployment guides
- Dockerize application

### Phase 6: Polish & Demo (Week 7)
- Performance optimization
- Bug fixes
- Demo preparation
- Final documentation review

## 9. Out of Scope

The following are explicitly out of scope for this project:
- Production-grade database setup (will use simple in-memory or local PostgreSQL)
- Authentication/authorization system (simplified auth for demo)
- Frontend UI (API-first approach, UI optional)
- Multi-tenancy support
- Advanced monitoring dashboards (basic metrics only)

## 10. Dependencies & Assumptions

### 10.1 Dependencies
- Temporal server (local Docker instance)
- Python 3.11+ runtime
- Docker for containerization
- GitHub for source control and CI/CD

### 10.2 Assumptions
- Developer has basic Python knowledge
- Local development environment (macOS/Linux)
- Access to Docker
- GitHub account with Actions enabled

## 11. Risks & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Temporal learning curve steep | High | Medium | Start with simple workflows, use official tutorials |
| MCP integration complexity | Medium | Medium | Reference todo-mcp-server implementation |
| CI/CD configuration issues | Low | Low | Use existing patterns from secbot |
| Scope creep | Medium | High | Stick to defined requirements, defer enhancements |

## 12. References

- [Temporal Documentation](https://docs.temporal.io/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [todo-mcp-server Reference](../../mcp/todo-mcp-server/)
- [secbot Reference](../../secbot/)

---

**Document Version**: 1.0
**Last Updated**: 2026-02-23
**Status**: Approved for Implementation
