# GenAI Monorepo

This repository contains multiple projects related to Generative AI exploration and implementation.

## Repository Structure

```
genai/
├── apps/           # Application projects
│   └── secbot/     # GenAI Powered Security Self-Service Chatbot
└── mcp/            # Model Context Protocol (MCP) servers
    └── todo-mcp-server/  # Todo MCP server implementation
```

## Projects

### 🤖 SecBot - Security Self-Service Chatbot

**Location:** [`apps/secbot/`](apps/secbot/)

A proof-of-concept generative AI-powered chatbot designed to enhance security enablement and self-service in enterprise environments. The chatbot leverages specialized security knowledge to educate users on security principles, protocols, and procedures, enabling them to independently manage security configurations through GitOps workflows.

**Key Features:**
- AI-powered security guidance and mentoring
- Integration with GitOps workflows
- Self-service security configuration management
- Enterprise-scale security enablement

[Read more →](apps/secbot/README.md)

### 🔧 MCP Servers

**Location:** [`mcp/`](mcp/)

Model Context Protocol (MCP) server implementations that extend AI capabilities through standardized interfaces.

**Available Servers:**
- **Todo MCP Server** - A reference implementation for task management via MCP

[Explore MCP servers →](mcp/)

## Getting Started

Each project contains its own documentation and setup instructions. Navigate to the respective project directory to get started:

- **SecBot Application:** See [`apps/secbot/README.md`](apps/secbot/README.md)
- **MCP Servers:** See [`mcp/todo-mcp-server/README.md`](mcp/todo-mcp-server/README.md)

## Contributing

This is a personal exploration repository for Generative AI projects. Each project may have different contribution guidelines - please refer to the individual project documentation.

## License

See [LICENSE](LICENSE) file for details.
