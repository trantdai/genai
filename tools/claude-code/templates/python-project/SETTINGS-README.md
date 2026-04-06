# Claude Settings Configuration for Python Projects

Optimized Claude Code settings for Python development (~1,700 total lines, 28% reduction from baseline).

## Files Overview

- [`settings.json`](settings.json) - Core permissions & restrictions (251 lines)
- [`settings.local.json.example`](settings.local.json.example) - Local override template (33 lines)
- `SETTINGS-README.md` - This documentation

## Quick Start

```bash
# Copy template for local customization
cp .claude/settings.local.json.example .claude/settings.local.json

# Add to .gitignore
echo ".claude/settings.local.json" >> .gitignore
```

**Note**: Most projects work with default `settings.json`. Only customize via `settings.local.json` if needed.

## Security Architecture

### 🔒 Security-First Design

- **Deny by Default**: Restrictive permissions
- **Explicit Allow Lists**: Only approved commands/files accessible
- **Multi-Layer Protection**: File patterns, command restrictions, environment controls
- **No Duplication**: Detailed standards in `.claude/rules/`, not settings

### 🛡️ Permission Model

| Type | Default | Where Defined |
|------|---------|---------------|
| File Operations | Pattern-based | `file_restrictions.editable_patterns` |
| Commands | Allow-list only | `command_restrictions.allowed_commands` |
| Network | Localhost + Python CDNs | `permissions.network_access` |
| Environment | Safe vars only | `environment_variables.allowed_read` |

## Configuration Sections

### 1. Permissions (`permissions`)

Controls core Claude capabilities:

```json
{
  "permissions": {
    "file_operations": {
      "read": true,
      "write": true,
      "create": true,
      "delete": false,      // Disabled for safety
      "execute": false
    },
    "command_execution": {
      "enabled": true,
      "restricted_mode": true,  // Allow-list only
      "timeout_seconds": 300,
      "working_directory_restriction": true
    },
    "network_access": {
      "enabled": true,
      "allow_localhost": true,
      "allow_external": false,  // Block by default
      "allowed_domains": ["pypi.org", "files.pythonhosted.org", "github.com"]
    }
  }
}
```

### 2. Command Restrictions (`command_restrictions`)

**Allowed**: Python tools (python, pip, poetry), testing (pytest), quality (black, ruff, mypy), security (bandit, safety, pip-audit), git, docker, common utils (ls, cat, grep, find)

**Blocked**: Destructive (rm, dd, format), admin (sudo, su, chmod), process control (kill, shutdown), user management (passwd, userdel)

**Dangerous Flags**: `-rf`, `-f`, `--force`, `--delete` automatically blocked

### 3. File Restrictions (`file_restrictions`)

**Editable**: `*.py`, `*.md`, `*.yaml`, `*.json`, `*.toml`, `requirements*.txt`, `pyproject.toml`, `Dockerfile*`

**Read-Only**: `.git/*`, `__pycache__/*`, `*.pyc`, `.pytest_cache/*`, `.venv/*`, `dist/*`, `build/*`

**Forbidden**: `*.env`, `.env.*`, `*.key`, `*.pem`, `*secret*`, `*password*`, `*.sqlite`, `/etc/*`, `/var/*`

### 4. Environment Variables (`environment_variables`)

**Allowed Read**: `PATH`, `PYTHONPATH`, `VIRTUAL_ENV`, `HOME`, `USER`, `CI`, `GITHUB_*`, `PYTEST_*`

**Blocked Read**: `*SECRET*`, `*PASSWORD*`, `*KEY*`, `*TOKEN*`, `AWS_*`, `AZURE_*`, `GCP_*`, `DATABASE_URL`

## Development Standards

**All detailed standards are in `.claude/rules/`, NOT in settings.json:**

- **Code Style**: [python-code-style.md](.claude/rules/python-code-style.md) - Type hints, PEP 8, 100-char lines, complexity limits
- **Testing**: [python-testing.md](.claude/rules/python-testing.md) - pytest, 80%+ coverage, AAA pattern, fixtures
- **Security**: [python-security.md](.claude/rules/python-security.md) - Input validation, bcrypt, secrets management, OWASP
- **Async**: [python-async.md](.claude/rules/python-async.md) - asyncio patterns, connection pooling, rate limiting
- **Performance**: [python-performance.md](.claude/rules/python-performance.md) - Data structures, profiling, caching

**Why separate?** Keeps settings.json focused on permissions/restrictions. Prevents duplication. Easier to maintain.

## Local Customization

### Creating settings.local.json

```bash
cp .claude/settings.local.json.example .claude/settings.local.json
```

### Common Overrides

**Increase Limits:**
```json
{
  "permissions": {
    "command_execution": {
      "timeout_seconds": 600
    }
  },
  "file_restrictions": {
    "max_file_size_mb": 25
  }
}
```

**Add Custom Commands:**
```json
{
  "command_restrictions": {
    "allowed_commands": ["jupyter", "ipython", "conda", "npm"]
  }
}
```

**Add Private Registries:**
```json
{
  "permissions": {
    "network_access": {
      "allow_external": true,
      "allowed_domains": ["your-registry.com", "internal.company.com"]
    }
  }
}
```

**Custom Project Structure:**
```json
{
  "project_structure": {
    "test_directory": "test",
    "docs_directory": "documentation"
  }
}
```

## Troubleshooting

**Claude Can't Edit Files**
→ Add patterns to `file_restrictions.editable_patterns`

**Command Not Allowed**
→ Add to `command_restrictions.allowed_commands`

**Network Access Blocked**
→ Add domains to `permissions.network_access.allowed_domains`

**Debug Mode:**
```json
{
  "logging": {
    "level": "DEBUG"
  }
}
```

## File Precedence

Settings load order (later overrides earlier):

1. `.claude/settings.json` (base)
2. `.claude/settings.local.json` (user overrides)

## Best Practices

### ✅ Do
- Keep `settings.json` in version control
- Gitignore `settings.local.json`
- Use minimum necessary permissions
- Review allowed commands regularly

### ❌ Don't
- Never commit `settings.local.json`
- Don't disable security features
- Don't store secrets in settings files
- Don't allow dangerous commands

---

**Related Documentation:**
- [CLAUDE.md](CLAUDE.md) - Quick reference guide
- [README.md](README.md) - Template overview
- [.claude/rules/](.claude/rules/) - Development standards
