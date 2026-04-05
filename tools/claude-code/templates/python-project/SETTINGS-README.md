# Claude Settings Configuration for Python Projects

This directory contains comprehensive Claude Code settings configurations optimized for Python development with a security-first approach.

## Files Overview

- [`settings.json`](settings.json) - Production-ready settings (committed to repo)
- [`settings.local.json.example`](settings.local.json.example) - Template for personal overrides (gitignored)
- `SETTINGS-README.md` - This documentation file

## Quick Start

1. **Use Production Settings**: The [`settings.json`](settings.json) file works out-of-the-box for most Python projects
2. **Create Local Overrides**: Copy [`settings.local.json.example`](settings.local.json.example) to `settings.local.json` and customize
3. **Add to `.gitignore`**: Ensure `settings.local.json` is gitignored to protect sensitive data

```bash
# Copy template for local customization
cp settings.local.json.example settings.local.json

# Add to .gitignore if not already present
echo "settings.local.json" >> .gitignore
```

## Security Architecture

### 🔒 Security-First Design

- **Deny by Default**: All permissions start as restricted
- **Explicit Allow Lists**: Only specifically approved commands and files are accessible
- **Multi-Layer Protection**: File patterns, command restrictions, and environment controls
- **Secret Detection**: Automatic scanning for exposed credentials
- **Audit Logging**: All operations are logged for security review

### 🛡️ Permission Model

| Permission Type | Default | Override Location |
|---|---|---|
| File Operations | Limited patterns only | `file_restrictions.editable_patterns` |
| Command Execution | Approved commands only | `command_restrictions.allowed_commands` |
| Network Access | Localhost + approved domains | `permissions.network_access` |
| Environment Variables | Safe variables only | `environment_variables.allowed_read` |

## Configuration Sections

### 1. Permissions (`permissions`)

Controls core Claude capabilities with security boundaries.

```json
{
  "permissions": {
    "file_operations": {
      "read": true,          // Allow reading files
      "write": true,         // Allow editing files (restricted by patterns)
      "create": true,        // Allow creating new files
      "delete": false,       // Prevent file deletion (security)
      "execute": false       // Prevent direct file execution
    },
    "command_execution": {
      "enabled": true,                    // Enable command execution
      "restricted_mode": true,            // Use allow-list approach
      "timeout_seconds": 300,             // 5-minute timeout
      "working_directory_restriction": true // Restrict to project directory
    },
    "network_access": {
      "enabled": true,        // Enable network operations
      "allow_localhost": true, // Allow local development servers
      "allow_external": false, // Block external domains by default
      "allowed_domains": [     // Approved external domains
        "pypi.org",
        "github.com"
      ]
    }
  }
}
```

**Key Security Features**:
- File deletion disabled by default
- Command execution uses allow-list only
- Network access restricted to essential domains
- Working directory restrictions prevent path traversal

### 2. Command Restrictions (`command_restrictions`)

Defines which commands Claude can execute with explicit allow and block lists.

#### Allowed Commands
- **Python Tools**: `python`, `pip`, `poetry`, `pipenv`
- **Testing**: `pytest`, `coverage`
- **Code Quality**: `black`, `ruff`, `mypy`, `bandit`, `safety`
- **Version Control**: `git`
- **Containers**: `docker`, `docker-compose`
- **System Utils**: `ls`, `cat`, `grep`, `find`, `mkdir`, `touch`

#### Blocked Commands
- **Destructive**: `rm`, `dd`, `format`, `fdisk`
- **System Admin**: `sudo`, `su`, `chmod`, `chown`
- **Process Control**: `kill`, `shutdown`, `reboot`
- **User Management**: `passwd`, `userdel`, `usermod`

#### Dangerous Flags
Automatically blocked dangerous command flags:
- `-rf`, `-f`, `--force`, `--delete`, `--remove`, `--recursive`

### 3. File Restrictions (`file_restrictions`)

Controls which files Claude can read, edit, or access using pattern matching.

#### Editable Patterns ✅
```
*.py, *.pyi, *.pyx          # Python source files
*.md, *.rst, *.txt          # Documentation
*.yaml, *.yml, *.json       # Configuration files
requirements*.txt           # Dependency files
pyproject.toml, setup.py    # Project configuration
Dockerfile*, docker-compose* # Container definitions
```

#### Read-Only Patterns 👁️
```
.git/*, __pycache__/*       # Version control and cache
*.pyc, *.pyo, *.pyd        # Compiled Python
.pytest_cache/*, .coverage  # Test artifacts
dist/*, build/*            # Build outputs
.venv/*, venv/*, env/*     # Virtual environments
```

#### Forbidden Patterns ❌
```
*.env, .env.local          # Environment files with secrets
*.key, *.pem, *.p12        # Cryptographic keys
*secret*, *password*       # Files containing secrets
*.sqlite, *.db            # Database files
/etc/*, /var/*, /usr/*     # System directories
```

### 4. Environment Variables (`environment_variables`)

Controls access to environment variables with security considerations.

#### Allowed Read Variables
- **Development**: `PATH`, `PYTHONPATH`, `VIRTUAL_ENV`
- **System Info**: `HOME`, `USER`, `PWD`, `SHELL`
- **CI/CD**: `CI`, `GITHUB_*`
- **Testing**: `PYTEST_*`, `COVERAGE_*`

#### Blocked Read Variables
- **Secrets**: `*SECRET*`, `*PASSWORD*`, `*KEY*`, `*TOKEN*`
- **Cloud Credentials**: `AWS_*`, `AZURE_*`, `GCP_*`
- **Database**: `DATABASE_URL`, `DB_*`

### 5. Hooks Configuration (`hooks`)

References to hook scripts for automated workflows.

#### Available Hooks
- **pre_command**: Executed before command runs
- **post_command**: Executed after command completes
- **file_change**: Triggered on file modifications
- **security_scan**: Runs security checks

Hook scripts location: `.claude/hooks/`

### 6. MCP Servers (`mcp_servers`)

Model Context Protocol server configurations for enhanced capabilities.

#### Built-in Servers
- **filesystem**: Safe file system operations
- **git**: Version control integration
- **python_analyzer**: AST analysis and type checking
- **testing**: Test execution and coverage
- **security_scanner**: Vulnerability scanning
- **documentation**: Documentation generation

### 7. Custom Tools (`custom_tools`)

Python-specific development tools with predefined configurations.

#### Available Tools
- **python_formatter**: Black code formatting
- **python_linter**: Ruff linting with auto-fix
- **type_checker**: MyPy static type checking
- **security_scanner**: Bandit security analysis
- **dependency_checker**: Safety vulnerability scanning
- **test_runner**: Pytest with coverage
- **coverage_reporter**: Coverage report generation

### 8. Code Analysis (`code_analysis`)

Automated code quality and complexity analysis.

#### Analysis Features
- **AST Parsing**: Abstract syntax tree analysis
- **Complexity Analysis**: Cyclomatic complexity measurement
- **Dependency Tracking**: Import and dependency analysis
- **Function/Class Analysis**: Structure and metrics

#### Quality Thresholds
```json
{
  "thresholds": {
    "max_complexity": 15,      // Cyclomatic complexity limit
    "max_function_length": 50, // Lines per function
    "max_class_methods": 20,   // Methods per class
    "max_file_length": 1000    // Lines per file
  }
}
```

### 9. Testing Configuration (`testing`)

Comprehensive testing setup with coverage requirements.

#### Features
- **Framework**: Pytest (industry standard)
- **Auto Discovery**: Automatic test detection
- **Coverage**: 80% minimum threshold
- **Parallel Execution**: Multi-threaded test runs
- **Pattern Matching**: Flexible test file patterns

### 10. Security Features (`security`)

Multi-layered security scanning and protection.

#### Security Tools
- **Bandit**: Python security linting
- **Safety**: Dependency vulnerability scanning
- **Semgrep**: Static analysis security testing

#### Secret Detection
Automatic detection of exposed secrets using regex patterns:
```
- API keys and tokens (20+ characters)
- AWS credentials
- GitHub tokens
- Database URLs
```

## Local Customization

### Creating settings.local.json

Copy the example template and customize for your environment:

```bash
cp settings.local.json.example settings.local.json
```

### Common Overrides

#### Increase Development Limits
```json
{
  "file_restrictions": {
    "max_file_size_mb": 50
  },
  "performance": {
    "max_concurrent_tasks": 8,
    "memory_limit_mb": 2048
  }
}
```

#### Enable Auto-Formatting
```json
{
  "auto_formatting": {
    "enabled": true,
    "on_save": true,
    "tools": ["black", "ruff --fix"]
  }
}
```

#### Add Custom Commands
```json
{
  "command_restrictions": {
    "allowed_commands": [
      "jupyter",
      "ipython",
      "conda",
      "your-custom-tool"
    ]
  }
}
```

#### Relax Security for Development
```json
{
  "security": {
    "scan_on_change": false
  },
  "testing": {
    "coverage_threshold": 60
  }
}
```

## Integration Examples

### FastAPI Projects
```json
{
  "custom_tools": {
    "api_server": {
      "command": "uvicorn",
      "args": ["main:app", "--reload", "--host", "0.0.0.0"],
      "auto_run": false
    }
  }
}
```

### Data Science Projects
```json
{
  "command_restrictions": {
    "allowed_commands": [
      "jupyter", "ipython", "pandas-profiling"
    ]
  },
  "file_restrictions": {
    "editable_patterns": [
      "*.ipynb", "*.csv", "*.parquet"
    ]
  }
}
```

### Django Projects
```json
{
  "custom_tools": {
    "django_server": {
      "command": "python",
      "args": ["manage.py", "runserver"],
      "auto_run": false
    },
    "django_migrate": {
      "command": "python",
      "args": ["manage.py", "migrate"],
      "auto_run": false
    }
  }
}
```

## Security Best Practices

### ✅ Do's
- Keep [`settings.json`](settings.json) in version control
- Gitignore `settings.local.json`
- Review allowed commands regularly
- Use minimum necessary permissions
- Enable security scanning
- Set appropriate file size limits
- Use explicit allow-lists over deny-lists

### ❌ Don'ts
- Never commit `settings.local.json`
- Don't disable security features in production
- Avoid overly permissive file patterns
- Don't store secrets in settings files
- Don't allow dangerous commands
- Don't ignore security scan results

## Troubleshooting

### Common Issues

#### Claude Can't Edit Files
**Problem**: "Permission denied" or "File not editable"
**Solution**: Add file patterns to `file_restrictions.editable_patterns`

#### Command Not Found
**Problem**: "Command 'xyz' is not allowed"
**Solution**: Add command to `command_restrictions.allowed_commands`

#### Network Access Blocked
**Problem**: Cannot download packages or access APIs
**Solution**: Add domains to `permissions.network_access.allowed_domains`

#### Tests Not Running
**Problem**: Test discovery fails
**Solution**: Update `testing.test_patterns` with correct patterns

#### Performance Issues
**Problem**: Claude operations are slow
**Solution**: Increase limits in `performance` section

### Debug Mode

Enable verbose logging for troubleshooting:

```json
{
  "logging": {
    "level": "DEBUG",
    "verbose_mode": true
  }
}
```

## File Precedence

Settings are loaded in this order (later files override earlier ones):

1. [`settings.json`](settings.json) (base configuration)
2. `settings.local.json` (user overrides)
3. Environment variables (if supported)
4. Command-line arguments (if supported)

## Schema Validation

Both settings files must conform to the Claude settings schema. Invalid JSON or unknown properties will cause errors.

### Validation Tools

```bash
# Validate JSON syntax
python -m json.tool settings.json

# Check with Claude (if available)
claude validate-settings settings.json
```

## Migration Guide

### From Previous Versions

If upgrading from older Claude settings:

1. **Backup Current Settings**: Save existing `settings.json`
2. **Review Breaking Changes**: Check changelog for removed properties
3. **Merge Custom Settings**: Transfer customizations to new format
4. **Test Thoroughly**: Validate all workflows work correctly

### Version Compatibility

| Settings Version | Claude Version | Status |
|---|---|---|
| 1.0 | Latest | ✅ Current |
| 0.9 | Legacy | ⚠️ Deprecated |
| 0.8 | Legacy | ❌ Unsupported |

## Advanced Configuration

### Custom MCP Server

```json
{
  "mcp_servers": {
    "custom_analyzer": {
      "enabled": true,
      "config": {
        "server_path": "./custom_mcp_server.py",
        "capabilities": ["analysis", "refactoring"],
        "timeout": 60
      }
    }
  }
}
```

### Hook Scripts

Create custom hooks in `.claude/hooks/`:

```python
# .claude/hooks/pre-command.py
def pre_command_hook(command, args, context):
    """Executed before every command"""
    if command == "pytest":
        print("Running tests with coverage...")
    return True  # Allow command to proceed
```

### Environment-Specific Settings

Use different settings per environment:

```bash
# Development
ln -sf settings.dev.json settings.local.json

# Production
ln -sf settings.prod.json settings.local.json

# Testing
ln -sf settings.test.json settings.local.json
```

## Support and Contributing

### Getting Help
- Check this documentation first
- Review [`settings.json`](settings.json) comments
- Consult Claude documentation
- Open GitHub issues for bugs

### Contributing Improvements
- Follow security-first principles
- Add comprehensive documentation
- Test with multiple Python projects
- Submit pull requests with examples

---

**📚 Related Documentation**
- [Python Development Standards](../../../.roo/rules/02-python-standards.md)
- [Security Standards](../../../.roo/rules/07-security-standards.md)
- [Testing Standards](../../../.roo/rules/README.md)

**🔗 Quick Links**
- [`settings.json`](settings.json) - Main configuration
- [`settings.local.json.example`](settings.local.json.example) - Local template
- [Python Base Component](README.md) - Component overview
