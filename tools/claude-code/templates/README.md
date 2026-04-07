# Claude Code Templates

Reusable configuration templates for Claude Code AI-assisted development, providing standardized project structures, development rules, and workflow automation.

## Overview

This directory contains templates that configure Claude Code's behavior for different project types. Templates include development standards, security guidelines, testing practices, and automation hooks to ensure consistent, high-quality code generation.

## Contents

### Global Configuration

- **[`CLAUDE.md`](./CLAUDE.md)** - Global workflow orchestration rules shared by Anthropic
  - Task management and granularity guidelines
  - Subagent orchestration strategies
  - Self-improvement and verification workflows
  - **Installation**: Copy to `~/.claude/CLAUDE.md` for global application

### Project Templates

#### Python Project Template

**Location**: [`python-project/`](./python-project/)

Comprehensive Python project template with modern tooling and best practices.

**Features**:
- Modern Python 3.13+ with src-layout structure
- Type-safe development (mypy strict mode)
- Comprehensive testing (pytest, 80%+ coverage)
- Security-first approach (Pydantic validation, secrets management)
- Async I/O patterns (asyncio, asyncpg, httpx)

**Configuration Structure** (~1,700 lines):
```
python-project/.claude/
├── settings.json                 # Core permissions & restrictions
├── settings.local.json.example   # Local override template
├── agents/                       # Specialized AI agent definitions
├── hooks/                        # Git hooks and automation
├── rules/                        # Development standards
│   ├── python-code-style.md     # PEP 8, type hints, formatting
│   ├── python-testing.md        # pytest, coverage, fixtures
│   ├── python-security.md       # Input validation, auth, secrets
│   └── ...                      # Additional standards
└── skills/                       # Reusable task templates
```

**Documentation**:
- [`python-project/README.md`](./python-project/README.md) - Complete template documentation
- [`python-project/SETTINGS-README.md`](./python-project/SETTINGS-README.md) - Settings configuration guide
- [`python-project/CLAUDE.md`](./python-project/CLAUDE.md) - Project-specific Claude instructions
- [`python-project/CLAUDE.local.md`](./python-project/CLAUDE.local.md) - Local customization example

#### Future Templates

- **TypeScript Project** - Planned for future release

## Quick Start

### 1. Install Global Configuration

Copy the global configuration to your home directory:

```bash
# Create Claude config directory if it doesn't exist
mkdir -p ~/.claude

# Copy global configuration
cp tools/claude-code/templates/CLAUDE.md ~/.claude/CLAUDE.md
```

### 2. Set Up Project Template

Copy the appropriate template to your project root:

**For Python projects**:
```bash
# Navigate to your project root
cd /path/to/your/project

# Copy Python template configuration
cp -r /path/to/genai/tools/claude-code/templates/python-project/.claude .

# Copy local customization template
cp /path/to/genai/tools/claude-code/templates/python-project/CLAUDE.local.md .
```

**For CLAUDE.md, choose one approach**:

**Option A: Copy Template (Comprehensive Baseline)**
```bash
# Use template CLAUDE.md as-is or as starting point
cp /path/to/genai/tools/claude-code/templates/python-project/CLAUDE.md .
```

**Option B: Generate Project-Specific (Focused & Minimal)**
```bash
# After copying .claude/, use Claude Code's 'init' command
# to analyze your codebase and generate AGENTS.md/CLAUDE.md
# with only non-obvious, project-specific guidance
```

**Option C: Hybrid Approach (Recommended)**
```bash
# 1. Copy template as baseline
cp /path/to/genai/tools/claude-code/templates/python-project/CLAUDE.md .

# 2. Run 'init' command to analyze your specific codebase
# Claude will enhance CLAUDE.md with project-specific discoveries

# 3. Result: Comprehensive template + project-specific insights
```

**Choosing the Right Approach**:

| Approach | Best For | Pros | Cons |
|----------|----------|------|------|
| **Option A: Copy Template** | New projects, standard patterns | Comprehensive guidance, all best practices documented | May include obvious information |
| **Option B: Generate with 'init'** | Existing codebases, unique patterns | Minimal, focused on non-obvious discoveries | Requires manual codebase analysis |
| **Option C: Hybrid** | Most projects | Best of both worlds: comprehensive + specific | Requires both steps |

**Recommendation**: Use **Option C (Hybrid)** for most projects. The template provides comprehensive Python best practices, while the 'init' command adds project-specific insights that aren't obvious from standard patterns.

### 3. Customize for Your Project

1. **Review settings**: Edit `.claude/settings.json` to adjust permissions and restrictions
2. **Local overrides**: Copy `.claude/settings.local.json.example` to `.claude/settings.local.json` and customize
3. **Project context**: Update `CLAUDE.md` with project-specific information
4. **Local notes**: Use `CLAUDE.local.md` for personal development notes (git-ignored)

## Template Components

### Settings Files

- **`settings.json`**: Core configuration for Claude Code behavior
  - File operation permissions
  - Command execution restrictions
  - Mode-specific file access patterns
  - Security boundaries

- **`settings.local.json`**: Local overrides (git-ignored)
  - Personal preferences
  - Machine-specific paths
  - Development environment customizations

### Agents

Specialized AI agent definitions for focused tasks:
- Code generation agents
- Testing agents
- Documentation agents
- Security review agents

### Hooks

Automation scripts triggered by development events:
- Pre-commit validation
- Post-commit actions
- Pre-push checks
- Custom workflow triggers

### Rules

Development standards and best practices:
- Code style guidelines
- Testing requirements
- Security standards
- Documentation practices
- Performance optimization
- Error handling patterns

### Skills

Reusable task templates for common operations:
- Project scaffolding
- API endpoint creation
- Database migration generation
- Test suite setup
- Documentation generation

## Usage Guidelines

### When to Use Templates

✅ **Use templates when**:
- Starting a new project
- Standardizing existing project configuration
- Onboarding team members to AI-assisted development
- Enforcing consistent development practices
- Implementing security and quality standards

### Customization Best Practices

1. **Start with defaults**: Use template as-is initially to understand the patterns
2. **Incremental changes**: Customize gradually based on project needs
3. **Document changes**: Note customizations in `CLAUDE.local.md`
4. **Share improvements**: Contribute useful patterns back to templates
5. **Version control**: Commit `.claude/` directory (except `settings.local.json`)

### Template Maintenance

- **Keep updated**: Periodically sync with latest template versions
- **Review rules**: Ensure rules align with current project practices
- **Prune unused**: Remove agents/skills not relevant to your project
- **Add project-specific**: Create custom rules for unique requirements

## Configuration Hierarchy

Claude Code loads configuration in this order (later overrides earlier):

1. **Global**: `~/.claude/CLAUDE.md` - Universal workflow rules
2. **Project**: `.claude/settings.json` - Project-wide configuration
3. **Local**: `.claude/settings.local.json` - Personal overrides
4. **Context**: `CLAUDE.md` - Project-specific instructions
5. **Session**: `CLAUDE.local.md` - Temporary development notes

## Examples

### Example 1: New Python API Project

```bash
# Create project structure
mkdir my-api && cd my-api
git init

# Copy Python template
cp -r ~/genai/tools/claude-code/templates/python-project/.claude .
cp ~/genai/tools/claude-code/templates/python-project/CLAUDE.md .

# Customize for API development
# Edit .claude/settings.json to enable API-specific rules
# Add API documentation requirements to CLAUDE.md

# Start development with Claude Code
# Claude will now follow Python best practices and API standards
```

### Example 2: Existing Project Standardization

```bash
# Navigate to existing project
cd existing-project

# Backup current configuration
mv .claude .claude.backup 2>/dev/null || true

# Copy template
cp -r ~/genai/tools/claude-code/templates/python-project/.claude .

# Merge custom rules from backup
# Review and integrate project-specific rules

# Test with Claude Code
# Verify Claude follows new standards
```

## Troubleshooting

### Claude Not Following Rules

1. **Check file locations**: Ensure `.claude/` is in project root
2. **Verify syntax**: Validate JSON in `settings.json`
3. **Review hierarchy**: Check if local settings override project settings
4. **Restart Claude**: Reload configuration by restarting Claude Code

### Permission Errors

1. **Review settings.json**: Check `allowedOperations` and `restrictedPaths`
2. **Check file patterns**: Ensure file patterns match your project structure
3. **Local overrides**: Use `settings.local.json` for development exceptions

### Template Conflicts

1. **Identify conflicts**: Check which rules are conflicting
2. **Prioritize**: Decide which standard takes precedence
3. **Document exceptions**: Note deviations in `CLAUDE.local.md`
4. **Update templates**: Contribute fixes for common conflicts

## Contributing

Improvements to templates are welcome:

1. **Test thoroughly**: Verify changes across multiple projects
2. **Document rationale**: Explain why changes improve the template
3. **Maintain compatibility**: Ensure changes don't break existing projects
4. **Follow standards**: Adhere to documentation standards in templates
5. **Submit PR**: Include examples demonstrating improvements

## Related Documentation

- [Python Project Template README](./python-project/README.md) - Detailed Python template documentation
- [Settings Configuration Guide](./python-project/SETTINGS-README.md) - Settings file reference
- [Roo Code Templates](../roo-code/templates/) - Alternative template system

## Support

For issues or questions:
- Review template documentation in respective directories
- Check Claude Code documentation
- Examine example projects using templates
- Consult project-specific `CLAUDE.md` files

## License

See [LICENSE](../../../LICENSE) in repository root.
