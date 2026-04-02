# Roo Code Templates

This directory contains template files for setting up Roo Code (AI-powered coding assistant) in your projects. These templates provide standardized rules, configurations, and best practices to ensure consistent, high-quality AI-assisted development.

## 📁 Contents

### `.roo/` Directory
The `.roo/` directory contains all Roo Code configuration files, including rules for different modes and development standards.

#### Core Rules (`rules/`)
Universal rules that apply across all modes:

- [`00-critical-core.md`](.roo/rules/00-critical-core.md) - Essential principles for all modes (task splitting, security, quality standards)
- [`01-pr-reviews.md`](.roo/rules/01-pr-reviews.md) - Pull request review standards and guidelines
- [`09-documentation-standards.md`](.roo/rules/09-documentation-standards.md) - Documentation organization and writing standards
- [`10-commit-standards.md`](.roo/rules/10-commit-standards.md) - Conventional commit message format and best practices
- [`11-task-management.md`](.roo/rules/11-task-management.md) - Task splitting, error prevention, and execution guidelines
- [`12-collaborative-planning.md`](.roo/rules/12-collaborative-planning.md) - Planning workflow and approval process

#### Mode-Specific Rules

**Code Mode** (`rules-code/`)
- [`python-standards.md`](.roo/rules-code/python-standards.md) - Python coding standards, testing, and best practices
- [`typescript-standards.md`](.roo/rules-code/typescript-standards.md) - TypeScript/JavaScript standards and patterns
- [`task-execution.md`](.roo/rules-code/task-execution.md) - Code mode task execution guidelines

**DevOps Mode** (`rules-devops/`)
- [`cicd-standards.md`](.roo/rules-devops/cicd-standards.md) - CI/CD pipeline standards and best practices
- [`docker-standards.md`](.roo/rules-devops/docker-standards.md) - Docker and containerization guidelines
- [`iac-standards.md`](.roo/rules-devops/iac-standards.md) - Infrastructure as Code (Terraform, CloudFormation) standards
- [`shell-scripting.md`](.roo/rules-devops/shell-scripting.md) - Shell script best practices and patterns

**Documentation Writer Mode** (`rules-documentation-writer/`)
- [`documentation-standards.md`](.roo/rules-documentation-writer/documentation-standards.md) - Comprehensive documentation guidelines

**Security Review Mode** (`rules-security-review/`)
- [`security-detailed.md`](.roo/rules-security-review/security-detailed.md) - Security audit checklists and vulnerability patterns

**Mode Writer Mode** (`rules-mode-writer/`)
- [`1_mode_creation_workflow.xml`](.roo/rules-mode-writer/1_mode_creation_workflow.xml) - Workflow for creating custom modes
- [`2_xml_structuring_best_practices.xml`](.roo/rules-mode-writer/2_xml_structuring_best_practices.xml) - XML structure guidelines
- [`3_mode_configuration_patterns.xml`](.roo/rules-mode-writer/3_mode_configuration_patterns.xml) - Configuration patterns
- [`4_instruction_file_templates.xml`](.roo/rules-mode-writer/4_instruction_file_templates.xml) - Instruction file templates

#### Archived Rules (`rules-archive/`)
Legacy rules that have been superseded by mode-specific rules. Kept for reference.

### `.rooignore`
Configuration file that excludes files and directories from AI context to:
- **Protect secrets** - Environment files, keys, credentials
- **Reduce noise** - Dependencies, build artifacts, logs
- **Improve performance** - Large files, binary files, generated code
- **Focus AI** - Only include relevant source code and documentation

## 🚀 Quick Start

You can use these templates in two ways:

### Option A: Global Configuration (Recommended for Personal Use)

Apply rules across **all your projects** by copying to your home directory:

```bash
# macOS/Linux
cp -r path/to/tools/roo-code/templates/.roo ~/
cp path/to/tools/roo-code/templates/.rooignore ~/

# Windows (PowerShell)
Copy-Item -Recurse path\to\tools\roo-code\templates\.roo $HOME\
Copy-Item path\to\tools\roo-code\templates\.rooignore $HOME\
```

**Benefits:**
- ✅ Rules apply to all projects automatically
- ✅ Consistent standards across your workspace
- ✅ No need to copy templates to each project
- ✅ Single location to update rules

**When to use:**
- Personal projects with consistent standards
- Solo development across multiple repositories
- Learning and experimentation

**Note:** Project-specific `.roo/` configurations will override global settings.

### Option B: Project-Specific Configuration

Apply rules to a **single project** by copying to the project root:

```bash
# From your project root
cp -r path/to/tools/roo-code/templates/.roo .
cp path/to/tools/roo-code/templates/.rooignore .
```

**Benefits:**
- ✅ Team-specific rules committed to repository
- ✅ Version-controlled with project code
- ✅ Different standards per project
- ✅ Shared across team members

**When to use:**
- Team projects with specific conventions
- Open source projects with contributor guidelines
- Projects requiring unique standards
- When rules should be version-controlled

### Customize for Your Project/Workspace

#### Update `.rooignore`
Add project-specific patterns at the bottom of [`.rooignore`](.rooignore):

```gitignore
# ============================================================================
# CUSTOM PROJECT PATTERNS
# ============================================================================
my-large-dataset/
legacy-code/
experimental/
```

#### Select Relevant Rules
You don't need all rules. Keep only what's relevant:

- **Python project**: Keep `rules-code/python-standards.md`
- **TypeScript project**: Keep `rules-code/typescript-standards.md`
- **Infrastructure project**: Keep `rules-devops/` directory
- **Documentation-heavy**: Keep `rules-documentation-writer/`

Remove unused mode-specific directories to reduce clutter.

#### Customize Standards
Edit rule files to match your team's conventions:
- Code style preferences
- Testing requirements
- Security policies
- Documentation structure

### Verify Setup

Check that Roo Code recognizes your configuration:

**For Global Configuration:**
1. Open any project in VS Code with Roo Code extension
2. Start a conversation with Roo Code
3. Verify it references rules from `~/.roo/`
4. Check that global `.rooignore` patterns are applied

**For Project-Specific Configuration:**
1. Open your project in VS Code with Roo Code extension
2. Start a conversation with Roo Code
3. Verify it references rules from project's `.roo/` directory
4. Confirm project-specific rules override global ones (if both exist)

**Priority Order:**
- Project-specific `.roo/` (highest priority)
- Global `~/.roo/` (fallback)
- Roo Code defaults (lowest priority)

## 📋 Rule Categories

### Critical Core Standards
**Always loaded** - Essential principles for all tasks:
- Task splitting thresholds (>5 files, >500 lines → split)
- Security fundamentals (no hardcoded secrets, input validation)
- Quality standards (80% test coverage, meaningful tests)
- Error recovery patterns

### Mode-Specific Standards
**Loaded based on active mode** - Specialized guidelines:
- **Code Mode**: Language-specific standards, testing patterns
- **Architect Mode**: Design patterns, architectural decisions
- **DevOps Mode**: Infrastructure, deployment, CI/CD
- **Security Review Mode**: Vulnerability patterns, audit checklists
- **Documentation Writer Mode**: Writing style, organization

## 🎯 Key Features

### Task Splitting Rules
Prevents API streaming failures and context window errors:
- 🔴 **STOP**: >10 files, >1000 lines, >10 steps
- 🟡 **CAUTION**: 5-10 files, 500-1000 lines, 5-10 steps
- 🟢 **SAFE**: <5 files, <500 lines, <5 steps

### Security Standards
Non-negotiable security requirements:
- ✅ Never hardcode secrets
- ✅ Validate all inputs
- ✅ Use parameterized queries
- ✅ Sanitize error messages
- ✅ Follow OWASP Top 10 prevention

### Quality Standards
Consistent quality across all code:
- ✅ 80% minimum test coverage
- ✅ Cognitive complexity ≤15
- ✅ Meaningful variable/function names
- ✅ DRY principle
- ✅ Documentation for public APIs

### Collaborative Planning
Structured workflow before implementation:
1. Review task scope/spec
2. Identify ambiguities
3. Ask clarification questions
4. Document updated scope
5. Create implementation plan
6. Share plan for approval
7. Iterate based on feedback

## 📖 Documentation Standards

### File Organization
Optimal file count by project size:
- **Small** (<10k LOC): 3-7 documentation files
- **Medium** (10k-50k LOC): 7-15 documentation files
- **Large** (>50k LOC): 15-25 documentation files

### Core Documentation Files
Every project should have:
- `README.md` - Project overview and quick start
- `ARCHITECTURE.md` - System design and decisions
- `API.md` - API reference
- `CONTRIBUTING.md` - Development guidelines

### Redundancy Prevention
- Document each concept in **ONE** primary location
- Use **links** instead of duplicating content
- **Update** existing content rather than appending
- **Consolidate** similar examples

## 🔧 Customization Guide

### Adding Custom Rules

Create new rule files in appropriate directories:

```bash
# Language-specific rule
.roo/rules-code/golang-standards.md

# Custom mode rules
.roo/rules-custom-mode/my-standards.md
```

### Modifying Existing Rules

Edit rule files to match your needs:
1. Keep the structure and format
2. Update specific requirements
3. Add project-specific examples
4. Document deviations from defaults

### Creating Mode-Specific Rules

Follow the pattern in existing mode directories:
```
.roo/rules-{mode-name}/
├── {standard-name}.md
└── {another-standard}.md
```

## 🛡️ Best Practices

### Do's ✅
- **Keep rules updated** with code changes
- **Remove unused rules** to reduce noise
- **Customize for your team** - don't use defaults blindly
- **Document deviations** from standard rules
- **Review rules periodically** (quarterly recommended)

### Don'ts ❌
- **Don't ignore security rules** - they're non-negotiable
- **Don't skip task splitting** - prevents failures
- **Don't duplicate content** - use links instead
- **Don't keep outdated rules** - remove or update them
- **Don't add secrets to `.roo/`** - use `.rooignore`

## 🔍 Troubleshooting

### Roo Code Not Following Rules
1. Verify `.roo/` directory is in project root
2. Check rule file syntax (valid Markdown)
3. Ensure rules are clear and specific
4. Try restarting VS Code / Roo Code extension

### Too Many Rules / Context Overload
1. Remove unused mode-specific directories
2. Consolidate similar rules
3. Use `.rooignore` to exclude unnecessary files
4. Split large rule files into focused topics

### Rules Conflicting
1. Check for contradictory requirements
2. Ensure mode-specific rules don't override critical core rules
3. Document intentional deviations
4. Prioritize security and quality standards

## 📚 Related Resources

### Official Documentation
- [Roo Code Documentation](https://roo.dev/docs) - Official Roo Code docs
- [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=roo-code) - Install Roo Code

### Standards References
- [Conventional Commits](https://www.conventionalcommits.org/) - Commit message format
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Security vulnerabilities
- [Google Style Guides](https://google.github.io/styleguide/) - Language style guides
- [Keep a Changelog](https://keepachangelog.com/) - Changelog format

## 🤝 Contributing

To improve these templates:
1. Test changes in real projects
2. Document rationale for changes
3. Keep rules clear and actionable
4. Follow existing structure and format
5. Update this README with significant changes

## 📄 License

These templates are provided as-is for use in your projects. Customize freely to match your team's needs.

## 🆘 Support

For issues or questions:
- Check rule files for detailed guidance
- Review troubleshooting section above
- Consult Roo Code official documentation
- Adapt rules to your specific context

---

**Remember**: These are templates and starting points. Customize them to match your team's conventions, project requirements, and development workflow. The goal is to enhance AI-assisted development, not constrain it.
