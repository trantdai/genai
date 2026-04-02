# Documentation Standards

## Purpose
Comprehensive guidelines for creating, organizing, and maintaining technical documentation that is findable, maintainable, and free from redundancy.

## Critical Principles

### 1. Single Source of Truth
- Each concept must be documented in **ONE primary location**
- Other locations should **LINK** to the primary source, not duplicate content
- Avoid copy-pasting information across multiple files

### 2. Balanced File Organization
- **Too few files** = Hard to navigate, overwhelming content
- **Too many files** = Scattered information, hard to find
- **Goal**: Optimal balance based on project size and audience needs

### 3. Prevent Redundancy
- **Update existing content** rather than appending new versions
- **Remove outdated information** completely
- **Consolidate similar examples** into one comprehensive example

---

## File Organization Guidelines

### Optimal File Count by Project Size

| Project Size | Lines of Code | Recommended Doc Files | Core Files |
|--------------|---------------|----------------------|------------|
| **Small** | <10k LOC | 3-7 files | README, ARCHITECTURE, API |
| **Medium** | 10k-50k LOC | 7-15 files | + CONTRIBUTING, guides by domain |
| **Large** | >50k LOC | 15-25 files | + Detailed domain docs, ADRs |

### Core Documentation Files (Always Required)

```
docs/
├── README.md              # Project overview, quick start, doc index
├── ARCHITECTURE.md        # System design, key decisions
├── API.md                 # API reference (or API/ directory)
└── CONTRIBUTING.md        # Development guidelines
```

### When to Split Files

Split documentation when:
- ✅ A single topic exceeds **2000 lines**
- ✅ Topics serve **different audiences** (users vs. developers)
- ✅ Topics have **different update frequencies**
- ✅ Content is **independently consumable**

### When to Consolidate Files

Consolidate documentation when:
- ✅ Files are **<200 lines** and closely related
- ✅ Information is **frequently cross-referenced**
- ✅ Users need to **read multiple files together**
- ✅ Content is **tightly coupled** (e.g., API endpoints for one service)

### Balanced Documentation Structure Example

```
docs/
├── README.md                    # Overview + documentation index
├── getting-started.md           # Installation + quick start + basic config
├── user-guide.md                # All user-facing features (consolidated)
├── api-reference.md             # All API endpoints (consolidated with TOC)
├── architecture.md              # System design + architectural decisions
├── development.md               # Setup + contributing + testing
└── troubleshooting.md           # Common issues + solutions
```

**Total: 7 files** (optimal for medium projects)

---

## Information Architecture

### Documentation Index (Required)

**README.md must include a documentation map:**

```markdown
## Documentation

- [Getting Started](./docs/getting-started.md) - Installation and quick start
- [User Guide](./docs/user-guide.md) - Complete feature documentation
- [API Reference](./docs/api-reference.md) - API endpoints and examples
- [Architecture](./docs/architecture.md) - System design and decisions
- [Development](./docs/development.md) - Contributing and development setup
- [Troubleshooting](./docs/troubleshooting.md) - Common issues and solutions
```

### Cross-Referencing Standards

**Use relative links to connect related content:**

```markdown
For authentication details, see [Authentication](./api-reference.md#authentication).

See also:
- [User Management API](./api-reference.md#user-management)
- [Security Architecture](./architecture.md#security)
```

**Benefits:**
- Avoids content duplication
- Maintains single source of truth
- Easy to update (change once, reflected everywhere)

### Table of Contents for Long Files

For files >500 lines, include a TOC at the top:

```markdown
# API Reference

## Table of Contents
- [Authentication](#authentication)
- [User Management](#user-management)
- [Product Management](#product-management)
- [Order Management](#order-management)
```

---

## Redundancy Prevention

### Before Adding Content - Checklist

- [ ] **Search existing docs** for similar information
- [ ] If found, **update existing content** rather than duplicating
- [ ] If adding new perspective, **link to existing content**
- [ ] If content is outdated, **replace it** (don't append)

### Update Strategy

**❌ Bad: Appending New Versions**
```markdown
## Installation (Old Method)
[outdated content]

## Installation (New Method - Updated 2024)
[new content]

## Installation (Latest - Updated 2025)
[newer content]
```

**✅ Good: Replacing Outdated Content**
```markdown
## Installation
[current content only]

> **Note**: For legacy versions (<2.0), see [Legacy Installation](./legacy/installation.md)
```

### Consolidating Similar Content

**❌ Bad: Multiple Similar Examples**
```markdown
## Example 1: Basic User Creation
[code example]

## Example 2: User Creation with Email
[code example]

## Example 3: User Creation with Validation
[code example]
```

**✅ Good: One Comprehensive Example**
```markdown
## User Creation Examples

### Basic User Creation
[code example]

### With Optional Fields
[code example showing email, validation, etc.]
```

---

## Documentation Types & When to Use

### 1. README.md
**Purpose**: Project overview and entry point
**Audience**: Everyone
**Content**:
- Project description and purpose
- Quick start guide
- Documentation index
- Key links (repo, issues, contributing)

**Length**: 200-500 lines

### 2. Getting Started / Installation
**Purpose**: Help users get up and running
**Audience**: New users and developers
**Content**:
- Prerequisites
- Installation steps
- Basic configuration
- First example/tutorial

**Length**: 300-800 lines

### 3. User Guide / Feature Documentation
**Purpose**: Comprehensive feature documentation
**Audience**: End users
**Content**:
- Feature descriptions
- Usage examples
- Configuration options
- Best practices

**Length**: 500-2000 lines (split if exceeds 2000)

### 4. API Reference
**Purpose**: Complete API documentation
**Audience**: Developers integrating with the API
**Content**:
- Endpoint descriptions
- Request/response formats
- Authentication
- Error codes
- Code examples

**Length**: 500-3000 lines (use TOC if >1000 lines)

### 5. Architecture Documentation
**Purpose**: System design and decisions
**Audience**: Developers and architects
**Content**:
- System architecture diagrams
- Component descriptions
- Design decisions (ADRs)
- Data flow
- Technology stack

**Length**: 500-1500 lines

### 6. Contributing / Development Guide
**Purpose**: Help developers contribute
**Audience**: Contributors
**Content**:
- Development setup
- Coding standards
- Testing guidelines
- PR process
- Release process

**Length**: 300-1000 lines

### 7. Troubleshooting
**Purpose**: Help users solve common problems
**Audience**: Users and support teams
**Content**:
- Common issues and solutions
- Error messages and fixes
- FAQ
- Debug procedures

**Length**: 300-1000 lines

---

## Documentation Maintenance

### Update Triggers

Documentation must be updated when:
- ✅ **Code changes** affect documented behavior
- ✅ **New features** are added
- ✅ **APIs change** (endpoints, parameters, responses)
- ✅ **Configuration options** change
- ✅ **Dependencies** are updated
- ✅ **Bugs are fixed** that affect documented behavior

### Periodic Maintenance (Quarterly)

Every 3 months, review documentation for:
- [ ] **Redundant content** - Consolidate duplicates
- [ ] **Outdated information** - Update or remove
- [ ] **Broken links** - Fix cross-references
- [ ] **Missing content** - Fill gaps
- [ ] **File organization** - Consolidate or split as needed

### Documentation Refactoring Triggers

Refactor documentation when:
- 🔴 **>20 files** without clear structure
- 🔴 **Users report** difficulty finding information
- 🔴 **Multiple files** cover overlapping topics
- 🔴 **Significant redundancy** across files
- 🔴 **No clear documentation index**

### Refactoring Process

1. **Audit** all documentation files
2. **Map** information architecture (what's where)
3. **Identify** redundancies and gaps
4. **Consolidate or split** as needed
5. **Update** all cross-references
6. **Add** navigation aids (TOC, index)
7. **Test** findability with sample questions

---

## Writing Guidelines

### Documentation Quality Standards

- ✅ **Update with code** - Keep docs synchronized
- ✅ **Document "why" not "what"** - Explain reasoning, not just mechanics
- ✅ **Use examples** - Show, don't just tell
- ✅ **Be concise** - Respect reader's time
- ✅ **Use consistent terminology** - Define terms once, use consistently
- ✅ **Include error cases** - Document what can go wrong

### Writing Style

- Use **active voice**: "The API returns..." not "The response is returned..."
- Use **present tense**: "The function validates..." not "The function will validate..."
- Use **imperative mood** for instructions: "Run the command" not "You should run..."
- Use **second person** for user-facing docs: "You can configure..." not "Users can configure..."

### Code Examples

- ✅ **Complete and runnable** - Don't use pseudocode
- ✅ **Include context** - Show imports, setup, etc.
- ✅ **Show expected output** - What should users see?
- ✅ **Handle errors** - Show error handling patterns

---

## Mode-Specific Guidelines

### Documentation Writer Mode

When in Documentation Writer mode:
- **Maximum section size**: 500 words per batch
- **Write one section** at a time for large docs
- **Wait for confirmation** before proceeding to next section
- **Use todo lists** to track documentation progress

### Code Mode

When writing documentation in Code mode:
- **Update docs with code changes** - Same PR/commit
- **Keep docstrings/JSDoc current** - Inline documentation
- **Update API docs** when endpoints change
- **Add examples** for new features

### Architect Mode

When creating architectural documentation:
- **One major section** at a time
- **One diagram** per response
- **One ADR** (Architectural Decision Record) at a time
- **Link to related decisions** - Build decision graph

---

## Documentation Review Checklist

Before finalizing documentation:

### Content Quality
- [ ] Information is accurate and up-to-date
- [ ] Examples are complete and tested
- [ ] Terminology is consistent
- [ ] No redundant content
- [ ] No outdated information

### Organization
- [ ] File count is appropriate for project size
- [ ] Information is easy to find
- [ ] Related content is linked
- [ ] Documentation index exists
- [ ] TOC exists for long files (>500 lines)

### Maintainability
- [ ] Single source of truth maintained
- [ ] Cross-references use relative links
- [ ] Update triggers are clear
- [ ] File organization is logical

### Accessibility
- [ ] Clear entry point (README)
- [ ] Navigation aids present
- [ ] Audience-appropriate language
- [ ] Examples are provided

---

## Common Anti-Patterns to Avoid

### ❌ Anti-Pattern 1: Documentation Sprawl
**Problem**: 30+ small files, hard to navigate
**Solution**: Consolidate related content, aim for 7-15 files for medium projects

### ❌ Anti-Pattern 2: The Monolith
**Problem**: One 5000-line file with everything
**Solution**: Split by topic, keep files under 2000 lines

### ❌ Anti-Pattern 3: Copy-Paste Documentation
**Problem**: Same information duplicated across multiple files
**Solution**: Document once, link from other locations

### ❌ Anti-Pattern 4: Append-Only Updates
**Problem**: Multiple versions of same content (Old, New, Latest)
**Solution**: Replace outdated content, archive if needed

### ❌ Anti-Pattern 5: Orphaned Documentation
**Problem**: Documentation not linked from anywhere
**Solution**: Maintain documentation index, ensure all docs are discoverable

### ❌ Anti-Pattern 6: Stale Documentation
**Problem**: Documentation doesn't match current code
**Solution**: Update docs with code changes, include in definition of done

---

## Success Metrics

Well-organized documentation should:
- ✅ **Findable**: Users can locate information in <2 minutes
- ✅ **Accurate**: Documentation matches current code behavior
- ✅ **Complete**: All features and APIs documented
- ✅ **Maintainable**: Easy to update without breaking links
- ✅ **Non-redundant**: Each concept documented once
- ✅ **Navigable**: Clear structure with index and cross-references

---

## Related Standards

For comprehensive development practices, also refer to:
- [Task Management](.roo/rules/11-task-management.md) - Task execution and error prevention
- [Collaborative Planning](.roo/rules/12-collaborative-planning.md) - Planning and approval workflow
- [Commit Standards](.roo/rules/10-commit-standards.md) - Use `docs` type for documentation commits
- [PR Review Standards](.roo/rules/01-pr-reviews.md) - Documentation review guidelines

---

## Remember

> **"Good documentation is findable, accurate, and maintainable. Optimize for the reader, not the writer."**

When in doubt:
1. **Consolidate** rather than scatter
2. **Link** rather than duplicate
3. **Update** rather than append
4. **Organize** for findability
