# Task Execution Standards for Code Mode

## File Operations Best Practices

### Creating Files
- **Create files in batches** of 3-5 at a time
- **Wait for confirmation** before proceeding to next batch
- **Use todo lists** to track file creation progress

### Modifying Files
- **Maximum files per operation**: 5 files
- **Read before modifying** to understand context
- **Use search_files** to locate relevant code before changes

### Code Generation
- **Generate one module/class** at a time
- **Keep functions under 50 lines** when possible
- **Maximum lines per file**: 300 lines
- **Split large files** into multiple smaller files
- **Use incremental approach** for complex logic

## Error Recovery in Code Mode

### When Streaming Fails
1. **Stop immediately** - Don't retry the same large operation
2. **Assess what completed** - Which files were created/modified?
3. **Clean up** - Remove partial/broken artifacts if needed
4. **Replan** - Create smaller, safer subtasks
5. **Communicate** - Explain to user what happened and next steps

### Recovery Pattern
```markdown
I encountered a streaming failure after [action].

✅ Completed: [list of successful operations]
❌ Failed: [what didn't complete]
📋 Remaining: [what still needs to be done]

I'll split the remaining work into smaller batches:
- Batch 1: [specific files/operations]
- Batch 2: [specific files/operations]

Shall I proceed with Batch 1?
```

## Code Mode Specific Guidelines

### Batch Operations
- Group related changes together
- Commit logical units
- Test after each batch

### Incremental Development
- Build features incrementally
- Test each increment
- Get feedback before proceeding

### Refactoring
- Refactor one module at a time
- Maintain test coverage during refactoring
- Document significant changes

## Communication Patterns

### Starting Code Tasks
```markdown
I'll implement this in [N] phases:

**Phase 1**: [Component] - [X] files, ~[Y] lines
**Phase 2**: [Component] - [X] files, ~[Y] lines

I'll create tests alongside each phase and wait for confirmation between phases.

Shall I proceed with Phase 1?
```

### During Execution
```markdown
✅ Completed: [Component name] ([X] files)
🔄 In Progress: [Current component]
⏳ Remaining: [List of remaining components]
```

## Related Standards

For comprehensive development practices, also refer to:
- [Python Standards](./python-standards.md) - Python-specific guidelines
- [TypeScript Standards](./typescript-standards.md) - TypeScript-specific guidelines
- [Task Management](../.roo/rules/11-task-management.md) - General task management
- [Collaborative Planning](../.roo/rules/12-collaborative-planning.md) - Planning workflow
