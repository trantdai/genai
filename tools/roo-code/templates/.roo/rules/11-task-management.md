# Task Management & Error Prevention Standards

## Critical Principle: Task Granularity
**ALWAYS split sizable tasks into granular and manageable pieces to avoid API streaming failures and LLM errors.**

This is especially critical in Orchestrator mode where complex multi-step operations can exceed token limits or cause streaming failures.

## Pre-Task Checklist (Run BEFORE Starting)

Before beginning ANY task, ask yourself:
- [ ] Have I followed the collaborative planning workflow? (see [`12-collaborative-planning.md`](.roo/rules/12-collaborative-planning.md))
  - [ ] Reviewed task scope/spec if it exists?
  - [ ] Asked clarification questions for ambiguities?
  - [ ] Documented updated scope based on clarifications?
  - [ ] Created and shared implementation plan for approval?
  - [ ] Incorporated feedback into the plan?
- [ ] Is this task >5 files OR >500 lines? → **SPLIT IT**
- [ ] Does this have multiple independent steps? → **SPLIT IT**
- [ ] Am I in Orchestrator mode? → **EXTRA CAUTION**
- [ ] Have I created a todo list? → **CREATE ONE NOW**
- [ ] Can I describe this in <3 sentences? → If NO, **SPLIT IT**

## 🛡️ Proactive Rule Enforcement (MANDATORY)

### Before EVERY Response
- [ ] Assessed task complexity (files, lines, steps)?
- [ ] Checked against critical thresholds?
- [ ] Determined if splitting is needed?
- [ ] Communicated plan to user?
- [ ] Received approval before proceeding?

### Self-Enforcement Pattern
**If about to violate rules**:
1. **STOP** - Don't proceed with violation
2. **ACKNOWLEDGE** - "I need to split this task first"
3. **REPLAN** - Create proper splitting strategy
4. **COMMUNICATE** - Share plan with user
5. **EXECUTE** - Only after approval

### Automatic Triggers
**MUST split when**:
- PR review with >5 files
- Response will exceed 2000 words
- Reading >3 large files (>1000 lines each)
- Generating >500 lines of code
- Context approaching 150k tokens

## 🚨 Critical Thresholds

- 🔴 **STOP**: >10 files, >1000 lines, >10 steps
- 🟡 **CAUTION**: 5-10 files, 500-1000 lines, 5-10 steps
- 🟢 **SAFE**: <5 files, <500 lines, <5 steps

## Quick Reference: Size Thresholds

| Operation Type | Maximum Size | Recommended Batch |
|---------------|--------------|-------------------|
| File creation | 5 files | 3 files |
| Code generation | 300 lines | 150-200 lines |
| File modification | 5 files | 2-3 files |
| Documentation | 1 major section | 500 words |
| IaC resources | 5 resources | 3 resources |
| PR review | 5 files | 3-5 files per phase |

## PR Review Splitting

### Why PR Reviews Are High Risk
- Multi-file analysis consumes significant tokens
- Extensive commentary generation
- Code snippet inclusion
- Cross-referencing between files
- **Result**: Easy to exceed context window limits

### Mandatory PR Review Approach
1. **Count files changed** - If >5, split by file groups
2. **Estimate lines changed** - If >500, split by aspect
3. **Create phase plan** - Share with user for approval
4. **Execute one phase** - Wait for confirmation
5. **Continue next phase** - Repeat until complete

### Example Phase Plan
```markdown
PR Analysis: 8 files changed, ~750 lines

Phase 1: Security review (auth.py, api.py, middleware.py)
Phase 2: Code quality (services.py, utils.py)
Phase 3: Testing review (test_auth.py, test_api.py, test_services.py)
Phase 4: Summary and recommendations

Shall I proceed with Phase 1?
```

## Task Splitting Guidelines

### When to Split Tasks
Split tasks when they involve:
- **Multiple file operations** (>5 files to create/modify)
- **Large code changes** (>500 lines of code)
- **Complex refactoring** across multiple modules
- **Multi-step workflows** with dependencies
- **Comprehensive feature implementations**
- **Large-scale documentation updates**
- **Infrastructure provisioning** with multiple resources
- **Batch operations** on multiple items

### Common Failure Scenarios
- ❌ Creating 10+ files in one `write_to_file` batch
- ❌ Generating a 1000+ line file in a single operation
- ❌ Running multiple complex searches without checkpoints
- ❌ Delegating complex multi-file tasks to subagents
- ❌ Attempting to refactor entire modules in one operation
- ❌ Creating comprehensive documentation in single response

### How to Split Tasks

#### 1. Break Down by Logical Components
```
❌ Bad: "Create a complete REST API with authentication, database, and frontend"

✅ Good:
- Step 1: Set up project structure and dependencies
- Step 2: Implement database models and migrations
- Step 3: Create authentication endpoints
- Step 4: Implement CRUD endpoints for main resources
- Step 5: Add input validation and error handling
- Step 6: Create frontend components
- Step 7: Integrate frontend with API
- Step 8: Add tests and documentation
```

#### 2. Break Down by File Groups
```
❌ Bad: "Update all 20 configuration files"

✅ Good:
- Batch 1: Update core config files (5 files)
- Batch 2: Update service configs (5 files)
- Batch 3: Update deployment configs (5 files)
- Batch 4: Update CI/CD configs (5 files)
```

#### 3. Break Down by Functionality
```
❌ Bad: "Implement complete user management system"

✅ Good:
- Phase 1: User registration and basic CRUD
- Phase 2: Authentication and session management
- Phase 3: Authorization and role-based access
- Phase 4: User profile and preferences
- Phase 5: Password reset and email verification
```

## ⚠️ ORCHESTRATOR MODE: CRITICAL REQUIREMENTS

**This mode is MOST prone to streaming failures. Follow these rules strictly:**

1. **NEVER delegate complex tasks** - Break them down first
2. **ONE subtask at a time** - Wait for completion confirmation
3. **Mandatory todo lists** - Always use `update_todo_list`
4. **Verify before proceeding** - Check each subtask result
5. **Maximum subtask size** - Keep under 300 lines of code

### Task Delegation Strategy
When in Orchestrator mode:

1. **Analyze the full scope** before delegating
2. **Create explicit subtasks** with clear boundaries
3. **Delegate one subtask at a time** to specialized modes
4. **Wait for completion** before proceeding to dependent tasks
5. **Verify results** before moving to the next phase

### Example Orchestration Pattern
```markdown
## Main Task: Build E-commerce Platform

### Subtask 1: Database Design (Architect Mode)
- Design database schema
- Create ERD diagrams
- Document relationships

### Subtask 2: API Implementation (Code Mode)
- Implement product endpoints
- Implement cart endpoints
- Implement order endpoints

### Subtask 3: Testing (Code Mode)
- Write unit tests for API
- Write integration tests
- Verify test coverage

### Subtask 4: Documentation (Documentation Writer Mode)
- API documentation
- Setup guide
- User guide
```

## Error Handling & Recovery

### API Streaming Failures
When encountering API streaming failures:

1. **Immediately stop** the current operation
2. **Identify the scope** of what was being attempted
3. **Split into smaller chunks** (aim for <300 lines per operation)
4. **Retry with reduced scope**
5. **Document what was completed** vs. what remains

### LLM Token Limit Errors
When approaching token limits:

1. **Pause and assess** remaining work
2. **Create a checkpoint** of completed work
3. **Break remaining work** into smaller tasks
4. **Use todo lists** to track progress
5. **Resume with focused scope**

### Recovery Pattern
```markdown
If error occurs:
1. Acknowledge the error explicitly
2. Summarize what was completed successfully
3. List what remains to be done
4. Propose smaller, focused next steps
5. Ask user to confirm the approach
```

### Recovery Example: Mid-Task Streaming Failure

**What happened**: Streaming failed while creating 8 files (completed 3)

**Recovery steps**:
1. ✅ Acknowledge: "I encountered a streaming failure after creating 3 files"
2. ✅ Checkpoint: "Successfully created: file1.py, file2.py, file3.py"
3. ✅ Remaining: "Still need: file4.py, file5.py, file6.py, file7.py, file8.py"
4. ✅ Replan: "I'll create the remaining 5 files in two batches: [4-6] then [7-8]"
5. ✅ Confirm: "Shall I proceed with files 4-6?"

## Best Practices

### File Operations
- **Create files in batches** of 3-5 at a time
- **Wait for confirmation** before proceeding to next batch
- **Use todo lists** to track file creation progress

### Code Generation
- **Generate one module/class** at a time
- **Keep functions under 50 lines** when possible
- **Split large files** into multiple smaller files
- **Use incremental approach** for complex logic

### Documentation
- **Write one section** at a time for large docs
- **Split by topic** rather than creating one massive file
- **Update incrementally** rather than rewriting entirely

### Infrastructure as Code
- **Provision resources in logical groups**
- **Create modules separately** before composing
- **Test each component** before moving to next
- **Use workspaces/environments** to isolate changes

## Proactive Monitoring

### Self-Check Questions
Before starting any task, ask:
- [ ] Can this be completed in a single operation?
- [ ] Will this generate >300 lines of code?
- [ ] Does this involve >5 files?
- [ ] Are there multiple independent components?
- [ ] Could this exceed token limits?

If **any answer is YES**, split the task first.

### Progress Tracking
For multi-step tasks:
- **Always use `update_todo_list`** to track progress
- **Mark items complete** as you finish them
- **Update the list** if new subtasks are discovered
- **Keep user informed** of progress at each step

### Progress Tracking Tools
- Use `update_todo_list` tool to create and maintain task lists
- Use `attempt_completion` only after ALL subtasks are verified
- Use `ask_followup_question` if task scope is unclear
- Use `read_file` before modifying to understand context
- Use `search_files` to locate relevant code before changes

## Communication Patterns

### Starting Large Tasks (Template)
```markdown
I've analyzed this task and identified it requires [X files/Y lines/Z steps].

To avoid API streaming failures, I'll split this into [N] phases:

**Phase 1**: [Specific deliverable] (Est: [X] files)
**Phase 2**: [Specific deliverable] (Est: [Y] files)
**Phase 3**: [Specific deliverable] (Est: [Z] files)

I'll use `update_todo_list` to track progress and wait for your confirmation between phases.

Shall I proceed with Phase 1?
```

### During Task Execution
```markdown
✅ Completed: [Component name]
🔄 In Progress: [Current component]
⏳ Remaining: [List of remaining components]
```

### When Encountering Errors
```markdown
I encountered an [error type]. To proceed safely, I'll:
1. Complete the current smaller scope
2. Break remaining work into these focused tasks: [list]
3. Continue with reduced scope to avoid further errors
```

## Mode-Specific Guidelines

### Ask Mode
- **Maximum analysis scope**: 3-5 files per response
- **Maximum explanation length**: 2000 words
- **PR review approach**: ALWAYS split by phase
- **Documentation analysis**: One major section at a time
- **Context window awareness**: CRITICAL - extensive reading and analysis

### Code Mode
- **Maximum files per operation**: 5 files
- **Maximum lines per file**: 300 lines
- **Batch operations**: Group related changes
- **Incremental commits**: Commit logical units
- **Context window risk**: Medium (code generation uses tokens)

### Architect Mode
- **Documentation sections**: One major section at a time
- **Diagram complexity**: One diagram per response
- **Decision records**: One ADR at a time
- **Context window risk**: High (extensive documentation generation)

### Debug Mode
- **Investigation scope**: One issue at a time
- **Log analysis**: Focused time windows
- **Fix implementation**: Isolated changes
- **Context window risk**: Medium (log analysis can be extensive)

### Orchestrator Mode
- **Maximum subtask complexity**: Medium (avoid complex subtasks)
- **Delegation frequency**: One subtask at a time
- **Progress tracking**: Mandatory todo list
- **Verification**: Check each subtask completion before proceeding
- **Context window risk**: HIGH (coordination overhead)

### Security Review Mode
- **File analysis**: 3-5 files maximum per phase
- **Vulnerability assessment**: One category at a time
- **Audit reports**: Split by security domain
- **Context window risk**: HIGH (detailed analysis + recommendations)

## Emergency Protocols

### If Streaming Fails Mid-Operation
1. **Stop immediately** - Don't retry the same large operation
2. **Assess damage** - What was partially completed?
3. **Clean up** - Remove partial/broken artifacts if needed
4. **Replan** - Create smaller, safer subtasks
5. **Communicate** - Explain to user what happened and next steps

### If Token Limit Approached
1. **Finish current atomic unit** (current file/function)
2. **Create checkpoint** - Summarize progress
3. **Update todo list** with remaining work
4. **Propose continuation** - Smaller next step
5. **Wait for user confirmation**

## Context Window Emergency Protocol

### Warning Signs
- Token count approaching 150,000 (75% of limit)
- Response generation slowing down
- Multiple large files being analyzed
- Extensive commentary being generated

### Immediate Actions
1. **STOP CURRENT OPERATION**
   - Don't complete the current response
   - Don't try to "finish just this part"

2. **CHECKPOINT PROGRESS**
   ```markdown
   ⚠️ Context Window Warning: Approaching token limit

   ✅ Completed so far:
   - [List completed items]

   ⏳ Remaining work:
   - [List remaining items]

   📋 Proposed next steps:
   - Phase 1: [Specific scope]
   - Phase 2: [Specific scope]

   Shall I proceed with Phase 1?
   ```

3. **REPLAN WITH SMALLER SCOPE**
   - Reduce scope to <50% of original
   - Focus on single aspect/component
   - Create explicit phase boundaries

4. **WAIT FOR USER CONFIRMATION**
   - Don't proceed automatically
   - Let user decide on continuation strategy

### Prevention is Better Than Recovery
- **Always split proactively** - Don't wait for warnings
- **Monitor token usage** - Be aware of conversation length
- **Use phased approaches** - Default to smaller scopes
- **Communicate early** - Share splitting plans upfront

## Learning from Failures

When a streaming failure or token limit error occurs:
1. **Document the failure** in `tasks/lessons.md` if it exists
2. **Note what size/complexity triggered it** (files, lines, steps)
3. **Adjust your thresholds** to be more conservative
4. **Update this document** if you discover new patterns
5. **Share learnings** with the user for future reference

### Failure Pattern Recognition
Common patterns that lead to failures:
- Attempting to create entire project structures at once
- Generating large configuration files without splitting
- Refactoring multiple modules simultaneously
- Creating comprehensive test suites in one operation
- Writing extensive documentation without checkpoints

## Success Metrics

A well-managed task should:
- ✅ Complete without API/streaming errors
- ✅ Have clear progress indicators
- ✅ Be resumable if interrupted
- ✅ Produce working code at each checkpoint
- ✅ Keep user informed throughout
- ✅ Finish all planned work

## Related Standards

For comprehensive development practices, also refer to:
- [Collaborative Planning](.roo/rules/12-collaborative-planning.md) - Planning and approval workflow
- [Python Standards](.roo/rules/02-python-standards.md) - Code quality and testing
- [TypeScript Standards](.roo/rules/03-typescript-standards.md) - Type safety and patterns
- [Documentation Standards](.roo/rules/09-documentation-standards.md) - Documentation practices
- [Commit Standards](.roo/rules/10-commit-standards.md) - Version control conventions
- [PR Review Standards](.roo/rules/01-pr-reviews.md) - Code review guidelines

## Remember
**"Small, focused, incremental progress is better than ambitious failures."**

When in doubt, split it smaller. It's always easier to combine small successes than to recover from large failures.
