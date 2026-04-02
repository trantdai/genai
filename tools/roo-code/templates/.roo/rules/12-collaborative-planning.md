# Collaborative Planning Standards

## Core Principle
**Before implementation, always engage in collaborative planning to ensure alignment, clarity, and shared understanding of the task.**

This workflow ensures that:
- Requirements are clearly understood
- Ambiguities are resolved upfront
- Implementation plans are reviewed and approved
- Changes are documented and communicated

## Collaborative Planning Workflow

### 1. Review Task Scope/Spec

**Before starting any implementation**, review existing documentation:

- [ ] Check for task specifications, requirements documents, or user stories
- [ ] Review related documentation in `docs/` directory
- [ ] Understand acceptance criteria and success metrics
- [ ] Identify dependencies and constraints
- [ ] Review architectural patterns and standards that apply

**If no spec exists**: Document your understanding of the task requirements before proceeding.

### 2. Identify Ambiguities and Gaps

Analyze the task for unclear or missing information:

- [ ] Are requirements specific and measurable?
- [ ] Are edge cases defined?
- [ ] Are technical constraints clear?
- [ ] Are success criteria explicit?
- [ ] Are there conflicting requirements?
- [ ] Is the scope well-bounded?

**Document all ambiguities** you identify for clarification.

### 3. Ask Clarification Questions

**Mandatory step**: When ambiguities exist, ask clarification questions before implementation.

#### Good Clarification Questions:
- ✅ "Should the API endpoint return 404 or 400 when the user ID doesn't exist?"
- ✅ "What's the expected behavior when the file size exceeds 10MB?"
- ✅ "Should we validate email format on the frontend, backend, or both?"
- ✅ "Is backward compatibility required for this API change?"

#### Poor Clarification Questions:
- ❌ "What should I do?" (too vague)
- ❌ "Is this okay?" (no context)
- ❌ "Any preferences?" (too open-ended)

#### When to Ask:
- **Always** when requirements are ambiguous
- **Always** when multiple valid interpretations exist
- **Always** when edge cases are undefined
- **Before** making architectural decisions
- **Before** implementing breaking changes

#### How to Ask:
Use the `ask_followup_question` tool with:
- Clear, specific questions
- Context about why clarification is needed
- Suggested options when applicable
- Impact of different choices

### 4. Document Updated Scope

After receiving clarifications:

- [ ] Update task scope/spec with new information
- [ ] Document decisions made during clarification
- [ ] Note any assumptions being made
- [ ] Update acceptance criteria if needed
- [ ] Document constraints or limitations

**Format**: Use clear, concise language. Include:
- What was clarified
- Decision made
- Rationale (if applicable)
- Impact on implementation

### 5. Create Implementation Plan

Develop a detailed plan before coding:

#### Plan Components:
1. **Approach**: High-level strategy and architecture
2. **Steps**: Ordered list of implementation steps
3. **Files**: Files to create/modify
4. **Dependencies**: External dependencies or prerequisites
5. **Testing**: Testing strategy and coverage
6. **Risks**: Potential issues and mitigation strategies

#### Plan Template:
```markdown
## Implementation Plan: [Task Name]

### Approach
[High-level strategy and architectural decisions]

### Implementation Steps
1. [Step 1 with estimated complexity]
2. [Step 2 with estimated complexity]
3. [Step 3 with estimated complexity]

### Files to Create/Modify
- `path/to/file1.py` - [Purpose]
- `path/to/file2.py` - [Purpose]

### Dependencies
- [External libraries or services needed]

### Testing Strategy
- [Unit tests coverage]
- [Integration tests needed]
- [Manual testing steps]

### Risks & Mitigation
- **Risk**: [Potential issue]
  **Mitigation**: [How to address]

### Estimated Effort
[Time/complexity estimate]
```

### 6. Share Plan for Review/Approval

**Always share your plan** before implementation:

- [ ] Present the plan clearly and concisely
- [ ] Highlight key decisions and trade-offs
- [ ] Explain rationale for approach chosen
- [ ] Note any alternatives considered
- [ ] Ask for explicit approval: "Shall I proceed with this approach?"

#### Communication Pattern:
```markdown
I've analyzed the task and created an implementation plan:

**Approach**: [Brief summary]

**Key Steps**:
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Files Affected**: [X files to create, Y files to modify]

**Estimated Complexity**: [Low/Medium/High]

**Trade-offs**: [Any important trade-offs or decisions]

Shall I proceed with this approach?
```

### 7. Iterate Based on Feedback

When receiving feedback on your plan:

- [ ] Acknowledge the feedback
- [ ] Ask clarifying questions if feedback is unclear
- [ ] Update the plan based on feedback
- [ ] Document changes made and why
- [ ] Re-share updated plan if changes are significant
- [ ] Confirm final approach before proceeding

#### Iteration Pattern:
```markdown
Thank you for the feedback. I've updated the plan:

**Changes Made**:
- [Change 1]: [Reason]
- [Change 2]: [Reason]

**Updated Approach**: [Brief summary of changes]

Does this address your concerns? Shall I proceed?
```

## Integration with Task Management

This collaborative planning workflow integrates with [`11-task-management.md`](.roo/rules/11-task-management.md):

1. **First**: Complete collaborative planning (this document)
2. **Then**: Follow task management guidelines for execution
3. **Throughout**: Maintain communication and checkpoints

## Mode-Specific Guidance

### Orchestrator Mode
- **Always** complete collaborative planning before delegating
- Share the overall plan with user before creating subtasks
- Ensure each subtask has clear scope from planning phase
- Reference approved plan when delegating to specialized modes

### Code Mode
- Review plan before writing code
- Confirm approach if plan is ambiguous
- Update plan if implementation reveals new considerations
- Document deviations from plan with rationale

### Architect Mode
- Collaborative planning is core to this mode
- Create detailed architectural plans
- Document decision rationale thoroughly
- Ensure alignment with existing architecture (see `docs/`)

### Debug Mode
- Plan investigation approach before debugging
- Share hypothesis and investigation plan
- Document findings as you investigate
- Plan fix approach before implementing

## When to Skip Collaborative Planning

Collaborative planning may be abbreviated (but not skipped) for:

- **Trivial tasks**: Single-line fixes, typo corrections
- **Well-defined tasks**: Clear spec with no ambiguities
- **Emergency hotfixes**: Critical production issues (but document decisions afterward)

Even for these, still:
- Confirm understanding
- State your approach briefly
- Ask for approval if any uncertainty exists

## Anti-Patterns to Avoid

❌ **Don't**:
- Start coding immediately without understanding requirements
- Assume you know what the user wants without asking
- Make architectural decisions without discussion
- Implement first, ask questions later
- Skip planning for "small" tasks that turn out to be complex
- Ignore feedback on your plan
- Proceed without explicit approval

✅ **Do**:
- Take time to understand requirements fully
- Ask questions when anything is unclear
- Share your thinking and approach
- Wait for approval before implementation
- Document decisions and rationale
- Iterate on plans based on feedback
- Communicate proactively throughout

## Success Metrics

A successful collaborative planning process results in:

- ✅ Clear, documented requirements
- ✅ All ambiguities resolved
- ✅ Approved implementation plan
- ✅ Shared understanding between user and AI
- ✅ Reduced rework and iterations
- ✅ Better quality outcomes
- ✅ Documented decisions for future reference

## Examples

### Example 1: Feature Implementation

**User Request**: "Add user authentication to the API"

**Good Response**:
```markdown
I need to clarify a few things before planning the implementation:

1. **Authentication Method**: Should we use JWT tokens, session-based auth, or OAuth2?
2. **User Storage**: Where should user credentials be stored? (Database, external service)
3. **Password Requirements**: Any specific password complexity requirements?
4. **Endpoints**: Which endpoints need authentication? All or specific ones?
5. **Existing Users**: Do we need to migrate existing users or start fresh?

Once clarified, I'll create a detailed implementation plan for your review.
```

### Example 2: Bug Fix

**User Request**: "Fix the login bug"

**Good Response**:
```markdown
I need more information to plan the fix:

1. **Bug Description**: What specific behavior is occurring? (Error message, unexpected behavior, etc.)
2. **Expected Behavior**: What should happen instead?
3. **Reproduction Steps**: How can I reproduce the issue?
4. **Environment**: Does this occur in all environments or specific ones?
5. **Recent Changes**: Were there recent changes that might have caused this?

Once I understand the issue, I'll investigate and share a fix plan before implementing.
```

### Example 3: Refactoring

**User Request**: "Refactor the user service"

**Good Response**:
```markdown
Before planning the refactoring, I need to understand the goals:

1. **Motivation**: What problems are we trying to solve? (Performance, maintainability, testability?)
2. **Scope**: Which parts of the user service should be refactored?
3. **Constraints**: Are there backward compatibility requirements?
4. **Testing**: What's the current test coverage? Should we maintain it?
5. **Timeline**: Is this urgent or can we do it incrementally?

I'll then review the current code, create a refactoring plan with before/after architecture, and share it for approval.
```

## Related Standards

For comprehensive development practices, also refer to:
- [`11-task-management.md`](.roo/rules/11-task-management.md) - Task execution and error prevention
- [`09-documentation-standards.md`](.roo/rules/09-documentation-standards.md) - Documentation practices
- [`01-pr-reviews.md`](.roo/rules/01-pr-reviews.md) - Code review guidelines

## Remember

**"Plan the work, work the plan."**

Taking time for collaborative planning upfront saves time, reduces errors, and produces better outcomes. Always engage with the user to ensure shared understanding before implementation.
