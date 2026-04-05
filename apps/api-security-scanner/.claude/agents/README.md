# Python Development Agents

This directory contains specialized AI agents designed to provide expert assistance for different aspects of Python development. Each agent maintains context about your project and can be invoked by Claude Code for targeted, domain-specific guidance.

## Overview

The agent system provides context-aware expertise across five key domains:

1. **Python Specialist** - Core Python development and best practices
2. **Testing Expert** - Test-driven development and quality assurance
3. **Security Auditor** - Security analysis and vulnerability detection
4. **Code Reviewer** - Code quality and design pattern evaluation
5. **Performance Optimizer** - Performance analysis and optimization

## Agent Architecture

Each agent is defined with:
- **Expertise Areas**: Specific domains of knowledge
- **Tools**: Available tools for analysis and modification
- **Context Tracking**: Project-specific context maintained across sessions
- **Analysis Approach**: Structured methodology for problem-solving
- **Integration Points**: Collaboration with other agents

## Available Agents

### 🐍 Python Specialist
**File**: [`python-specialist.md`](python-specialist.md)

Expert Python developer with deep knowledge of best practices, async patterns, and Python 3.13+ features.

**When to Invoke**:
- Code review for Python best practices
- Async/await implementation and optimization
- Design pattern recommendations
- Code refactoring guidance
- Python 3.13+ feature adoption

**Key Expertise**:
- PEP 8 compliance and pythonic code patterns
- AsyncIO mastery and coroutine optimization
- Memory management and garbage collection
- SOLID principles and clean architecture
- Performance optimization strategies

### 🧪 Testing Expert
**File**: [`testing-expert.md`](testing-expert.md)

Pytest mastery and test-driven development specialist focused on comprehensive testing strategies.

**When to Invoke**:
- Test strategy design and implementation
- Coverage improvement (target: 80%+)
- Flaky test resolution
- Mock and fixture design
- Integration testing setup

**Key Expertise**:
- Pytest advanced features and plugins
- Test-driven development (TDD) methodology
- Coverage analysis and gap identification
- Property-based testing with Hypothesis
- Test performance optimization

### 🔒 Security Auditor
**File**: [`security-auditor.md`](security-auditor.md)

Expert security analyst specializing in vulnerability detection, secure coding patterns, and OWASP compliance.

**When to Invoke**:
- Security code reviews
- Vulnerability assessment
- Authentication/authorization review
- Secret management validation
- Dependency security analysis

**Key Expertise**:
- OWASP Top 10 vulnerability detection
- Secure coding pattern enforcement
- SQL injection and XSS prevention
- JWT and OAuth2 security
- HashiCorp Vault integration

### 📋 Code Reviewer
**File**: [`code-reviewer.md`](code-reviewer.md)

Expert code reviewer specializing in quality assessment, design patterns, and maintainability analysis.

**When to Invoke**:
- Pull request reviews
- Code quality audits
- Architecture review
- Refactoring planning
- Technical debt assessment

**Key Expertise**:
- Code quality metrics and analysis
- Design pattern evaluation
- SOLID principles verification
- Performance bottleneck identification
- Documentation completeness checks

### ⚡ Performance Optimizer
**File**: [`performance-optimizer.md`](performance-optimizer.md)

Expert performance analyst specializing in profiling, benchmarking, and optimization strategies.

**When to Invoke**:
- Performance issue investigation
- Scalability planning
- Database query optimization
- Memory leak detection
- API latency reduction

**Key Expertise**:
- CPU and memory profiling
- Database query optimization
- Async/await performance tuning
- Caching strategy design
- Algorithm complexity analysis

## How to Use Agents

### Direct Invocation
Reference an agent in your conversation with Claude Code:

```
"Can the Python Specialist review this async implementation?"
"Ask the Security Auditor to check for vulnerabilities in this authentication code"
"Have the Performance Optimizer analyze this database query"
```

### Automatic Invocation
Agents are automatically invoked based on context:
- Security issues → Security Auditor
- Performance problems → Performance Optimizer
- Test failures → Testing Expert
- Code review requests → Code Reviewer
- Python questions → Python Specialist

### Multi-Agent Collaboration
Agents work together on complex tasks:

```
Example: Optimizing a slow API endpoint
1. Performance Optimizer identifies bottleneck
2. Code Reviewer suggests architectural improvements
3. Python Specialist implements async patterns
4. Testing Expert adds performance tests
5. Security Auditor validates security implications
```

## Agent Capabilities

### Context Tracking
Each agent maintains awareness of:
- Project structure and organization
- Existing code patterns and conventions
- Historical issues and resolutions
- Performance baselines and metrics
- Security posture and vulnerabilities
- Test coverage and quality metrics

### Analysis Tools
Agents have access to:
- File reading and writing
- Code search and pattern matching
- Command execution for profiling/testing
- Diff generation for changes
- Integration with external tools (GitHub, etc.)

### Recommendation Format
All agents provide structured recommendations:
- **Issue Description**: Clear problem statement
- **Severity/Priority**: Impact assessment
- **Current State**: Baseline code/metrics
- **Recommended Solution**: Detailed improvement
- **Alternatives**: Trade-offs and options
- **Action Items**: Specific next steps

## Integration with Project Rules

Agents work in conjunction with project rules in [`../rules/`](../rules/):

| Agent | Related Rules |
|-------|---------------|
| Python Specialist | [`python-code-style.md`](../rules/python-code-style.md), [`python-async.md`](../rules/python-async.md), [`python-performance.md`](../rules/python-performance.md) |
| Testing Expert | [`python-testing.md`](../rules/python-testing.md) |
| Security Auditor | [`python-security.md`](../rules/python-security.md) |
| Code Reviewer | All rules files |
| Performance Optimizer | [`python-performance.md`](../rules/python-performance.md), [`python-async.md`](../rules/python-async.md) |

## Best Practices

### When to Use Agents

✅ **Good Use Cases**:
- Complex problems requiring domain expertise
- Code reviews and quality assessments
- Performance optimization and profiling
- Security audits and vulnerability scanning
- Test strategy and coverage improvement
- Architecture and design decisions

❌ **Not Ideal For**:
- Simple syntax questions (use rules instead)
- Basic documentation lookup
- Trivial code changes
- General conversation

### Effective Agent Interaction

1. **Be Specific**: Provide context about the problem
2. **Share Code**: Include relevant code snippets
3. **State Goals**: Clarify what you want to achieve
4. **Mention Constraints**: Note any limitations or requirements
5. **Request Alternatives**: Ask for multiple approaches when appropriate

### Example Interactions

**Good**:
```
"Security Auditor: Review this JWT implementation for OWASP compliance.
We're using HS256 and storing tokens in localStorage. Are there any
security concerns with this approach?"
```

**Better**:
```
"Security Auditor: Review the authentication system in auth/jwt.py.
We need to ensure OWASP A02:2021 compliance. Current implementation
uses HS256 with 15-minute expiration. We're considering moving to RS256.
What are the security implications and recommendations?"
```

## Agent Collaboration Patterns

### Sequential Collaboration
Agents work in sequence for complex tasks:
```
1. Code Reviewer identifies design issues
2. Python Specialist suggests refactoring
3. Testing Expert adds test coverage
4. Security Auditor validates security
5. Performance Optimizer benchmarks changes
```

### Parallel Collaboration
Multiple agents analyze different aspects simultaneously:
```
- Security Auditor: Check for vulnerabilities
- Performance Optimizer: Profile execution time
- Testing Expert: Assess test coverage
→ Comprehensive analysis in single pass
```

### Iterative Collaboration
Agents refine solutions through multiple iterations:
```
1. Python Specialist proposes solution
2. Code Reviewer suggests improvements
3. Python Specialist refines approach
4. Testing Expert validates with tests
5. Performance Optimizer confirms no regression
```

## Extending the Agent System

To add a new agent:

1. **Create Agent File**: `new-agent.md` with frontmatter
2. **Define Expertise**: List specific knowledge domains
3. **Specify Tools**: Available tools for the agent
4. **Document Approach**: Analysis methodology
5. **Add Examples**: Real-world interaction scenarios
6. **Update README**: Add agent to this documentation

### Agent Template

```markdown
---
name: Agent Name
description: Brief description of expertise
tools: [read_file, write_to_file, apply_diff, search_files, execute_command]
model: claude-4-sonnet
context_tracking: true
expertise_areas: [area1, area2, area3]
---

# Agent Name

## Expertise Areas
- Detailed expertise list

## When to Invoke
- Specific scenarios

## Context Maintained
- Project context tracked

## Analysis Approach
- Methodology steps

## Recommendations Format
- Output structure

## Example Interactions
- Real-world examples

## Integration Points
- Collaboration with other agents
```

## Technical Specification Alignment

These agents implement the AI-Assisted Development features described in **Technical Specification Section 9.1**:

- **Context-Aware Assistance**: Agents maintain project context
- **Specialized Expertise**: Domain-specific knowledge and guidance
- **Code Quality**: Automated review and improvement suggestions
- **Security Analysis**: Vulnerability detection and secure coding
- **Performance Optimization**: Profiling and optimization recommendations
- **Testing Guidance**: Test strategy and coverage improvement

## Support and Feedback

For questions or suggestions about the agent system:
- Review agent documentation in this directory
- Check project rules in [`../rules/`](../rules/)
- Refer to Technical Specification Section 9
- Provide feedback through project issues

---

**Note**: Agents are powered by Claude AI and provide recommendations based on best practices, project context, and industry standards. Always review and validate agent suggestions before implementation.
