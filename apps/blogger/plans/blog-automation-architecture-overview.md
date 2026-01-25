# Blog Post Automation Architecture - Overview

## Executive Summary

This document provides an architectural review for an automated blog post generation system that transforms user-provided key points into complete Jekyll-formatted blog posts using agentic AI and Model Context Protocol (MCP).

**Target Platform**: Jekyll static site on GitHub Pages
**Use Case**: Personal blogging (2-4 posts/month)
**Focus**: Simplicity, practicality, maintainability

## Architecture Components Summary

The proposed system consists of three main layers:

1. **Orchestration Layer**: Coordinates user input, LLM processing, and GitHub operations
2. **Language Model Layer**: Generates blog content from key points
3. **GitHub Integration Layer**: Handles file creation, commits, and deployment

## Jekyll Blog Analysis

Based on your existing blog structure:

### Required Front Matter Format
```yaml
---
title: [Post Title]
layout: post
post-image: "/assets/images/[category]/[image-file]"
description: [Brief description for SEO]
tags:
- [tag1]
- [tag2]
- [tag3]
- blog
---
```

### File Naming Convention
- Pattern: `YYYY-MM-DD-title-with-hyphens.md`
- Location: `_posts/` directory
- Examples: `2024-03-10-ai-security-poc-using-llm-guard.md`

### Content Structure Patterns
From your existing posts:
- H1 headers for main sections
- Code blocks with language specification
- Image references with alt text
- External links to GitHub repositories
- Bullet points for lists
- Inline code formatting with backticks

## Recommended Architecture: Simplified Approach

**Verdict**: For personal use, a **custom Python-based solution** is more appropriate than using Roo Code as the orchestrator.

### Why Custom Python Over Roo Code:

✅ **Simpler Setup**: Single Python script vs. complex IDE integration
✅ **Better Control**: Direct control over MCP server interactions
✅ **Easier Debugging**: Standard Python debugging tools
✅ **Lower Overhead**: No IDE dependencies
✅ **Portable**: Run from any environment with Python

### Architecture Diagram (Text Description)

```
┌─────────────────────────────────────────────────────────────┐
│                        User Input                            │
│              (Key points as bullet list)                     │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Python Orchestrator Script                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  1. Parse input                                       │  │
│  │  2. Generate prompt with Jekyll template             │  │
│  │  3. Call LLM via MCP or direct API                   │  │
│  │  4. Validate markdown output                         │  │
│  │  5. Create filename with date                        │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   Language Model                             │
│         (Local: Ollama OR API: Gemini/Groq)                 │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              GitHub MCP Server                               │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  1. Create file in _posts/                           │  │
│  │  2. Commit with message                              │  │
│  │  3. Push to main branch                              │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              GitHub Pages Deployment                         │
│            (Automatic Jekyll build & deploy)                 │
└─────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

1. **Single Python Script**: All orchestration logic in one maintainable file
2. **Flexible LLM Backend**: Support both local (Ollama) and API-based models
3. **Direct GitHub Integration**: Use GitHub MCP server for all git operations
4. **Manual Preview Option**: Generate locally first, review, then commit
5. **Simple Error Handling**: Retry logic with clear error messages

## Next Steps

Refer to the following detailed documents:
- `blog-automation-llm-evaluation.md` - Language model recommendations
- `blog-automation-github-integration.md` - GitHub MCP setup and workflow
- `blog-automation-implementation.md` - Code examples and setup
- `blog-automation-challenges.md` - Risks and mitigation strategies
- `blog-automation-roadmap.md` - Implementation phases and timeline

## Quick Start Recommendation

**Phase 1 MVP** (Weekend project):
1. Python script that takes bullet points as input
2. Calls Gemini 1.5 Flash API (free tier)
3. Generates markdown with proper front matter
4. Saves to `_posts/` directory locally
5. Manual git commit and push

**Phase 2 Enhancement** (Following weekend):
1. Add GitHub MCP server integration
2. Implement automated commit/push
3. Add local Ollama support as alternative
4. Improve error handling and validation
