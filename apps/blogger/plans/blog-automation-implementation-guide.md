# Blog Automation - Implementation Guide

## Minimal Working Implementation

This document provides a complete, working implementation of the blog post automation system.

## Prerequisites

```bash
# Python 3.9+
python --version

# Install dependencies
pip install google-generativeai pyyaml python-dotenv
```

## Environment Setup

Create `.env` file:
```bash
GEMINI_API_KEY=your_api_key_here
GITHUB_PERSONAL_ACCESS_TOKEN=ghp_your_token_here
GITHUB_OWNER=trantdai
GITHUB_REPO=trantdai.github.io
```

Add to `.gitignore`:
```
.env
*.pyc
__pycache__/
```

## Core Implementation

### File: `blog_generator.py`

```python
#!/usr/bin/env python3
"""
Automated Blog Post Generator for Jekyll
Generates blog posts from key points using Gemini API
"""

import os
import re
from datetime import datetime
from pathlib import Path
import yaml
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class BlogPostGenerator:
    def __init__(self):
        """Initialize the blog post generator"""
        self.api_key = os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found in environment")

        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')

    def sanitize_filename(self, title):
        """Convert title to valid filename"""
        clean = re.sub(r'[^\w\s-]', '', title.lower())
        clean = re.sub(r'[-\s]+', '-', clean)
        return clean.strip('-')

    def generate_prompt(self, title, key_points, tags=None):
        """Generate LLM prompt with Jekyll template"""
        tags_list = tags or ['blog', 'technical']
        tags_yaml = '\n'.join([f'- {tag}' for tag in tags_list])

        prompt = f"""Generate a professional technical blog post in Jekyll markdown format.

Title: {title}

Key Points to Cover:
{key_points}

Requirements:
1. Start with YAML front matter in this exact format:
---
title: {title}
layout: post
post-image: "/assets/images/blog/default.png"
description: [Write a concise 1-sentence SEO description]
tags:
{tags_yaml}
---

2. After front matter, write a complete blog post with:
   - Clear H1 headers for main sections
   - Technical depth appropriate for engineers
   - Code examples in fenced code blocks with language tags
   - Bullet points for lists
   - Professional but accessible tone
   - 800-1200 words

3. Use proper markdown formatting:
   - Headers: # H1, ## H2, ### H3
   - Code blocks: ```language
   - Links: [text](url)
   - Bold: **text**
   - Italic: *text*

Generate the complete blog post now:"""

        return prompt

    def generate_content(self, title, key_points, tags=None):
        """Generate blog post content using Gemini"""
        print(f"🤖 Generating content for: {title}")

        prompt = self.generate_prompt(title, key_points, tags)

        try:
            response = self.model.generate_content(prompt)
            content = response.text
            print("✅ Content generated successfully")
            return content
        except Exception as e:
            print(f"❌ Error generating content: {e}")
            raise

    def validate_front_matter(self, content):
        """Validate YAML front matter"""
        if not content.startswith('---'):
            return False, "Missing front matter delimiter"

        parts = content.split('---', 2)
        if len(parts) < 3:
            return False, "Incomplete front matter"

        try:
            front_matter = yaml.safe_load(parts[1])
            required_fields = ['title', 'layout', 'description', 'tags']

            for field in required_fields:
                if field not in front_matter:
                    return False, f"Missing required field: {field}"

            return True, "Valid front matter"
        except yaml.YAMLError as e:
            return False, f"YAML error: {str(e)}"

    def save_locally(self, title, content):
        """Save blog post to _posts directory"""
        # Generate filename
        date_str = datetime.now().strftime('%Y-%m-%d')
        title_slug = self.sanitize_filename(title)
        filename = f"{date_str}-{title_slug}.md"

        # Ensure _posts directory exists
        posts_dir = Path('_posts')
        posts_dir.mkdir(exist_ok=True)

        # Save file
        filepath = posts_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"📝 Saved to: {filepath}")
        return str(filepath)

    def generate_and_save(self, title, key_points, tags=None):
        """Complete workflow: generate and save blog post"""
        # Generate content
        content = self.generate_content(title, key_points, tags)

        # Validate
        is_valid, message = self.validate_front_matter(content)
        if not is_valid:
            print(f"⚠️  Warning: {message}")
            print("Continuing anyway...")

        # Save locally
        filepath = self.save_locally(title, content)

        print("\n✅ Blog post generated successfully!")
        print(f"📄 File: {filepath}")
        print("\n🔍 Next steps:")
        print("1. Review the generated content")
        print("2. Run 'bundle exec jekyll serve' to preview")
        print("3. Commit and push to GitHub when ready")

        return filepath


def main():
    """Main entry point"""
    # Example usage
    generator = BlogPostGenerator()

    title = "Getting Started with MCP Servers"

    key_points = """
    - What is Model Context Protocol (MCP)
    - Benefits of using MCP servers
    - Setting up your first MCP server
    - Example: GitHub MCP server integration
    - Best practices for MCP development
    """

    tags = ['mcp', 'ai', 'automation', 'blog']

    generator.generate_and_save(title, key_points, tags)


if __name__ == '__main__':
    main()
```

## Usage Examples

### Example 1: Basic Usage

```python
from blog_generator import BlogPostGenerator

generator = BlogPostGenerator()

title = "Kubernetes Security Best Practices"
key_points = """
- Pod security policies
- Network policies
- RBAC configuration
- Secrets management
- Image scanning
"""
tags = ['kubernetes', 'security', 'devops', 'blog']

generator.generate_and_save(title, key_points, tags)
```

### Example 2: Interactive CLI

Create `generate_blog.py`:

```python
#!/usr/bin/env python3
from blog_generator import BlogPostGenerator

def interactive_mode():
    """Interactive blog post generation"""
    print("=== Blog Post Generator ===\n")

    title = input("Enter blog post title: ")

    print("\nEnter key points (one per line, empty line to finish):")
    key_points_list = []
    while True:
        point = input("- ")
        if not point:
            break
        key_points_list.append(f"- {point}")

    key_points = '\n'.join(key_points_list)

    tags_input = input("\nEnter tags (comma-separated): ")
    tags = [tag.strip() for tag in tags_input.split(',')]
    tags.append('blog')  # Always add 'blog' tag

    generator = BlogPostGenerator()
    generator.generate_and_save(title, key_points, tags)

if __name__ == '__main__':
    interactive_mode()
```

Run it:
```bash
chmod +x generate_blog.py
./generate_blog.py
```

### Example 3: Batch Generation

```python
from blog_generator import BlogPostGenerator

generator = BlogPostGenerator()

blog_posts = [
    {
        'title': 'Docker Security Hardening',
        'key_points': '- Base image selection\n- Multi-stage builds\n- User permissions',
        'tags': ['docker', 'security', 'blog']
    },
    {
        'title': 'Terraform State Management',
        'key_points': '- Remote state\n- State locking\n- Sensitive data',
        'tags': ['terraform', 'iac', 'blog']
    }
]

for post in blog_posts:
    generator.generate_and_save(**post)
    print("\n" + "="*50 + "\n")
```

## Testing

### Test Script: `test_generator.py`

```python
import unittest
from blog_generator import BlogPostGenerator

class TestBlogGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = BlogPostGenerator()

    def test_sanitize_filename(self):
        """Test filename sanitization"""
        title = "Hello World! Test #123"
        result = self.generator.sanitize_filename(title)
        self.assertEqual(result, "hello-world-test-123")

    def test_validate_front_matter_valid(self):
        """Test valid front matter"""
        content = """---
title: Test Post
layout: post
description: A test post
tags:
- test
---

# Content here
"""
        is_valid, message = self.generator.validate_front_matter(content)
        self.assertTrue(is_valid)

    def test_validate_front_matter_invalid(self):
        """Test invalid front matter"""
        content = "# Just a header"
        is_valid, message = self.generator.validate_front_matter(content)
        self.assertFalse(is_valid)

if __name__ == '__main__':
    unittest.main()
```

Run tests:
```bash
python test_generator.py
```

## Local Preview Workflow

```bash
# 1. Generate blog post
python blog_generator.py

# 2. Start Jekyll server
bundle exec jekyll serve

# 3. Open browser
open http://localhost:4000

# 4. Review the post

# 5. If satisfied, commit
git add _posts/2026-01-11-your-post.md
git commit -m "docs: add blog post about X"
git push origin main
```

## Error Handling

The implementation includes basic error handling:

1. **Missing API Key**: Raises ValueError with clear message
2. **API Failures**: Catches and reports generation errors
3. **Invalid YAML**: Validates front matter and warns
4. **File System**: Creates directories if needed

## Performance

Typical execution times:
- API call: 3-8 seconds
- Validation: <0.1 seconds
- File save: <0.1 seconds
- **Total: ~5-10 seconds per post**

## Next Steps

See [`blog-automation-github-integration.md`](blog-automation-github-integration.md) for:
- Automated GitHub commit/push
- GitHub MCP server integration
- CI/CD pipeline setup
