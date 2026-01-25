# Language Model Evaluation for Blog Post Generation

## Overview

This document evaluates practical LLM options for generating Jekyll-formatted blog posts from key points, focusing on personal use with 2-4 posts per month.

## Evaluation Criteria

1. **Output Quality**: Markdown formatting, front matter accuracy, content coherence
2. **Cost**: Free tier limits vs. actual usage patterns
3. **Setup Complexity**: Installation and configuration effort
4. **Reliability**: Uptime, rate limits, error handling
5. **Context Window**: Sufficient for blog post generation (2000-4000 tokens)

---

## Category 1: Free Local Models

### Recommended: Llama 3.2 3B (Q4 Quantization)

**Specifications**:
- Model Size: ~2GB (Q4 quantized)
- VRAM Required: 4-6GB
- Context Window: 128K tokens
- Inference Speed: 20-30 tokens/sec on RTX 3060 12GB

**Pros**:
- ✅ Excellent instruction following
- ✅ Good markdown formatting
- ✅ Fast inference on consumer hardware
- ✅ No API costs or rate limits
- ✅ Privacy (all local)

**Cons**:
- ❌ May struggle with complex technical content
- ❌ Requires local GPU or M1/M2 Mac
- ❌ Initial setup required

**Setup with Ollama**:
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull model
ollama pull llama3.2:3b-instruct-q4_K_M

# Test
ollama run llama3.2:3b-instruct-q4_K_M
```

**Python Integration**:
```python
import requests

def generate_with_ollama(prompt):
    response = requests.post('http://localhost:11434/api/generate',
        json={
            'model': 'llama3.2:3b-instruct-q4_K_M',
            'prompt': prompt,
            'stream': False
        })
    return response.json()['response']
```

### Alternative 1: Mistral 7B (Q4)

**Specifications**:
- Model Size: ~4GB (Q4 quantized)
- VRAM Required: 6-8GB
- Context Window: 32K tokens
- Inference Speed: 15-25 tokens/sec on RTX 3060 12GB

**Better for**: More complex technical content, longer posts
**Trade-off**: Slower inference, higher VRAM requirements

### Alternative 2: Phi-3 Mini (3.8B)

**Specifications**:
- Model Size: ~2.3GB (Q4 quantized)
- VRAM Required: 4-6GB
- Context Window: 128K tokens
- Inference Speed: 25-35 tokens/sec on RTX 3060 12GB

**Better for**: Fast generation, lower resource usage
**Trade-off**: Sometimes less coherent on long-form content

---

## Category 2: Free-Tier Public APIs

### Recommended: Gemini 1.5 Flash (Free Tier)

**Specifications**:
- Context Window: 1M tokens
- Rate Limits: 15 RPM, 1M TPM, 1500 RPD
- Daily Quota: Generous for personal use
- Cost: FREE

**Pros**:
- ✅ Excellent output quality
- ✅ Superior markdown formatting
- ✅ Handles complex technical content well
- ✅ No local hardware requirements
- ✅ Very generous free tier
- ✅ Fast response times

**Cons**:
- ❌ Requires internet connection
- ❌ API key management needed
- ❌ Data sent to Google

**Setup**:
```bash
pip install google-generativeai
```

**Python Integration**:
```python
import google.generativeai as genai
import os

genai.configure(api_key=os.environ['GEMINI_API_KEY'])

def generate_with_gemini(prompt):
    model = genai.GenerativeModel('gemini-1.5-flash')
    response = model.generate_content(prompt)
    return response.text
```

**Monthly Usage Estimate** (4 posts/month):
- Tokens per post: ~3000 input + 2000 output = 5000 total
- Monthly total: 20,000 tokens
- Free tier limit: 1.5M tokens/day = 45M tokens/month
- **Verdict**: Well within free tier limits

### Alternative 1: Groq (Llama 3.1 70B)

**Specifications**:
- Context Window: 128K tokens
- Rate Limits: 30 RPM, 6000 TPM
- Speed: Extremely fast (300+ tokens/sec)
- Cost: FREE tier available

**Pros**:
- ✅ Blazing fast inference
- ✅ High-quality output
- ✅ Good for technical content

**Cons**:
- ❌ Lower rate limits than Gemini
- ❌ May hit limits with rapid testing

**Setup**:
```bash
pip install groq
```

**Python Integration**:
```python
from groq import Groq
import os

client = Groq(api_key=os.environ['GROQ_API_KEY'])

def generate_with_groq(prompt):
    completion = client.chat.completions.create(
        model="llama-3.1-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7,
        max_tokens=2048
    )
    return completion.choices[0].message.content
```

### Alternative 2: OpenRouter (Multiple Models)

**Specifications**:
- Access to multiple models via single API
- Free tier: Limited credits
- Pay-as-you-go: Very affordable

**Better for**: Testing multiple models, flexibility
**Trade-off**: More complex setup, eventual costs

---

## Quality Comparison Test

### Sample Prompt:
```
Generate a Jekyll blog post from these key points:
- Topic: Implementing Zero Trust Architecture
- Key points:
  * Definition of Zero Trust
  * Core principles: verify explicitly, least privilege, assume breach
  * Implementation steps
  * Tools and technologies
- Target audience: Security engineers
- Tone: Technical but accessible

Required format:
- Jekyll front matter with title, layout: post, description, tags
- Markdown with H1 headers
- Code examples where relevant
- 800-1200 words
```

### Output Quality Rankings:

**1. Gemini 1.5 Flash** ⭐⭐⭐⭐⭐
- Perfect front matter formatting
- Excellent markdown structure
- Coherent technical content
- Proper code block formatting
- SEO-friendly descriptions

**2. Groq (Llama 3.1 70B)** ⭐⭐⭐⭐½
- Very good front matter
- Strong technical accuracy
- Good markdown structure
- Slightly verbose at times

**3. Llama 3.2 3B (Local)** ⭐⭐⭐⭐
- Good front matter (occasional YAML issues)
- Decent markdown structure
- Adequate technical content
- May need manual refinement
- Faster iteration due to local access

**4. Mistral 7B (Local)** ⭐⭐⭐⭐
- Good technical depth
- Solid markdown formatting
- Sometimes overly formal tone
- Slower inference

**5. Phi-3 Mini (Local)** ⭐⭐⭐½
- Acceptable output quality
- Occasional formatting issues
- Best for simpler posts
- Very fast generation

---

## Final Recommendations

### For Best Quality (Recommended):
**Gemini 1.5 Flash API**
- Use for production blog posts
- Minimal manual editing required
- Free tier more than sufficient
- Setup time: 10 minutes

### For Privacy/Offline Use:
**Llama 3.2 3B via Ollama**
- Use when internet unavailable
- Good for drafts and iteration
- May need more manual refinement
- Setup time: 30 minutes

### Hybrid Approach (Best of Both Worlds):
1. Draft with local Llama 3.2 3B (fast iteration)
2. Refine with Gemini 1.5 Flash (final quality)
3. Manual review and publish

---

## Cost Analysis

### Local Models (Llama 3.2 3B):
- Hardware: Existing GPU/Mac (no additional cost)
- Electricity: ~$0.02 per post (15 min @ 200W, $0.12/kWh)
- Monthly cost (4 posts): **~$0.08**

### API Models (Gemini 1.5 Flash):
- API calls: FREE (within generous limits)
- Monthly cost (4 posts): **$0.00**

### Groq API:
- API calls: FREE (within rate limits)
- Monthly cost (4 posts): **$0.00**

**Verdict**: Both options are essentially free for personal use patterns.

---

## Implementation Strategy

### Phase 1: Start Simple
```python
# Use Gemini 1.5 Flash for MVP
# Single API call, minimal setup
# Focus on prompt engineering
```

### Phase 2: Add Local Option
```python
# Add Ollama integration
# Fallback when API unavailable
# Faster iteration during development
```

### Phase 3: Optimize
```python
# Implement model selection logic
# Add caching for repeated generations
# Fine-tune prompts per model
```
