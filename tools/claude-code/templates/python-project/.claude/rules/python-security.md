# Python Security Rules

## Security Principles
Defense in Depth, Least Privilege, Fail Securely, Zero Trust

## Input Validation

**Mandatory**: Use Pydantic for all data at trust boundaries.

**Rules:**
- Sanitize inputs (remove null bytes, HTML escape)
- Validate URL schemes (http/https only)
- Sanitize file paths (prevent directory traversal)
- Limit input length

**File Uploads:**
- Whitelist extensions: .txt, .pdf, .png, .jpg, .jpeg, .gif
- Validate MIME types (content, not extension)
- Max file size (10MB)

## Authentication & Authorization

**Passwords:**
- Bcrypt with 12+ rounds
- Minimum 12 characters

**JWT:**
- Access: 15min, Refresh: 7 days max
- Include: `exp`, `iat`, `jti`
- Strong secret: 32+ characters
- Algorithm: HS256 or RS256

**Sessions:**
- Timeout: 2 hours max
- Cookies: `HttpOnly`, `Secure`, `SameSite=Strict`

## Secrets Management

✅ **DO**: Environment variables
```python
import os
secret_key = os.getenv("SECRET_KEY")
if not secret_key or len(secret_key) < 32:
    raise ValueError("SECRET_KEY must be ≥32 chars")
```

❌ **DON'T**: Hardcode secrets

**Production**: Use Vault, AWS Secrets Manager, or Azure Key Vault

## Cryptography

- **Symmetric**: Fernet
- **Key derivation**: PBKDF2HMAC with 100,000+ iterations
- **Random**: `secrets` module (never `random`)

```python
from cryptography.fernet import Fernet
import secrets

cipher = Fernet(Fernet.generate_key())
token = secrets.token_urlsafe(32)
```

## Common Vulnerabilities

**SQL Injection:**
✅ Parameterized queries
```python
query = text("SELECT * FROM users WHERE id = :user_id")
result = connection.execute(query, {"user_id": user_id})
```

**XSS:**
```python
import html
sanitized = html.escape(user_input, quote=True)
```

**Security Headers:**
`Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`

**CSRF:**
CSRF tokens, `SameSite` cookies, verify Origin/Referer

**SSRF:**
Block private IPs (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16), whitelist schemes

**Path Traversal:**
```python
from pathlib import Path

def safe_join(base: str, *components: str) -> Path:
    base_path = Path(base).resolve()
    target = (base_path / Path(*components)).resolve()
    try:
        target.relative_to(base_path)
        return target
    except ValueError:
        raise ValueError("Path traversal detected")
```

## Dependency Security

```bash
pip-audit
safety check
bandit -r src/
```

Run on every PR, fail on high-severity.

## Secure Logging

**Log**: Failed auth, permission errors, suspicious activity
**Never Log**: Passwords, tokens, secrets, API keys

## Security Checklist

- [ ] Pydantic validates all inputs
- [ ] Passwords hashed (bcrypt 12+)
- [ ] Secrets in env vars
- [ ] HTTPS enforced
- [ ] Security headers configured
- [ ] SQL queries parameterized
- [ ] XSS prevention
- [ ] Rate limiting
- [ ] Dependencies scanned
