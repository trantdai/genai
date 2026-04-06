# Python Security Rules

## Overview
Security must be considered at every development stage. All code must follow these practices to protect against common vulnerabilities.

## Security Principles
- **Defense in Depth**: Multiple layers of security controls
- **Principle of Least Privilege**: Grant minimum necessary permissions
- **Fail Securely**: Failures don't compromise security
- **Input Validation**: Validate all inputs at trust boundaries
- **Output Encoding**: Properly encode outputs to prevent injection
- **Secure by Default**: Use secure configurations as defaults
- **Zero Trust**: Verify everything, trust nothing

## Input Validation

### Pydantic for Data Validation
**Mandatory**: Use Pydantic for all data validation at trust boundaries.

```python
from pydantic import BaseModel, EmailStr, validator

class UserRegistration(BaseModel):
    email: EmailStr
    username: str
    password: str
    
    @validator('username')
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', v):
            raise ValueError('Invalid username format')
        return v
    
    @validator('password')
    def validate_password_strength(cls, v):
        if len(v) < 12:
            raise ValueError('Password must be at least 12 characters')
        # Additional strength checks...
        return v
```

### Input Sanitization Rules
- Remove null bytes (`\x00`)
- HTML escape user inputs
- Remove dangerous characters for context
- Limit input length to prevent DoS
- Validate URL schemes (allow only http/https)
- Sanitize file paths (prevent directory traversal)

### File Upload Validation
- **Whitelist allowed extensions**: `.txt`, `.pdf`, `.png`, `.jpg`, `.jpeg`, `.gif`
- **Validate MIME types**: Check actual content, not just extension
- **Maximum file size**: Enforce limits (e.g., 10MB)
- **Scan for malware**: Check for suspicious content patterns
- **Safe filename**: Remove path components, dangerous characters, null bytes

## Authentication and Authorization

### Password Security
**Mandatory**: Use bcrypt with 12+ rounds for password hashing.

```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], bcrypt__rounds=12)

def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    if len(password) < 12:
        raise ValueError("Password too short")
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        # Prevent timing attacks
        pwd_context.hash("dummy_password")
        return False
```

❌ **DON'T**: Use weak hashing
- Never use MD5 or SHA-1 for passwords
- Don't use plain SHA-256 without salt
- Never store passwords in plain text

### JWT Token Management
- **Short-lived access tokens**: 15 minutes
- **Longer refresh tokens**: 7 days maximum
- **Include standard claims**: `exp`, `iat`, `jti` (for blacklisting)
- **Strong secret key**: Minimum 32 characters
- **Algorithm**: Use HS256 or RS256

```python
import jwt
from datetime import datetime, timedelta, timezone

def create_access_token(data: dict, secret_key: str) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access"
    })
    
    return jwt.encode(to_encode, secret_key, algorithm="HS256")
```

### Session Management
- **Session timeout**: 2 hours maximum
- **Validate user agent**: Detect session hijacking
- **Log IP changes**: Monitor for suspicious activity
- **Session limit**: Maximum 3 sessions per user
- **Secure cookies**: `HttpOnly`, `Secure`, `SameSite=Strict` flags

### Role-Based Access Control (RBAC)
- Define clear permission hierarchy
- Implement permission checks at function level
- Use decorators for permission enforcement
- Audit permission changes

```python
from enum import Enum
from functools import wraps

class Permission(Enum):
    READ_USER = "read_user"
    WRITE_USER = "write_user"
    DELETE_USER = "delete_user"

def require_permission(permission: Permission):
    """Decorator to require specific permission."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_user = get_current_user()
            if not current_user.has_permission(permission):
                raise PermissionError(f"Permission required: {permission.value}")
            return func(*args, **kwargs)
        return wrapper
    return decorator
```

### Multi-Factor Authentication (MFA)
- **TOTP-based MFA**: Use `pyotp` library
- **Backup codes**: Generate 10 one-time recovery codes
- **QR code setup**: For authenticator apps
- **Verify with tolerance**: Allow 30-second window

## Secrets Management

### Environment Variables
✅ **DO**: Store secrets in environment variables
```python
import os

class Settings:
    def __init__(self):
        self.secret_key = os.getenv("SECRET_KEY")
        self.jwt_secret = os.getenv("JWT_SECRET_KEY")
        self.db_password = os.getenv("DB_PASSWORD")
        
        self._validate_secrets()
    
    def _validate_secrets(self):
        """Validate required secrets are present and strong."""
        if not self.secret_key or len(self.secret_key) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
```

❌ **DON'T**: Hardcode secrets
```python
# Never do this
DATABASE_URL = "postgresql://user:password123@localhost/mydb"
API_KEY = "sk-1234567890abcdef"
SECRET_KEY = "my-secret-key"
```

### Production Secrets Management
- **HashiCorp Vault**: For production environments
- **AWS Secrets Manager**: For AWS deployments
- **Azure Key Vault**: For Azure deployments
- **Never commit secrets**: Use `.gitignore` for sensitive files

## Cryptography

### Encryption Standards
- **Use Fernet**: For symmetric encryption (cryptography library)
- **Key derivation**: PBKDF2HMAC with 100,000+ iterations
- **Random generation**: Use `secrets` module (never `random`)

```python
from cryptography.fernet import Fernet
import secrets

# Generate secure key
key = Fernet.generate_key()

# Encrypt data
cipher_suite = Fernet(key)
encrypted_data = cipher_suite.encrypt(b"sensitive data")

# Secure random token
secure_token = secrets.token_urlsafe(32)
```

❌ **DON'T**: Use weak cryptography
- Don't use `random` module for security
- Don't implement custom crypto algorithms
- Don't use deprecated algorithms (DES, RC4, MD5)

## Common Vulnerabilities Prevention

### SQL Injection
✅ **DO**: Use parameterized queries
```python
# Safe - parameterized query
query = text("SELECT * FROM users WHERE id = :user_id")
result = connection.execute(query, {"user_id": user_id})
```

❌ **DON'T**: Use string formatting
```python
# Vulnerable - SQL injection
query = f"SELECT * FROM users WHERE id = '{user_id}'"
```

### Cross-Site Scripting (XSS)
✅ **DO**: Escape HTML output
```python
import html

def sanitize_user_input(user_input: str) -> str:
    """Sanitize input to prevent XSS."""
    return html.escape(user_input, quote=True)
```

**Content Security Policy Headers**:
- `Content-Security-Policy`: Restrict resource loading
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`

### Cross-Site Request Forgery (CSRF)
- **CSRF tokens**: For state-changing operations
- **SameSite cookies**: `SameSite=Strict` or `Lax`
- **Verify Origin/Referer**: For additional protection
- **Token lifetime**: Short-lived tokens (1 hour)

### Server-Side Request Forgery (SSRF)
✅ **DO**: Validate outbound requests
- Block private IP ranges (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16)
- Block localhost access
- Whitelist allowed schemes (http, https only)
- Validate URLs before making requests

### Path Traversal
✅ **DO**: Validate file paths
```python
from pathlib import Path

def safe_join(base_directory: str, *path_components: str) -> Path:
    """Safely join paths and validate result."""
    base = Path(base_directory).resolve()
    target = (base / Path(*path_components)).resolve()
    
    # Verify target is within base directory
    try:
        target.relative_to(base)
        return target
    except ValueError:
        raise ValueError("Path traversal detected")
```

## Dependency Security

### Dependency Management
```toml
[tool.poetry.dependencies]
python = "^3.11"
fastapi = ">=0.104.0"  # Use minimum version constraints
cryptography = ">=41.0.0"  # Security-critical packages need updates
bcrypt = "~4.0.1"  # Pin security-critical more strictly
```

### Vulnerability Scanning
```bash
# Scan dependencies
pip-audit --requirement requirements.txt

# Alternative scanner
safety check

# Security linter
bandit -r src/
```

### CI/CD Security Integration
- Run security scans on every PR
- Fail builds on high-severity vulnerabilities
- Monitor for security advisories
- Update dependencies regularly

## Secure Logging

### Log Security Events
- Failed authentication attempts
- Permission errors
- Suspicious activities
- Rate limit violations

### Don't Log Sensitive Data
- **Never log**: Passwords, tokens, secrets, API keys, credit cards
- **Sanitize**: Remove sensitive fields before logging
- **Mask**: Partially hide user IDs, IP addresses (GDPR compliance)

```python
def log_security_event(event_type: str, user_id: str, details: dict):
    """Log security event without sensitive data."""
    sanitized_details = {
        k: "[REDACTED]" if k in {"password", "token", "secret"} else v
        for k, v in details.items()
    }
    logger.warning(f"SECURITY_EVENT: {event_type}", extra={
        "user_id": mask_user_id(user_id),
        "details": sanitized_details
    })
```

## Security Checklist

Before deployment:
- [ ] All inputs validated with Pydantic
- [ ] Passwords hashed with bcrypt (12+ rounds)
- [ ] Secrets stored in environment variables/vault
- [ ] HTTPS enforced for all communications
- [ ] Security headers configured
- [ ] CSRF protection enabled
- [ ] SQL queries parameterized
- [ ] XSS prevention (output encoding)
- [ ] Rate limiting implemented
- [ ] Logging configured (no sensitive data)
- [ ] Dependencies scanned for vulnerabilities
- [ ] Authentication tested
- [ ] Authorization tested
- [ ] Security audit completed

## References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Python Security](https://owasp.org/www-project-python-security/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [cryptography library](https://cryptography.io/)
- [passlib](https://passlib.readthedocs.io/)
- [pydantic](https://pydantic-docs.helpmanual.io/)
- [bandit](https://bandit.readthedocs.io/)
- [safety](https://pypi.org/project/safety/)
- [pip-audit](https://pypi.org/project/pip-audit/)
