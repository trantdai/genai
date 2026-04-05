# Python Security Rules

## Overview
This document defines comprehensive security standards for Python projects. Security must be considered at every stage of development, from design to deployment. All code must follow these security practices to protect against common vulnerabilities and ensure data protection.

## Security Principles

### Core Security Principles
- **Defense in Depth**: Implement multiple layers of security controls
- **Principle of Least Privilege**: Grant minimum necessary permissions
- **Fail Securely**: Ensure failures don't compromise security
- **Input Validation**: Validate all inputs at trust boundaries
- **Output Encoding**: Properly encode outputs to prevent injection
- **Secure by Default**: Use secure configurations as defaults
- **Zero Trust**: Verify everything, trust nothing

### Security Development Lifecycle
1. **Threat Modeling**: Identify potential security threats
2. **Secure Design**: Design with security in mind
3. **Secure Implementation**: Follow secure coding practices
4. **Security Testing**: Test for vulnerabilities
5. **Security Review**: Peer review for security issues
6. **Monitoring**: Continuous security monitoring

## Input Validation Requirements

### Pydantic for Data Validation
- **Mandatory**: Use Pydantic for all data validation
- **Rationale**: Type safety, automatic validation, serialization security

```python
from pydantic import BaseModel, EmailStr, validator
from typing import Optional
import re

class UserRegistration(BaseModel):
    """Secure user registration model with comprehensive validation."""

    email: EmailStr
    username: str
    password: str
    age: Optional[int] = None
    phone: Optional[str] = None

    @validator('username')
    def validate_username(cls, v):
        """Validate username format and content."""
        if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', v):
            raise ValueError('Username must be 3-20 characters, alphanumeric, underscore, or dash only')

        # Prevent common malicious usernames
        forbidden_names = {'admin', 'root', 'administrator', 'system', 'null', 'undefined'}
        if v.lower() in forbidden_names:
            raise ValueError('Username not allowed')

        return v

    @validator('password')
    def validate_password_strength(cls, v):
        """Enforce strong password requirements."""
        if len(v) < 12:
            raise ValueError('Password must be at least 12 characters long')

        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')

        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')

        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one digit')

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')

        return v

    @validator('age')
    def validate_age(cls, v):
        """Validate age range."""
        if v is not None:
            if v < 13 or v > 120:
                raise ValueError('Age must be between 13 and 120')
        return v

    @validator('phone')
    def validate_phone(cls, v):
        """Validate phone number format."""
        if v is not None:
            # Remove common separators
            cleaned = re.sub(r'[^\d+]', '', v)
            if not re.match(r'^\+?[1-9]\d{1,14}$', cleaned):
                raise ValueError('Invalid phone number format')
        return v
```

### Input Sanitization
✅ **DO**: Sanitize all user inputs
```python
import html
import re
from urllib.parse import quote

def sanitize_user_input(user_input: str) -> str:
    """Sanitize user input to prevent XSS and other attacks."""
    if not isinstance(user_input, str):
        raise ValueError("Input must be a string")

    # Remove null bytes
    sanitized = user_input.replace('\x00', '')

    # HTML escape
    sanitized = html.escape(sanitized, quote=True)

    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\']', '', sanitized)

    # Limit length to prevent DoS
    if len(sanitized) > 1000:
        sanitized = sanitized[:1000]

    return sanitized.strip()

def sanitize_sql_input(input_value: str) -> str:
    """Sanitize input for SQL queries (prefer parameterized queries)."""
    if not isinstance(input_value, str):
        raise ValueError("Input must be a string")

    # Remove SQL injection patterns
    dangerous_patterns = [
        r"(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)",
        r"[';\"\\]",
        r"--",
        r"/\*.*?\*/",
        r"@@\w+",
        r"char\(",
        r"nchar\(",
        r"varchar\(",
        r"nvarchar\(",
        r"alter\(",
        r"begin\(",
        r"cast\(",
        r"create\(",
        r"cursor\(",
        r"declare\(",
        r"delete\(",
        r"drop\(",
        r"end\(",
        r"exec\(",
        r"execute\(",
        r"fetch\(",
        r"insert\(",
        r"kill\(",
        r"open\(",
        r"select\(",
        r"sys",
        r"table",
        r"update\("
    ]

    sanitized = input_value
    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)

    return sanitized.strip()
```

### File Upload Validation
✅ **DO**: Validate file uploads comprehensively
```python
import mimetypes
import os
from pathlib import Path
from typing import BinaryIO, List

ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.doc', '.docx'}
ALLOWED_MIME_TYPES = {
    'text/plain',
    'application/pdf',
    'image/png',
    'image/jpeg',
    'image/gif',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

class FileUploadValidator:
    """Secure file upload validation."""

    @staticmethod
    def validate_file_upload(
        file_content: bytes,
        filename: str,
        max_size: int = MAX_FILE_SIZE
    ) -> dict:
        """
        Validate uploaded file for security.

        Returns:
            dict: Validation result with success status and details
        """
        errors = []

        # Check file size
        if len(file_content) > max_size:
            errors.append(f"File size {len(file_content)} exceeds maximum {max_size}")

        # Validate filename
        if not FileUploadValidator._is_safe_filename(filename):
            errors.append("Filename contains unsafe characters")

        # Check file extension
        file_ext = Path(filename).suffix.lower()
        if file_ext not in ALLOWED_EXTENSIONS:
            errors.append(f"File extension {file_ext} not allowed")

        # Validate MIME type
        mime_type, _ = mimetypes.guess_type(filename)
        if mime_type not in ALLOWED_MIME_TYPES:
            errors.append(f"MIME type {mime_type} not allowed")

        # Check for null bytes (directory traversal)
        if b'\x00' in file_content:
            errors.append("File contains null bytes")

        # Basic malware detection (check for suspicious patterns)
        if FileUploadValidator._contains_suspicious_content(file_content):
            errors.append("File contains suspicious content")

        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'size': len(file_content),
            'mime_type': mime_type
        }

    @staticmethod
    def _is_safe_filename(filename: str) -> bool:
        """Check if filename is safe."""
        # Remove path components
        safe_filename = os.path.basename(filename)

        # Check for dangerous patterns
        dangerous_patterns = [
            '..',           # Directory traversal
            '/',            # Path separator
            '\\',           # Windows path separator
            ':',            # Drive separator (Windows)
            '<', '>', '|',  # Shell metacharacters
            '*', '?',       # Wildcards
            '"', "'",       # Quotes
            '\x00',         # Null byte
        ]

        for pattern in dangerous_patterns:
            if pattern in safe_filename:
                return False

        # Check length
        if len(safe_filename) > 255:
            return False

        # Check for reserved names (Windows)
        reserved_names = {
            'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4',
            'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2',
            'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
        }
        name_without_ext = Path(safe_filename).stem.upper()
        if name_without_ext in reserved_names:
            return False

        return True

    @staticmethod
    def _contains_suspicious_content(content: bytes) -> bool:
        """Basic check for suspicious file content."""
        suspicious_patterns = [
            b'<script',           # JavaScript
            b'javascript:',       # JavaScript URI
            b'<?php',            # PHP code
            b'<%',               # Server-side code
            b'eval(',            # Code evaluation
            b'exec(',            # Code execution
            b'system(',          # System calls
            b'shell_exec(',      # Shell execution
            b'passthru(',        # Command execution
            b'file_get_contents(',  # File access
            b'fopen(',           # File operations
            b'fwrite(',          # File writing
            b'include(',         # File inclusion
            b'require(',         # File inclusion
        ]

        content_lower = content.lower()
        for pattern in suspicious_patterns:
            if pattern in content_lower:
                return True

        return False
```

### URL and Path Validation
✅ **DO**: Validate URLs and file paths
```python
from urllib.parse import urlparse
import os
from pathlib import Path

def validate_url(url: str, allowed_schemes: List[str] = None) -> bool:
    """Validate URL for security."""
    if allowed_schemes is None:
        allowed_schemes = ['http', 'https']

    try:
        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme not in allowed_schemes:
            return False

        # Check for suspicious characters
        if any(char in url for char in ['<', '>', '"', "'"]):
            return False

        # Check for localhost/private IP access (SSRF prevention)
        hostname = parsed.hostname
        if hostname:
            if hostname in ['localhost', '127.0.0.1', '::1']:
                return False

            # Check for private IP ranges
            if hostname.startswith(('10.', '172.', '192.168.')):
                return False

        return True

    except Exception:
        return False

def validate_file_path(file_path: str, base_directory: str) -> bool:
    """Validate file path to prevent directory traversal."""
    try:
        # Resolve both paths
        resolved_base = Path(base_directory).resolve()
        resolved_path = Path(base_directory, file_path).resolve()

        # Check if the resolved path is within the base directory
        return resolved_path.is_relative_to(resolved_base)

    except Exception:
        return False

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage."""
    # Remove path components
    safe_name = os.path.basename(filename)

    # Replace dangerous characters
    safe_name = re.sub(r'[<>:"/\\|?*]', '_', safe_name)

    # Remove control characters
    safe_name = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', safe_name)

    # Limit length
    if len(safe_name) > 255:
        name, ext = os.path.splitext(safe_name)
        safe_name = name[:255-len(ext)] + ext

    # Ensure it's not empty
    if not safe_name or safe_name == '.':
        safe_name = 'unnamed_file'

    return safe_name

## Authentication and Authorization

### Password Security
✅ **DO**: Use secure password hashing
```python
import bcrypt
from passlib.context import CryptContext
import secrets

# Use bcrypt with appropriate rounds (12-15 for 2024)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

class PasswordManager:
    """Secure password management."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt."""
        if len(password) < 12:
            raise ValueError("Password too short")

        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash."""
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except Exception:
            # Prevent timing attacks
            pwd_context.hash("dummy_password")
            return False

    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """Generate cryptographically secure password."""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
```

❌ **DON'T**: Use weak hashing algorithms
```python
import hashlib
import md5  # Don't use

# Wrong - MD5 is cryptographically broken
password_hash = md5.md5(password.encode()).hexdigest()

# Wrong - SHA-1 is also weak
password_hash = hashlib.sha1(password.encode()).hexdigest()

# Wrong - Plain SHA-256 without salt
password_hash = hashlib.sha256(password.encode()).hexdigest()

# Wrong - Custom hashing
password_hash = password + "salt"  # Insecure
```

### JWT Token Management
✅ **DO**: Implement secure JWT handling
```python
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import secrets

class JWTManager:
    """Secure JWT token management."""

    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        if len(secret_key) < 32:
            raise ValueError("JWT secret key must be at least 32 characters")

        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = 15  # Short-lived access tokens
        self.refresh_token_expire_days = 7     # Longer refresh tokens

    def create_access_token(
        self,
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create JWT access token."""
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=self.access_token_expire_minutes
            )

        # Add standard claims
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "jti": secrets.token_urlsafe(32),  # JWT ID for blacklisting
            "type": "access"
        })

        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(self, user_id: str) -> str:
        """Create JWT refresh token."""
        to_encode = {
            "sub": user_id,
            "exp": datetime.now(timezone.utc) + timedelta(days=self.refresh_token_expire_days),
            "iat": datetime.now(timezone.utc),
            "jti": secrets.token_urlsafe(32),
            "type": "refresh"
        }

        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def verify_token(self, token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"require_exp": True, "require_iat": True}
            )

            # Verify token type
            if payload.get("type") != token_type:
                return None

            # Check if token is blacklisted (implement your blacklist logic)
            if self._is_token_blacklisted(payload.get("jti")):
                return None

            return payload

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception:
            return None

    def _is_token_blacklisted(self, jti: str) -> bool:
        """Check if token is blacklisted (implement with your storage)."""
        # Implement blacklist check using Redis/database
        # return redis_client.sismember("blacklisted_tokens", jti)
        return False

    def blacklist_token(self, jti: str) -> None:
        """Add token to blacklist."""
        # Implement with your storage
        # redis_client.sadd("blacklisted_tokens", jti)
        pass
```

### Session Management
✅ **DO**: Implement secure session handling
```python
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

class SessionManager:
    """Secure session management."""

    def __init__(self, session_store):
        self.session_store = session_store  # Redis, database, etc.
        self.session_timeout = timedelta(hours=2)
        self.max_sessions_per_user = 3

    def create_session(self, user_id: str, user_agent: str, ip_address: str) -> str:
        """Create new user session."""
        session_id = secrets.token_urlsafe(32)

        session_data = {
            "user_id": user_id,
            "created_at": datetime.utcnow(),
            "last_activity": datetime.utcnow(),
            "user_agent": user_agent,
            "ip_address": ip_address,
            "is_active": True
        }

        # Store session
        self.session_store.set(
            f"session:{session_id}",
            session_data,
            expire=self.session_timeout
        )

        # Manage session limits
        self._enforce_session_limit(user_id)

        return session_id

    def validate_session(
        self,
        session_id: str,
        user_agent: str,
        ip_address: str
    ) -> Optional[Dict[str, Any]]:
        """Validate session and check for suspicious activity."""
        session_data = self.session_store.get(f"session:{session_id}")

        if not session_data or not session_data.get("is_active"):
            return None

        # Check for session hijacking indicators
        if session_data["user_agent"] != user_agent:
            self._handle_suspicious_activity(session_id, "User agent mismatch")
            return None

        # Optional: Check for IP address changes (less strict)
        if session_data["ip_address"] != ip_address:
            # Log but don't reject (users may have dynamic IPs)
            self._log_ip_change(session_id, session_data["ip_address"], ip_address)

        # Update last activity
        session_data["last_activity"] = datetime.utcnow()
        self.session_store.set(
            f"session:{session_id}",
            session_data,
            expire=self.session_timeout
        )

        return session_data

    def invalidate_session(self, session_id: str) -> None:
        """Invalidate specific session."""
        session_data = self.session_store.get(f"session:{session_id}")
        if session_data:
            session_data["is_active"] = False
            self.session_store.set(f"session:{session_id}", session_data)

    def invalidate_all_user_sessions(self, user_id: str) -> None:
        """Invalidate all sessions for a user."""
        # Implementation depends on your storage backend
        user_sessions = self._get_user_sessions(user_id)
        for session_id in user_sessions:
            self.invalidate_session(session_id)

    def _enforce_session_limit(self, user_id: str) -> None:
        """Enforce maximum sessions per user."""
        user_sessions = self._get_user_sessions(user_id)
        if len(user_sessions) >= self.max_sessions_per_user:
            # Remove oldest session
            oldest_session = min(user_sessions, key=lambda x: x["created_at"])
            self.invalidate_session(oldest_session["session_id"])

    def _handle_suspicious_activity(self, session_id: str, reason: str) -> None:
        """Handle potentially suspicious session activity."""
        self.invalidate_session(session_id)
        # Log security event
        logger.warning(f"Suspicious session activity: {reason}, session: {session_id}")

    def _log_ip_change(self, session_id: str, old_ip: str, new_ip: str) -> None:
        """Log IP address changes."""
        logger.info(f"Session IP changed: {old_ip} -> {new_ip}, session: {session_id}")

    def _get_user_sessions(self, user_id: str) -> list:
        """Get all active sessions for a user."""
        # Implementation depends on your storage backend
        return []
```

### Role-Based Access Control (RBAC)
✅ **DO**: Implement comprehensive RBAC
```python
from enum import Enum
from typing import Set, Optional, Dict, Any
from functools import wraps

class Permission(Enum):
    """System permissions."""
    READ_USER = "read_user"
    WRITE_USER = "write_user"
    DELETE_USER = "delete_user"
    READ_ADMIN = "read_admin"
    WRITE_ADMIN = "write_admin"
    SYSTEM_CONFIG = "system_config"

class Role:
    """Role with associated permissions."""

    def __init__(self, name: str, permissions: Set[Permission]):
        self.name = name
        self.permissions = permissions

    def has_permission(self, permission: Permission) -> bool:
        """Check if role has specific permission."""
        return permission in self.permissions

# Define system roles
ROLES = {
    "user": Role("user", {Permission.READ_USER}),
    "moderator": Role("moderator", {
        Permission.READ_USER,
        Permission.WRITE_USER
    }),
    "admin": Role("admin", {
        Permission.READ_USER,
        Permission.WRITE_USER,
        Permission.DELETE_USER,
        Permission.READ_ADMIN,
        Permission.WRITE_ADMIN
    }),
    "super_admin": Role("super_admin", {
        Permission.READ_USER,
        Permission.WRITE_USER,
        Permission.DELETE_USER,
        Permission.READ_ADMIN,
        Permission.WRITE_ADMIN,
        Permission.SYSTEM_CONFIG
    })
}

class User:
    """User with role-based permissions."""

    def __init__(self, user_id: str, username: str, roles: Set[str]):
        self.user_id = user_id
        self.username = username
        self.roles = roles

    def has_permission(self, permission: Permission) -> bool:
        """Check if user has specific permission."""
        for role_name in self.roles:
            role = ROLES.get(role_name)
            if role and role.has_permission(permission):
                return True
        return False

    def has_any_role(self, required_roles: Set[str]) -> bool:
        """Check if user has any of the required roles."""
        return bool(self.roles.intersection(required_roles))

def require_permission(permission: Permission):
    """Decorator to require specific permission."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract user from context (implementation specific)
            current_user = get_current_user()  # Your implementation

            if not current_user or not current_user.has_permission(permission):
                raise PermissionError(f"Permission required: {permission.value}")

            return func(*args, **kwargs)
        return wrapper
    return decorator

def require_role(required_roles: Set[str]):
    """Decorator to require specific role(s)."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_user = get_current_user()

            if not current_user or not current_user.has_any_role(required_roles):
                raise PermissionError(f"Role required: {required_roles}")

            return func(*args, **kwargs)
        return wrapper
    return decorator

# Usage examples
@require_permission(Permission.READ_USER)
def get_user_profile(user_id: str):
    """Get user profile - requires read_user permission."""
    pass

@require_role({"admin", "super_admin"})
def delete_user(user_id: str):
    """Delete user - requires admin or super_admin role."""
    pass
```

### Multi-Factor Authentication (MFA)
✅ **DO**: Implement TOTP-based MFA
```python
import pyotp
import qrcode
from io import BytesIO
import base64

class MFAManager:
    """Multi-factor authentication management."""

    def __init__(self, issuer_name: str = "YourApp"):
        self.issuer_name = issuer_name

    def generate_secret(self) -> str:
        """Generate new MFA secret for user."""
        return pyotp.random_base32()

    def generate_qr_code(self, user_email: str, secret: str) -> str:
        """Generate QR code for MFA setup."""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name=self.issuer_name
        )

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64 string
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()

        return f"data:image/png;base64,{img_str}"

    def verify_token(self, secret: str, token: str) -> bool:
        """Verify MFA token."""
        if not token or not token.isdigit() or len(token) != 6:
            return False

        totp = pyotp.TOTP(secret)

        # Allow 30-second window tolerance
        return totp.verify(token, valid_window=1)

    def generate_backup_codes(self, count: int = 10) -> list:
        """Generate backup codes for MFA recovery."""
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()  # 8-character hex codes
            codes.append(code)
        return codes

    def verify_backup_code(self, user_backup_codes: list, provided_code: str) -> bool:
        """Verify backup code and remove it from list."""
        provided_code = provided_code.upper().strip()

        if provided_code in user_backup_codes:
            user_backup_codes.remove(provided_code)
            return True

        return False

class AuthenticationService:
    """Complete authentication service with MFA."""

    def __init__(self):
        self.password_manager = PasswordManager()
        self.mfa_manager = MFAManager()
        self.session_manager = SessionManager()
        self.failed_attempts = {}  # In production, use persistent storage
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(minutes=15)

    def authenticate_user(
        self,
        username: str,
        password: str,
        mfa_token: Optional[str] = None,
        user_agent: str = "",
        ip_address: str = ""
    ) -> Optional[str]:
        """Authenticate user with password and optional MFA."""

        # Check if account is locked
        if self._is_account_locked(username):
            raise AccountLockedError("Account temporarily locked due to failed attempts")

        # Verify password
        user = self._get_user_by_username(username)  # Your implementation
        if not user or not self.password_manager.verify_password(password, user.password_hash):
            self._record_failed_attempt(username)
            return None

        # Check if MFA is enabled for user
        if user.mfa_enabled:
            if not mfa_token:
                raise MFARequiredError("MFA token required")

            if not self.mfa_manager.verify_token(user.mfa_secret, mfa_token):
                self._record_failed_attempt(username)
                return None

        # Authentication successful - clear failed attempts
        self._clear_failed_attempts(username)

        # Create session
        session_id = self.session_manager.create_session(
            user.user_id, user_agent, ip_address
        )

        return session_id

    def _is_account_locked(self, username: str) -> bool:
        """Check if account is locked due to failed attempts."""
        if username not in self.failed_attempts:
            return False

        attempts_data = self.failed_attempts[username]
        if attempts_data["count"] >= self.max_failed_attempts:
            time_since_last = datetime.utcnow() - attempts_data["last_attempt"]
            return time_since_last < self.lockout_duration

        return False

    def _record_failed_attempt(self, username: str) -> None:
        """Record failed authentication attempt."""
        now = datetime.utcnow()

        if username in self.failed_attempts:
            self.failed_attempts[username]["count"] += 1
            self.failed_attempts[username]["last_attempt"] = now
        else:
            self.failed_attempts[username] = {
                "count": 1,
                "last_attempt": now
            }

    def _clear_failed_attempts(self, username: str) -> None:
        """Clear failed attempts for user."""
        if username in self.failed_attempts:
            del self.failed_attempts[username]

## Secrets Management

### Environment Variables
✅ **DO**: Use environment variables for secrets
```python
import os
from typing import Optional

class Settings:
    """Application settings with secure defaults."""

    def __init__(self):
        # Database credentials
        self.db_host = os.getenv("DB_HOST", "localhost")
        self.db_port = int(os.getenv("DB_PORT", "5432"))
        self.db_name = os.getenv("DB_NAME")
        self.db_user = os.getenv("DB_USER")
        self.db_password = os.getenv("DB_PASSWORD")

        # API keys and secrets
        self.secret_key = os.getenv("SECRET_KEY")
        self.jwt_secret = os.getenv("JWT_SECRET_KEY")
        self.api_key = os.getenv("EXTERNAL_API_KEY")

        # Validate required secrets
        self._validate_secrets()

    def _validate_secrets(self) -> None:
        """Validate that all required secrets are present."""
        required_secrets = [
            ("SECRET_KEY", self.secret_key),
            ("JWT_SECRET_KEY", self.jwt_secret),
            ("DB_PASSWORD", self.db_password),
        ]

        missing_secrets = [
            name for name, value in required_secrets
            if not value
        ]

        if missing_secrets:
            raise ValueError(f"Missing required environment variables: {missing_secrets}")

        # Validate secret strength
        if len(self.secret_key) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")

        if len(self.jwt_secret) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters")

# Usage
settings = Settings()
```

❌ **DON'T**: Hardcode secrets in source code
```python
# Wrong - secrets in source code
DATABASE_URL = "postgresql://user:password123@localhost/mydb"  # Don't do this
API_KEY = "sk-1234567890abcdef"  # Don't do this
SECRET_KEY = "my-secret-key"  # Don't do this

# Wrong - secrets in configuration files committed to git
config = {
    "api_key": "secret-api-key",  # Don't commit this
    "database_password": "admin123"  # Don't commit this
}
```

### Secure Configuration Loading
✅ **DO**: Use secure configuration management
```python
import os
from pathlib import Path
from typing import Dict, Any
import json

class SecureConfig:
    """Secure configuration management."""

    def __init__(self, config_file: Optional[str] = None):
        self.config = {}
        self._load_environment_variables()

        if config_file:
            self._load_config_file(config_file)

    def _load_environment_variables(self) -> None:
        """Load configuration from environment variables."""
        # Database configuration
        if os.getenv("DATABASE_URL"):
            self.config["database_url"] = os.getenv("DATABASE_URL")

        # Security configuration
        self.config.update({
            "secret_key": os.getenv("SECRET_KEY"),
            "jwt_secret": os.getenv("JWT_SECRET_KEY"),
            "encryption_key": os.getenv("ENCRYPTION_KEY"),
        })

        # API configuration
        self.config.update({
            "redis_url": os.getenv("REDIS_URL"),
            "external_api_key": os.getenv("EXTERNAL_API_KEY"),
            "webhook_secret": os.getenv("WEBHOOK_SECRET"),
        })

    def _load_config_file(self, config_file: str) -> None:
        """Load non-sensitive configuration from file."""
        config_path = Path(config_file)

        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_file}")

        # Only load non-sensitive configuration
        with open(config_path) as f:
            file_config = json.load(f)

        # Merge non-sensitive settings
        allowed_keys = {
            "app_name", "debug", "log_level", "timezone",
            "rate_limit", "cache_ttl", "upload_max_size"
        }

        for key, value in file_config.items():
            if key in allowed_keys:
                self.config[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config.get(key, default)

    def get_required(self, key: str) -> Any:
        """Get required configuration value."""
        value = self.config.get(key)
        if value is None:
            raise ValueError(f"Required configuration key missing: {key}")
        return value

# Usage
config = SecureConfig("app_config.json")
secret_key = config.get_required("secret_key")
```

### HashiCorp Vault Integration
✅ **DO**: Use HashiCorp Vault for production secrets
```python
import hvac
from typing import Dict, Any, Optional
import os

class VaultClient:
    """HashiCorp Vault client for secrets management."""

    def __init__(
        self,
        vault_url: str = None,
        vault_token: str = None,
        mount_point: str = "secret"
    ):
        self.vault_url = vault_url or os.getenv("VAULT_URL", "http://localhost:8200")
        self.vault_token = vault_token or os.getenv("VAULT_TOKEN")
        self.mount_point = mount_point

        if not self.vault_token:
            raise ValueError("VAULT_TOKEN environment variable required")

        # Initialize Vault client
        self.client = hvac.Client(url=self.vault_url, token=self.vault_token)

        if not self.client.is_authenticated():
            raise ConnectionError("Failed to authenticate with Vault")

    def get_secret(self, secret_path: str) -> Optional[Dict[str, Any]]:
        """Get secret from Vault."""
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=secret_path,
                mount_point=self.mount_point
            )

            return response["data"]["data"]

        except hvac.exceptions.Forbidden:
            raise PermissionError(f"Access denied to secret: {secret_path}")
        except hvac.exceptions.InvalidPath:
            return None
        except Exception as e:
            raise ConnectionError(f"Failed to retrieve secret: {e}")

    def set_secret(self, secret_path: str, secret_data: Dict[str, Any]) -> None:
        """Store secret in Vault."""
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=secret_path,
                secret=secret_data,
                mount_point=self.mount_point
            )
        except Exception as e:
            raise ConnectionError(f"Failed to store secret: {e}")

    def delete_secret(self, secret_path: str) -> None:
        """Delete secret from Vault."""
        try:
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=secret_path,
                mount_point=self.mount_point
            )
        except Exception as e:
            raise ConnectionError(f"Failed to delete secret: {e}")

# Usage
vault = VaultClient()
db_credentials = vault.get_secret("database/production")
```

## Cryptography

### Encryption and Decryption
✅ **DO**: Use established cryptography libraries
```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import secrets

class EncryptionManager:
    """Secure encryption/decryption using Fernet."""

    def __init__(self, password: Optional[str] = None):
        if password:
            self.key = self._derive_key_from_password(password)
        else:
            self.key = self._load_or_generate_key()

        self.cipher_suite = Fernet(self.key)

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new encryption key."""
        return Fernet.generate_key()

    def _derive_key_from_password(self, password: str, salt: bytes = None) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # Adjust based on security requirements
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def _load_or_generate_key(self) -> bytes:
        """Load key from environment or generate new one."""
        key_b64 = os.getenv("ENCRYPTION_KEY")

        if key_b64:
            try:
                return base64.urlsafe_b64decode(key_b64)
            except Exception:
                raise ValueError("Invalid ENCRYPTION_KEY format")

        # Generate new key if not provided
        new_key = Fernet.generate_key()
        print(f"Generated new encryption key: {base64.urlsafe_b64encode(new_key).decode()}")
        print("Set ENCRYPTION_KEY environment variable with this value")
        return new_key

    def encrypt(self, data: str) -> str:
        """Encrypt string data."""
        if not isinstance(data, str):
            raise ValueError("Data must be a string")

        encrypted_data = self.cipher_suite.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data."""
        if not isinstance(encrypted_data, str):
            raise ValueError("Encrypted data must be a string")

        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data)
            decrypted_data = self.cipher_suite.decrypt(decoded_data)
            return decrypted_data.decode()
        except Exception as e:
            raise ValueError(f"Failed to decrypt data: {e}")

    def encrypt_dict(self, data: Dict[str, Any]) -> str:
        """Encrypt dictionary data."""
        json_data = json.dumps(data, sort_keys=True)
        return self.encrypt(json_data)

    def decrypt_dict(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt dictionary data."""
        json_data = self.decrypt(encrypted_data)
        return json.loads(json_data)

# Usage
encryption = EncryptionManager()
encrypted_text = encryption.encrypt("sensitive data")
decrypted_text = encryption.decrypt(encrypted_text)
```

### Secure Random Generation
✅ **DO**: Use cryptographically secure random generation
```python
import secrets
import string
from typing import List

class SecureRandom:
    """Cryptographically secure random generation."""

    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate cryptographically secure token."""
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_hex_token(length: int = 32) -> str:
        """Generate cryptographically secure hex token."""
        return secrets.token_hex(length)

    @staticmethod
    def generate_password(
        length: int = 16,
        include_symbols: bool = True
    ) -> str:
        """Generate cryptographically secure password."""
        alphabet = string.ascii_letters + string.digits

        if include_symbols:
            alphabet += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        password = ''.join(secrets.choice(alphabet) for _ in range(length))

        # Ensure password contains at least one character from each category
        if length >= 4:
            # Force at least one uppercase, lowercase, digit, and symbol
            password = list(password)
            password[0] = secrets.choice(string.ascii_uppercase)
            password[1] = secrets.choice(string.ascii_lowercase)
            password[2] = secrets.choice(string.digits)

            if include_symbols:
                password[3] = secrets.choice("!@#$%^&*")

            # Shuffle to randomize positions
            for i in range(len(password)):
                j = secrets.randbelow(len(password))
                password[i], password[j] = password[j], password[i]

        return ''.join(password)

    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        """Generate cryptographically secure salt."""
        return os.urandom(length)

    @staticmethod
    def secure_choice(sequence: List[Any]) -> Any:
        """Cryptographically secure choice from sequence."""
        if not sequence:
            raise ValueError("Sequence cannot be empty")

        return secrets.choice(sequence)

# Usage
secure_token = SecureRandom.generate_token()
secure_password = SecureRandom.generate_password(20, include_symbols=True)
```

### Digital Signatures
✅ **DO**: Implement digital signatures for data integrity
```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import base64

class DigitalSignature:
    """Digital signature implementation for data integrity."""

    def __init__(self, private_key_pem: str = None, public_key_pem: str = None):
        if private_key_pem:
            self.private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )
        else:
            self.private_key = None

        if public_key_pem:
            self.public_key = serialization.load_pem_public_key(
                public_key_pem.encode()
            )
        elif self.private_key:
            self.public_key = self.private_key.public_key()
        else:
            self.public_key = None

    @staticmethod
    def generate_key_pair() -> tuple:
        """Generate RSA key pair for signing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        public_key = private_key.public_key()

        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem.decode(), public_pem.decode()

    def sign_data(self, data: str) -> str:
        """Sign data using private key."""
        if not self.private_key:
            raise ValueError("Private key required for signing")

        signature = self.private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return base64.b64encode(signature).decode()

    def verify_signature(self, data: str, signature: str) -> bool:
        """Verify signature using public key."""
        if not self.public_key:
            raise ValueError("Public key required for verification")

        try:
            signature_bytes = base64.b64decode(signature)

            self.public_key.verify(
                signature_bytes,
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True

        except InvalidSignature:
            return False
        except Exception:
            return False

# Usage
private_key_pem, public_key_pem = DigitalSignature.generate_key_pair()
signer = DigitalSignature(private_key_pem, public_key_pem)
signature = signer.sign_data("important message")
is_valid = signer.verify_signature("important message", signature)

## Common Vulnerabilities Prevention

### SQL Injection Prevention
✅ **DO**: Use parameterized queries and ORMs
```python
import sqlite3
from sqlalchemy import create_engine, text
from typing import Optional, List, Dict, Any

class SecureDatabaseClient:
    """Secure database client with SQL injection prevention."""

    def __init__(self, database_url: str):
        self.engine = create_engine(database_url)

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID using parameterized query."""
        query = text("SELECT * FROM users WHERE id = :user_id")

        with self.engine.connect() as connection:
            result = connection.execute(query, {"user_id": user_id})
            row = result.fetchone()
            return dict(row) if row else None

    def search_users(self, search_term: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search users with safe parameterization."""
        # Validate limit parameter
        if not isinstance(limit, int) or limit <= 0 or limit > 100:
            raise ValueError("Invalid limit parameter")

        query = text("""
            SELECT id, username, email, created_at
            FROM users
            WHERE username ILIKE :search_term
               OR email ILIKE :search_term
            LIMIT :limit
        """)

        # Use LIKE pattern safely
        safe_search = f"%{search_term}%"

        with self.engine.connect() as connection:
            result = connection.execute(query, {
                "search_term": safe_search,
                "limit": limit
            })
            return [dict(row) for row in result.fetchall()]

    def update_user_profile(self, user_id: str, profile_data: Dict[str, Any]) -> bool:
        """Update user profile with safe parameter binding."""
        # Whitelist allowed fields
        allowed_fields = {"username", "email", "first_name", "last_name", "bio"}

        # Filter to only allowed fields
        safe_data = {
            key: value for key, value in profile_data.items()
            if key in allowed_fields
        }

        if not safe_data:
            raise ValueError("No valid fields to update")

        # Build dynamic query safely
        set_clauses = [f"{field} = :{field}" for field in safe_data.keys()]
        query = text(f"""
            UPDATE users
            SET {', '.join(set_clauses)}, updated_at = NOW()
            WHERE id = :user_id
        """)

        # Add user_id to parameters
        params = {"user_id": user_id, **safe_data}

        with self.engine.connect() as connection:
            result = connection.execute(query, params)
            return result.rowcount > 0
```

❌ **DON'T**: Use string formatting for SQL queries
```python
# Wrong - SQL injection vulnerability
def get_user_unsafe(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"  # Vulnerable!
    return execute_query(query)

# Wrong - String concatenation
def search_users_unsafe(search_term):
    query = "SELECT * FROM users WHERE name LIKE '%" + search_term + "%'"  # Vulnerable!
    return execute_query(query)

# Wrong - % formatting
def update_user_unsafe(user_id, username):
    query = "UPDATE users SET username = '%s' WHERE id = %s" % (username, user_id)  # Vulnerable!
    return execute_query(query)
```

### Cross-Site Scripting (XSS) Prevention
✅ **DO**: Implement proper output encoding and CSP
```python
import html
import bleach
from markupsafe import Markup, escape
from typing import Dict, Any, List

class XSSProtection:
    """XSS prevention utilities."""

    # Allowed HTML tags and attributes for rich text
    ALLOWED_TAGS = [
        'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote'
    ]

    ALLOWED_ATTRIBUTES = {
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'width', 'height'],
    }

    @staticmethod
    def escape_html(text: str) -> str:
        """Escape HTML characters to prevent XSS."""
        if not isinstance(text, str):
            return str(text)

        return html.escape(text, quote=True)

    @staticmethod
    def sanitize_html(html_content: str) -> str:
        """Sanitize HTML content allowing only safe tags."""
        return bleach.clean(
            html_content,
            tags=XSSProtection.ALLOWED_TAGS,
            attributes=XSSProtection.ALLOWED_ATTRIBUTES,
            strip=True
        )

    @staticmethod
    def create_csp_header() -> Dict[str, str]:
        """Generate Content Security Policy header."""
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        return {
            "Content-Security-Policy": csp_policy,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block"
        }

    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL to prevent javascript: and data: URIs."""
        if not url:
            return False

        # Convert to lowercase for checking
        url_lower = url.lower().strip()

        # Block dangerous schemes
        dangerous_schemes = [
            'javascript:', 'data:', 'vbscript:', 'file:', 'ftp:'
        ]

        for scheme in dangerous_schemes:
            if url_lower.startswith(scheme):
                return False

        # Only allow http/https
        return url_lower.startswith(('http://', 'https://'))

# Template rendering with auto-escaping
class SafeTemplateRenderer:
    """Safe template rendering with automatic escaping."""

    def __init__(self):
        self.xss_protection = XSSProtection()

    def render_user_profile(self, user_data: Dict[str, Any]) -> str:
        """Render user profile with safe output encoding."""
        # Escape all user-provided data
        safe_username = self.xss_protection.escape_html(user_data.get('username', ''))
        safe_email = self.xss_protection.escape_html(user_data.get('email', ''))
        safe_bio = self.xss_protection.sanitize_html(user_data.get('bio', ''))

        # Use Markup for trusted HTML (bio after sanitization)
        return f"""
        <div class="user-profile">
            <h2>{safe_username}</h2>
            <p>Email: {safe_email}</p>
            <div class="bio">{Markup(safe_bio)}</div>
        </div>
        """

    def render_comment(self, comment_data: Dict[str, Any]) -> str:
        """Render user comment with XSS protection."""
        author = self.xss_protection.escape_html(comment_data.get('author', ''))
        content = self.xss_protection.escape_html(comment_data.get('content', ''))
        timestamp = self.xss_protection.escape_html(str(comment_data.get('created_at', '')))

        return f"""
        <div class="comment">
            <strong>{author}</strong>
            <span class="timestamp">{timestamp}</span>
            <p>{content}</p>
        </div>
        """
```

### Cross-Site Request Forgery (CSRF) Prevention
✅ **DO**: Implement CSRF tokens for state-changing operations
```python
import secrets
import hmac
import hashlib
from datetime import datetime, timedelta
from typing import Optional

class CSRFProtection:
    """CSRF protection implementation."""

    def __init__(self, secret_key: str, token_lifetime: int = 3600):
        if len(secret_key) < 32:
            raise ValueError("Secret key must be at least 32 characters")

        self.secret_key = secret_key.encode()
        self.token_lifetime = token_lifetime

    def generate_csrf_token(self, session_id: str) -> str:
        """Generate CSRF token for session."""
        timestamp = str(int(datetime.utcnow().timestamp()))
        random_part = secrets.token_urlsafe(16)

        # Create message to sign
        message = f"{session_id}:{timestamp}:{random_part}"

        # Create HMAC signature
        signature = hmac.new(
            self.secret_key,
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        # Combine all parts
        token = f"{timestamp}:{random_part}:{signature}"
        return token

    def validate_csrf_token(self, token: str, session_id: str) -> bool:
        """Validate CSRF token."""
        if not token or not session_id:
            return False

        try:
            parts = token.split(':')
            if len(parts) != 3:
                return False

            timestamp_str, random_part, provided_signature = parts

            # Check token age
            token_timestamp = int(timestamp_str)
            current_timestamp = int(datetime.utcnow().timestamp())

            if current_timestamp - token_timestamp > self.token_lifetime:
                return False

            # Recreate expected signature
            message = f"{session_id}:{timestamp_str}:{random_part}"
            expected_signature = hmac.new(
                self.secret_key,
                message.encode(),
                hashlib.sha256
            ).hexdigest()

            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(expected_signature, provided_signature)

        except (ValueError, IndexError):
            return False

# FastAPI CSRF middleware example
from fastapi import Request, HTTPException
from fastapi.responses import Response

class CSRFMiddleware:
    """CSRF middleware for FastAPI."""

    def __init__(self, secret_key: str):
        self.csrf_protection = CSRFProtection(secret_key)
        self.safe_methods = {"GET", "HEAD", "OPTIONS", "TRACE"}

    async def __call__(self, request: Request, call_next):
        """Process request with CSRF protection."""

        # Skip CSRF check for safe methods
        if request.method in self.safe_methods:
            response = await call_next(request)
            return response

        # Get session ID from request (implement your session logic)
        session_id = self._get_session_id(request)
        if not session_id:
            raise HTTPException(status_code=401, detail="No valid session")

        # Check CSRF token for state-changing requests
        csrf_token = request.headers.get("X-CSRF-Token")
        if not csrf_token:
            csrf_token = (await request.form()).get("csrf_token")

        if not self.csrf_protection.validate_csrf_token(csrf_token, session_id):
            raise HTTPException(status_code=403, detail="CSRF token validation failed")

        response = await call_next(request)
        return response

    def _get_session_id(self, request: Request) -> Optional[str]:
        """Extract session ID from request."""
        # Implement your session extraction logic
        return request.cookies.get("session_id")
```

### Server-Side Request Forgery (SSRF) Prevention
✅ **DO**: Validate and restrict outbound requests
```python
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Set, List
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import connection

class SSRFProtection:
    """SSRF protection for outbound HTTP requests."""

    def __init__(self):
        # Blocked IP ranges (RFC 1918 private networks, localhost, etc.)
        self.blocked_networks = [
            ipaddress.IPv4Network('127.0.0.0/8'),    # Localhost
            ipaddress.IPv4Network('10.0.0.0/8'),     # Private class A
            ipaddress.IPv4Network('172.16.0.0/12'),  # Private class B
            ipaddress.IPv4Network('192.168.0.0/16'), # Private class C
            ipaddress.IPv4Network('169.254.0.0/16'), # Link-local
            ipaddress.IPv4Network('224.0.0.0/4'),    # Multicast
            ipaddress.IPv6Network('::1/128'),         # IPv6 localhost
            ipaddress.IPv6Network('fc00::/7'),        # IPv6 private
            ipaddress.IPv6Network('fe80::/10'),       # IPv6 link-local
        ]

        self.allowed_schemes = {'http', 'https'}
        self.blocked_ports = {22, 23, 25, 53, 80, 135, 139, 445, 993, 995, 1433, 3306, 3389, 5432, 5985, 5986}

    def validate_url(self, url: str) -> bool:
        """Validate URL for SSRF protection."""
        try:
            parsed = urlparse(url)

            # Check scheme
            if parsed.scheme not in self.allowed_schemes:
                return False

            # Resolve hostname to IP
            hostname = parsed.hostname
            if not hostname:
                return False

            # Check if hostname is an IP address
            try:
                ip = ipaddress.ip_address(hostname)
                return not self._is_blocked_ip(ip)
            except ValueError:
                # Hostname is not an IP, resolve it
                pass

            # Resolve hostname
            try:
                ip_addresses = socket.getaddrinfo(hostname, parsed.port)
                for addr_info in ip_addresses:
                    ip_str = addr_info[4][0]
                    ip = ipaddress.ip_address(ip_str)

                    if self._is_blocked_ip(ip):
                        return False

                return True

            except socket.gaierror:
                return False

        except Exception:
            return False

    def _is_blocked_ip(self, ip: ipaddress._BaseAddress) -> bool:
        """Check if IP address is in blocked networks."""
        for network in self.blocked_networks:
            if ip in network:
                return True
        return False

class SecureHTTPClient:
    """HTTP client with SSRF protection."""

    def __init__(self, timeout: int = 30, max_redirects: int = 3):
        self.ssrf_protection = SSRFProtection()
        self.timeout = timeout
        self.max_redirects = max_redirects

        # Create session with custom adapter
        self.session = requests.Session()
        self.session.mount('http://', SSRFAdapter())
        self.session.mount('https://', SSRFAdapter())

    def get(self, url: str, **kwargs) -> requests.Response:
        """Make GET request with SSRF protection."""
        if not self.ssrf_protection.validate_url(url):
            raise ValueError(f"URL blocked by SSRF protection: {url}")

        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', True)
        kwargs.setdefault('max_redirects', self.max_redirects)

        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """Make POST request with SSRF protection."""
        if not self.ssrf_protection.validate_url(url):
            raise ValueError(f"URL blocked by SSRF protection: {url}")

        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', False)  # Don't follow redirects for POST

        return self.session.post(url, **kwargs)

class SSRFAdapter(HTTPAdapter):
    """Custom HTTP adapter with SSRF protection."""

    def init_poolmanager(self, *args, **kwargs):
        # Override socket creation to add IP validation
        kwargs['socket_options'] = connection.default_socket_options + [
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
        ]
        return super().init_poolmanager(*args, **kwargs)
```

### Path Traversal Prevention
✅ **DO**: Validate and sanitize file paths
```python
import os
from pathlib import Path
from typing import Optional

class PathTraversalProtection:
    """Protection against path traversal attacks."""

    def __init__(self, base_directory: str):
        self.base_directory = Path(base_directory).resolve()

        # Ensure base directory exists
        self.base_directory.mkdir(parents=True, exist_ok=True)

    def safe_join(self, *path_components: str) -> Optional[Path]:
        """Safely join path components and validate result."""
        try:
            # Clean each component
            clean_components = []
            for component in path_components:
                if not component or component in ('.', '..'):
                    continue

                # Remove dangerous characters
                clean_component = self._sanitize_path_component(component)
                if clean_component:
                    clean_components.append(clean_component)

            if not clean_components:
                return None

            # Join with base directory
            target_path = self.base_directory
            for component in clean_components:
                target_path = target_path / component

            # Resolve to absolute path
            resolved_path = target_path.resolve()

            # Verify it's within base directory
            if not self._is_safe_path(resolved_path):
                return None

            return resolved_path

        except (OSError, ValueError):
            return None

    def _sanitize_path_component(self, component: str) -> str:
        """Sanitize individual path component."""
        # Remove null bytes and control characters
        sanitized = ''.join(c for c in component if ord(c) >= 32)

        # Remove dangerous patterns
        dangerous_patterns = ['..', './', '\\', ':', '*', '?', '"', '<', '>', '|']
        for pattern in dangerous_patterns:
            sanitized = sanitized.replace(pattern, '')

        # Limit length
        if len(sanitized) > 255:
            sanitized = sanitized[:255]

        return sanitized.strip()

    def _is_safe_path(self, path: Path) -> bool:
        """Check if path is within base directory."""
        try:
            path.relative_to(self.base_directory)
            return True
        except ValueError:
            return False

    def read_file_safely(self, *path_components: str) -> Optional[bytes]:
        """Safely read file content."""
        safe_path = self.safe_join(*path_components)
        if not safe_path or not safe_path.is_file():
            return None

        try:
            with open(safe_path, 'rb') as f:
                return f.read()
        except (OSError, IOError):
            return None

    def write_file_safely(self, content: bytes, *path_components: str) -> bool:
        """Safely write file content."""
        safe_path = self.safe_join(*path_components)
        if not safe_path:
            return False

        try:
            # Create parent directories if needed
            safe_path.parent.mkdir(parents=True, exist_ok=True)

            with open(safe_path, 'wb') as f:
                f.write(content)
            return True

        except (OSError, IOError):
            return False

# Usage example
file_manager = PathTraversalProtection('/app/uploads')

# Safe file operations
content = file_manager.read_file_safely('user123', 'profile.jpg')
success = file_manager.write_file_safely(b'file content', 'user123', 'document.pdf')

## Dependency Security

### Dependency Management
✅ **DO**: Use minimum version constraints and security scanning
```toml
# pyproject.toml - Secure dependency management
[tool.poetry.dependencies]
python = "^3.11"
fastapi = ">=0.104.0"  # Use minimum version constraints
pydantic = ">=2.4.0"
sqlalchemy = ">=2.0.0"
cryptography = ">=41.0.0"  # Security-critical packages need frequent updates
requests = ">=2.31.0"
# Pin security-critical dependencies more strictly
bcrypt = "~4.0.1"  # Compatible release

[tool.poetry.group.dev.dependencies]
pytest = ">=7.4.0"
black = ">=23.7.0"
ruff = ">=0.0.290"
mypy = ">=1.5.0"

[tool.poetry.group.security.dependencies]
bandit = ">=1.7.5"      # Security linter
safety = ">=2.3.0"      # Dependency vulnerability scanner
pip-audit = ">=2.6.0"   # Alternative vulnerability scanner
```

### Vulnerability Scanning
✅ **DO**: Implement automated vulnerability scanning
```bash
#!/bin/bash
# security-scan.sh - Comprehensive security scanning

set -e

echo "Running security scans..."

# 1. Scan for known vulnerabilities in dependencies
echo "Checking for vulnerable dependencies..."
pip-audit --requirement requirements.txt --format=json --output=vulnerabilities.json

# Alternative with safety
safety check --json --output=safety-report.json

# 2. Static security analysis with bandit
echo "Running static security analysis..."
bandit -r src/ -f json -o bandit-report.json

# 3. Check for secrets in code
echo "Scanning for secrets..."
if command -v truffleHog &> /dev/null; then
    trufflehog filesystem . --json > secrets-scan.json
fi

# 4. License compliance check
echo "Checking license compliance..."
pip-licenses --format=json --output-file=licenses.json

echo "Security scans complete!"
```

### Security Monitoring
✅ **DO**: Monitor for security advisories and updates
```python
import subprocess
import json
from datetime import datetime
from typing import List, Dict, Any
import requests

class SecurityMonitor:
    """Monitor dependencies for security vulnerabilities."""

    def __init__(self):
        self.vulnerability_sources = [
            "https://pypi.org/pypi/{package}/json",  # PyPI API
            "https://api.github.com/advisories",      # GitHub Security Advisories
        ]

    def check_vulnerabilities(self) -> Dict[str, Any]:
        """Check for vulnerabilities in installed packages."""
        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "vulnerabilities": [],
            "recommendations": []
        }

        # Use pip-audit for vulnerability checking
        try:
            result = subprocess.run([
                "pip-audit", "--format=json", "--desc"
            ], capture_output=True, text=True, check=True)

            vulnerabilities = json.loads(result.stdout)
            results["vulnerabilities"] = vulnerabilities

        except subprocess.CalledProcessError as e:
            results["error"] = f"Vulnerability scan failed: {e}"

        return results

    def get_security_updates(self) -> List[Dict[str, str]]:
        """Get available security updates for packages."""
        updates = []

        try:
            # Get list of outdated packages
            result = subprocess.run([
                "pip", "list", "--outdated", "--format=json"
            ], capture_output=True, text=True, check=True)

            outdated_packages = json.loads(result.stdout)

            for package in outdated_packages:
                updates.append({
                    "package": package["name"],
                    "current_version": package["version"],
                    "latest_version": package["latest_version"],
                    "update_command": f"pip install {package['name']}>={package['latest_version']}"
                })

        except subprocess.CalledProcessError:
            pass

        return updates

    def generate_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report."""
        return {
            "scan_time": datetime.utcnow().isoformat(),
            "vulnerabilities": self.check_vulnerabilities(),
            "security_updates": self.get_security_updates(),
            "recommendations": self._get_security_recommendations()
        }

    def _get_security_recommendations(self) -> List[str]:
        """Get security recommendations."""
        return [
            "Regularly update dependencies to latest secure versions",
            "Run security scans in CI/CD pipeline",
            "Monitor security advisories for used packages",
            "Use dependency pinning for production deployments",
            "Implement automated security update process",
            "Review and audit new dependencies before adding"
        ]

# Usage
monitor = SecurityMonitor()
security_report = monitor.generate_security_report()
```

### Secure Development Practices
✅ **DO**: Follow secure development lifecycle
```python
# Security checklist for Python projects

SECURITY_CHECKLIST = {
    "code_review": [
        "All code changes reviewed by security-aware developers",
        "Security implications of changes considered",
        "No hardcoded secrets or credentials",
        "Input validation implemented for all user inputs",
        "Output encoding applied to prevent XSS"
    ],

    "testing": [
        "Security tests included in test suite",
        "Penetration testing performed regularly",
        "Fuzzing applied to input handling functions",
        "Authentication and authorization tested",
        "Error handling tested for information disclosure"
    ],

    "deployment": [
        "Secrets managed through secure secret management",
        "Security headers configured properly",
        "HTTPS enforced for all communications",
        "Security monitoring and logging enabled",
        "Regular security updates applied"
    ],

    "monitoring": [
        "Security events logged and monitored",
        "Anomaly detection implemented",
        "Incident response plan in place",
        "Regular security audits performed",
        "Vulnerability management process established"
    ]
}

def validate_security_compliance(project_path: str) -> Dict[str, bool]:
    """Validate project security compliance."""
    compliance = {}

    # Check for security configuration files
    security_files = {
        ".bandit": "Bandit configuration present",
        "security-scan.sh": "Security scanning script present",
        "SECURITY.md": "Security policy documented"
    }

    for file_name, description in security_files.items():
        file_path = os.path.join(project_path, file_name)
        compliance[description] = os.path.exists(file_path)

    # Check for security dependencies
    requirements_path = os.path.join(project_path, "requirements.txt")
    if os.path.exists(requirements_path):
        with open(requirements_path) as f:
            requirements = f.read()
            compliance["Security scanning tools installed"] = (
                "bandit" in requirements or "safety" in requirements
            )

    return compliance
```

### CI/CD Security Integration
✅ **DO**: Integrate security into CI/CD pipeline
```yaml
# .github/workflows/security.yml
name: Security Scans

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * 1'  # Weekly security scan

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install bandit safety pip-audit

    - name: Run Bandit security linter
      run: |
        bandit -r src/ -f json -o bandit-report.json
      continue-on-error: true

    - name: Run pip-audit vulnerability scan
      run: |
        pip-audit --format=json --output=vulnerabilities.json
      continue-on-error: true

    - name: Run Safety vulnerability scan
      run: |
        safety check --json --output=safety-report.json
      continue-on-error: true

    - name: Upload security reports
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: |
          bandit-report.json
          vulnerabilities.json
          safety-report.json

    - name: Security scan results
      run: |
        echo "Security scan completed. Check artifacts for detailed reports."

  secret-scan:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0  # Full history for secret scanning

    - name: Run TruffleHog secret scan
      uses: trufflesecurity/trufflehog@main
      with:
        path: ./
        base: main
        head: HEAD
```

### Error Handling and Logging Security
✅ **DO**: Implement secure error handling and logging
```python
import logging
import traceback
from typing import Any, Dict, Optional

class SecureLogger:
    """Secure logging implementation that prevents information disclosure."""

    def __init__(self, name: str, level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        # Configure secure formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def log_security_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log security event without sensitive information."""
        sanitized_details = self._sanitize_log_data(details or {})

        log_entry = {
            "event_type": event_type,
            "user_id": self._sanitize_user_id(user_id),
            "ip_address": self._sanitize_ip_address(ip_address),
            "details": sanitized_details
        }

        self.logger.warning(f"SECURITY_EVENT: {log_entry}")

    def log_error_safely(self, error: Exception, context: Dict[str, Any] = None) -> None:
        """Log error without exposing sensitive information."""
        error_type = type(error).__name__
        error_message = str(error)

        # Don't log full stack traces in production
        if self._is_production():
            sanitized_context = self._sanitize_log_data(context or {})
            self.logger.error(
                f"Error occurred: {error_type} - Context: {sanitized_context}"
            )
        else:
            # Full details in development
            self.logger.error(
                f"Error: {error_type}: {error_message}",
                extra={"context": context},
                exc_info=True
            )

    def _sanitize_log_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from log data."""
        sensitive_keys = {
            'password', 'token', 'secret', 'key', 'credential',
            'authorization', 'cookie', 'session', 'private'
        }

        sanitized = {}
        for key, value in data.items():
            key_lower = key.lower()

            # Check if key contains sensitive information
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_log_data(value)
            elif isinstance(value, str) and len(value) > 100:
                # Truncate long strings
                sanitized[key] = value[:100] + "..."
            else:
                sanitized[key] = value

        return sanitized

    def _sanitize_user_id(self, user_id: Optional[str]) -> Optional[str]:
        """Sanitize user ID for logging."""
        if not user_id:
            return None

        # Hash or partially mask user ID for privacy
        if len(user_id) > 6:
            return user_id[:3] + "*" * (len(user_id) - 6) + user_id[-3:]
        else:
            return "*" * len(user_id)

    def _sanitize_ip_address(self, ip_address: Optional[str]) -> Optional[str]:
        """Sanitize IP address for logging (GDPR compliance)."""
        if not ip_address:
            return None

        # Mask last octet of IPv4 addresses
        if '.' in ip_address:
            parts = ip_address.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.XXX"

        return ip_address

    def _is_production(self) -> bool:
        """Check if running in production environment."""
        return os.getenv("ENVIRONMENT", "development").lower() == "production"

# Usage
secure_logger = SecureLogger(__name__)

try:
    # Some operation
    pass
except Exception as e:
    secure_logger.log_error_safely(e, {"operation": "user_login", "user_id": "user123"})

# Log security event
secure_logger.log_security_event(
    "failed_login_attempt",
    user_id="user123",
    ip_address="192.168.1.100",
    details={"attempts": 3, "reason": "invalid_password"}
)
```

## References and Resources

### Security Standards and Guidelines
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Most critical web application security risks
- [OWASP Python Security](https://owasp.org/www-project-python-security/) - Python-specific security guidance
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Comprehensive cybersecurity framework
- [CWE Top 25](https://cwe.mitre.org/top25/) - Most dangerous software weaknesses

### Python Security Libraries
- [cryptography](https://cryptography.io/) - Modern cryptographic library for Python
- [passlib](https://passlib.readthedocs.io/) - Password hashing library
- [pydantic](https://pydantic-docs.helpmanual.io/) - Data validation using Python type annotations
- [bleach](https://bleach.readthedocs.io/) - HTML sanitization library
- [bcrypt](https://github.com/pyca/bcrypt/) - Password hashing function

### Security Tools
- [bandit](https://bandit.readthedocs.io/) - Security linter for Python code
- [safety](https://pypi.org/project/safety/) - Dependency vulnerability scanner
- [pip-audit](https://pypi.org/project/pip-audit/) - Vulnerability scanner for Python packages
- [truffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanner
- [semgrep](https://semgrep.dev/) - Static analysis tool with security rules

### Vulnerability Databases
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/) - U.S. government vulnerability database
- [CVE Database](https://cve.mitre.org/) - Common vulnerabilities and exposures
- [GitHub Security Advisories](https://github.com/advisories) - Security advisories for open source projects
- [PyUp Safety DB](https://pyup.io/safety/) - Python vulnerability database

### Security Testing Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - Web application security testing
- [Python Security Testing](https://python-security.readthedocs.io/) - Security testing for Python applications
- [Penetration Testing Framework](http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html) - Penetration testing methodology

### Compliance and Regulations
- [GDPR](https://gdpr-info.eu/) - General Data Protection Regulation
- [PCI DSS](https://www.pcisecuritystandards.org/) - Payment Card Industry Data Security Standard
- [SOC 2](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html) - Security, Availability, and Processing Integrity
- [ISO 27001](https://www.iso.org/isoiec-27001-information-security.html) - Information Security Management

### Additional Reading
- [Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/) - OWASP secure coding guidelines
- [Python Security Best Practices](https://python-security.readthedocs.io/) - Comprehensive Python security guide
- [Web Application Security Consortium](http://www.webappsec.org/) - Web application security resources
```
```
```
