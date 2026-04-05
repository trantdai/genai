# Security Audit Workflow

## When to Use
Use this skill to perform comprehensive security audits on Python projects. Run before production deployments, after dependency updates, or as part of regular security reviews.

## Prerequisites
- Python project with dependencies defined
- Security scanning tools installed:
  - `pip-audit` for dependency vulnerability scanning
  - `safety` for known security vulnerabilities
  - `bandit` for code security analysis
  - `detect-secrets` for secret scanning
- Virtual environment activated
- Access to project codebase

## Workflow Steps

### 1. Setup and Environment Check
```bash
cd /path/to/project
source .venv/bin/activate

# Install security tools if not present
pip install pip-audit safety bandit detect-secrets
```

### 2. Scan Dependencies for Vulnerabilities
```bash
# Run pip-audit to check for known vulnerabilities
pip-audit --desc --format json -o pip-audit-report.json

# View results in terminal
pip-audit --desc

# Run safety check
safety check --json --output safety-report.json

# View safety results
safety check --full-report
```

**What to Look For**:
- CVE (Common Vulnerabilities and Exposures) identifiers
- Severity levels (Critical, High, Medium, Low)
- Affected package versions
- Available fixes or patches
- Transitive dependencies with vulnerabilities

**Remediation**:
```bash
# Update vulnerable packages
pip install --upgrade <package-name>

# If no fix available, consider alternatives
pip uninstall <vulnerable-package>
pip install <alternative-package>

# Update requirements
pip freeze > requirements.txt
```

### 3. Scan for Hardcoded Secrets
```bash
# Initialize detect-secrets baseline
detect-secrets scan > .secrets.baseline

# Scan for secrets in codebase
detect-secrets scan --baseline .secrets.baseline

# Audit findings
detect-secrets audit .secrets.baseline
```

**Common Secret Types to Find**:
- API keys and tokens
- Database credentials
- Private keys and certificates
- AWS access keys
- OAuth tokens
- Passwords and passphrases

**Remediation**:
```bash
# Remove secrets from code
# Move to environment variables
export API_KEY="your-key-here"

# Or use .env file (add to .gitignore)
echo "API_KEY=your-key-here" >> .env

# Use python-dotenv to load
from dotenv import load_dotenv
load_dotenv()
```

### 4. Code Security Analysis with Bandit
```bash
# Run bandit with detailed output
bandit -r src/ -f json -o bandit-report.json

# View high and medium severity issues
bandit -r src/ -ll

# Detailed report with code context
bandit -r src/ -v --format html -o bandit-report.html
```
**Security Issues Bandit Detects**:
- SQL injection vulnerabilities
- Command injection risks
- Insecure deserialization
- Weak cryptography
- Hardcoded passwords
- Use of eval/exec
- Insecure random number generation
- Path traversal vulnerabilities

### 5. Validate Input Validation Patterns
```bash
# Search for input validation patterns
grep -r "request\." src/ --include="*.py"
grep -r "input(" src/ --include="*.py"
grep -r "raw_input" src/ --include="*.py"
```

**Manual Review Checklist**:
- [ ] All user inputs are validated
- [ ] Input validation uses allowlists, not denylists
- [ ] Type checking is enforced (Pydantic models)
- [ ] Length limits are enforced
- [ ] Special characters are handled safely
- [ ] File uploads are validated (type, size, content)
- [ ] URL inputs are validated and sanitized

**Example Secure Input Validation**:
```python
from pydantic import BaseModel, Field, validator

class UserInput(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, regex="^[a-zA-Z0-9_]+$")
    email: str = Field(..., regex=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    age: int = Field(..., ge=0, le=150)

    @validator('username')
    def validate_username(cls, v):
        if v.lower() in ['admin', 'root', 'system']:
            raise ValueError('Reserved username')
        return v
```

### 6. Review Authentication and Authorization
```bash
# Search for authentication patterns
grep -r "authenticate\|login\|password" src/ --include="*.py"
grep -r "jwt\|token\|session" src/ --include="*.py"
grep -r "@require\|@login_required\|@permission" src/ --include="*.py"
```

**Security Checklist**:
- [ ] Passwords are hashed (bcrypt, argon2)
- [ ] Multi-factor authentication available
- [ ] Session tokens are secure and expire
- [ ] JWT tokens have expiration
- [ ] Authorization checks on all endpoints
- [ ] Principle of least privilege enforced
- [ ] Failed login attempts are rate-limited
- [ ] Account lockout after failed attempts

**Example Secure Authentication**:
```python
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(hours=1)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
```

### 7. Check SQL Injection Vulnerabilities
```bash
# Search for SQL query patterns
grep -r "execute\|cursor\|query" src/ --include="*.py"
grep -r "SELECT\|INSERT\|UPDATE\|DELETE" src/ --include="*.py" -i
```

**SQL Injection Prevention**:
- [ ] Use parameterized queries exclusively
- [ ] Use ORM (SQLAlchemy, Django ORM)
- [ ] Never concatenate user input into SQL
- [ ] Validate and sanitize all inputs
- [ ] Use stored procedures where appropriate
- [ ] Implement least privilege database access

**Vulnerable Code (DON'T DO THIS)**:
```python
# ❌ VULNERABLE - SQL Injection risk
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)
```

**Secure Code (DO THIS)**:
```python
# ✅ SECURE - Parameterized query
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))

# ✅ SECURE - Using ORM
user = session.query(User).filter(User.username == username).first()
```

### 8. Verify Secure Error Handling
```bash
# Search for error handling patterns
grep -r "except\|raise\|Exception" src/ --include="*.py"
grep -r "traceback\|debug" src/ --include="*.py"
```

**Error Handling Security Checklist**:
- [ ] Errors don't expose sensitive information
- [ ] Stack traces not shown to users in production
- [ ] Generic error messages for authentication failures
- [ ] Detailed errors logged securely
- [ ] No database schema exposed in errors
- [ ] No file paths exposed in errors

**Example Secure Error Handling**:
```python
import logging
from fastapi import HTTPException

logger = logging.getLogger(__name__)

try:
    result = process_sensitive_data(user_input)
except ValueError as e:
    # Log detailed error securely
    logger.error(f"Processing failed: {str(e)}", exc_info=True)
    # Return generic error to user
    raise HTTPException(status_code=400, detail="Invalid input provided")
except Exception as e:
    # Log unexpected errors
    logger.critical(f"Unexpected error: {str(e)}", exc_info=True)
    # Return generic error
    raise HTTPException(status_code=500, detail="An error occurred")
```

### 9. Generate Security Report
```bash
# Create comprehensive security report
cat > security-audit-report.md << 'EOF'
# Security Audit Report
**Date**: $(date +%Y-%m-%d)
**Auditor**: $(git config user.name)
**Project**: $(basename $(pwd))

## Executive Summary
<!-- High-level overview of security posture -->

## Vulnerability Scan Results
### Dependency Vulnerabilities
- Critical: X
- High: X
- Medium: X
- Low: X

### Code Security Issues
- Critical: X
- High: X
- Medium: X
- Low: X

## Findings

### Critical Issues
<!-- List critical security issues -->

### High Priority Issues
<!-- List high priority issues -->

### Medium Priority Issues
<!-- List medium priority issues -->

## Recommendations
1. <!-- Prioritized recommendations -->

## Remediation Plan
<!-- Action items with timeline -->

## Compliance Status
- [ ] OWASP Top 10 compliance
- [ ] Input validation implemented
- [ ] Authentication secure
- [ ] Authorization enforced
- [ ] Secrets management proper
- [ ] Error handling secure
- [ ] Logging implemented

## Next Steps
<!-- Follow-up actions -->
EOF
```

### 10. Run Comprehensive Security Check Script
```bash
# Create automated security audit script
cat > security-audit.sh << 'EOF'
#!/bin/bash
set -e

echo "🔒 Starting Security Audit..."
echo ""

echo "1️⃣ Scanning dependencies for vulnerabilities..."
pip-audit --desc || true
safety check --full-report || true

echo ""
echo "2️⃣ Scanning for hardcoded secrets..."
detect-secrets scan --baseline .secrets.baseline || true

echo ""
echo "3️⃣ Running code security analysis..."
bandit -r src/ -ll || true

echo ""
echo "4️⃣ Checking for common security issues..."
grep -r "eval\|exec\|pickle" src/ --include="*.py" || echo "No dangerous functions found"

echo ""
echo "5️⃣ Checking authentication patterns..."
grep -r "password.*=.*['\"]" src/ --include="*.py" || echo "No hardcoded passwords found"

echo ""
echo "✅ Security audit complete! Review reports for details."
EOF

chmod +x security-audit.sh
./security-audit.sh
```

## Success Criteria
- ✅ No critical or high severity vulnerabilities in dependencies
- ✅ No hardcoded secrets in codebase
- ✅ No critical security issues in code (bandit)
- ✅ Input validation implemented on all endpoints
- ✅ Authentication and authorization properly implemented
- ✅ SQL injection prevention in place
- ✅ Secure error handling implemented
- ✅ Security logging configured
- ✅ All findings documented in report

## Common Issues

### Issue: Too many false positives from bandit
**Solution**:
```toml
# pyproject.toml
[tool.bandit]
exclude_dirs = ["tests/", "migrations/"]
skips = ["B101", "B601"]  # Skip assert and shell injection in specific contexts

[tool.bandit.assert_used]
skips = ["*/test_*.py", "*/tests.py"]
```

### Issue: Dependency has no fix available
**Solution**:
1. Check if vulnerability affects your usage
2. Look for alternative packages
3. Implement workarounds or mitigations
4. Document risk acceptance if necessary
5. Monitor for future patches

### Issue: Secrets detected in git history
**Solution**:
```bash
# Use BFG Repo-Cleaner to remove secrets from history
bfg --replace-text passwords.txt

# Or use git-filter-repo
git filter-repo --path-glob '**/*.env' --invert-paths

# Rotate all exposed secrets immediately
# Update secret management system
```

### Issue: SQL injection in legacy code
**Solution**:
```python
# Refactor to use parameterized queries
# Before (vulnerable):
query = f"SELECT * FROM users WHERE id = {user_id}"

# After (secure):
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))

# Or migrate to ORM:
user = session.query(User).filter(User.id == user_id).first()
```

## Examples

### Example 1: Quick Security Check
```bash
# Run quick security scan before commit
pip-audit --desc && \
bandit -r src/ -ll && \
detect-secrets scan --baseline .secrets.baseline

echo "✅ Quick security check passed"
```

### Example 2: Pre-Production Security Audit
```bash
# Comprehensive audit before production deployment
echo "Running comprehensive security audit..."

# Dependency scan
pip-audit --desc --format json -o reports/pip-audit.json

# Code security
bandit -r src/ -f json -o reports/bandit.json

# Secret scan
detect-secrets scan > reports/secrets.baseline

# Generate report
python scripts/generate_security_report.py

echo "Review reports/ directory for findings"
```

### Example 3: CI/CD Security Gate
```yaml
# .github/workflows/security-audit.yml
name: Security Audit
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
      - name: Install tools
        run: pip install pip-audit safety bandit detect-secrets
      - name: Dependency scan
        run: pip-audit --desc
      - name: Code security
        run: bandit -r src/ -ll
      - name: Secret scan
        run: detect-secrets scan --baseline .secrets.baseline
```

## Related Skills
- [`code-review-workflow.md`](./code-review-workflow.md) - Include security in code reviews
- [`dependency-update.md`](./dependency-update.md) - Update vulnerable dependencies
- [`tdd-workflow.md`](./tdd-workflow.md) - Write security tests

## Best Practices
- Run security audits regularly (weekly/monthly)
- Automate security scanning in CI/CD
- Keep security tools updated
- Document all security findings
- Prioritize critical and high severity issues
- Implement defense in depth
- Follow principle of least privilege
- Use security linters in IDE
- Train team on secure coding practices
- Maintain security baseline and track improvements
- Rotate secrets regularly
- Monitor security advisories for dependencies
- Conduct periodic penetration testing
- Implement security logging and monitoring

