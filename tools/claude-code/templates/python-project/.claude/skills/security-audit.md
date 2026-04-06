# Security Audit Workflow

## Tools
`pip-audit`, `safety`, `bandit`, `detect-secrets`

## Steps

### 1. Dependency Scan
- [ ] Run `pip-audit --desc`
- [ ] Run `safety check`
- [ ] Update vulnerable packages
- [ ] Rerun to verify

### 2. Secret Detection
- [ ] Run `detect-secrets scan > .secrets.baseline`
- [ ] Audit: `detect-secrets audit .secrets.baseline`
- [ ] Remove hardcoded secrets → environment variables
- [ ] Rotate compromised credentials

### 3. Code Security
- [ ] Run `bandit -r src/`
- [ ] Fix high/medium severity issues
- [ ] Check: SQL injection, command injection, weak crypto

### 4. Configuration
- [ ] Secrets in environment variables
- [ ] HTTPS enforced
- [ ] Security headers configured
- [ ] Debug mode disabled in production

### 5. Authentication & Authorization
- [ ] Password hashing: bcrypt 12+ rounds
- [ ] JWT: 15min access, 7-day refresh max
- [ ] Rate limiting implemented
- [ ] RBAC enforced

## Severity Actions
- **Critical**: Block deployment (SQL injection, auth bypass, RCE)
- **High**: Fix before deployment (XSS, CSRF, weak crypto)
- **Medium**: Fix within sprint
- **Low**: Document and schedule

See: [`.claude/rules/python-security.md`](../rules/python-security.md)
