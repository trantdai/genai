# Security Audit Workflow

## When to Use
Before production deployment, after dependency updates, or during regular security reviews.

## Prerequisites
- [ ] Security tools installed: `pip-audit`, `safety`, `bandit`, `detect-secrets`
- [ ] Virtual environment activated
- [ ] Access to project codebase

## Quick Audit

```bash
# Install tools
pip install pip-audit safety bandit detect-secrets

# Run all scans
pip-audit --desc
safety check
bandit -r src/
detect-secrets scan
```

## Dependency Vulnerability Scan

- [ ] Run pip-audit for CVE scan
- [ ] Run safety check for known vulnerabilities
- [ ] Review severity levels (Critical/High/Medium/Low)
- [ ] Check affected package versions
- [ ] Identify available patches

### Remediation
- [ ] Update vulnerable packages: `pip install --upgrade <package>`
- [ ] Consider alternatives if no fix available
- [ ] Update requirements.txt
- [ ] Rerun scans to verify fixes

## Secret Detection

- [ ] Initialize baseline: `detect-secrets scan > .secrets.baseline`
- [ ] Scan codebase for secrets
- [ ] Audit findings: `detect-secrets audit .secrets.baseline`
- [ ] Check for:
  - API keys and tokens
  - Database credentials
  - Private keys/certificates
  - AWS/cloud credentials
  - OAuth tokens
  - Passwords

### Remediation
- [ ] Remove hardcoded secrets
- [ ] Move to environment variables
- [ ] Rotate compromised credentials
- [ ] Add to .gitignore
- [ ] Update .secrets.baseline

## Code Security Analysis

- [ ] Run bandit: `bandit -r src/ -f json -o bandit-report.json`
- [ ] Review high/medium severity issues
- [ ] Check for:
  - SQL injection vulnerabilities
  - Command injection risks
  - Hardcoded passwords
  - Weak cryptography
  - Insecure temp file usage
  - Assert statements in production

### Remediation
- [ ] Fix high-severity issues immediately
- [ ] Address medium-severity issues
- [ ] Document risk acceptance for low-severity issues
- [ ] Add # nosec comments with justification (sparingly)

## Authentication & Authorization Check

- [ ] Password hashing uses bcrypt (12+ rounds)
- [ ] JWT tokens have short expiry (15 min access, 7 days refresh)
- [ ] Session management implemented correctly
- [ ] RBAC permissions enforced at function level
- [ ] No authentication bypasses
- [ ] Rate limiting implemented

## Input Validation

- [ ] All inputs validated with Pydantic
- [ ] SQL queries use parameterization
- [ ] File uploads validated (type, size, content)
- [ ] URL/path inputs sanitized
- [ ] HTML output encoded

## Configuration Review

- [ ] All secrets in environment variables
- [ ] HTTPS enforced in production
- [ ] Security headers configured (CSP, X-Frame-Options, etc.)
- [ ] CORS configured correctly
- [ ] Debug mode disabled in production
- [ ] Error messages don't leak sensitive info

## Dependency Audit

- [ ] No deprecated packages
- [ ] All packages actively maintained
- [ ] License compliance checked
- [ ] Transitive dependencies reviewed
- [ ] Minimal dependency count

## Generate Reports

```bash
# Dependency vulnerabilities
pip-audit --format json -o reports/pip-audit.json
safety check --json --output reports/safety.json

# Code security
bandit -r src/ -f json -o reports/bandit.json

# Secrets scan
detect-secrets scan --baseline reports/secrets.baseline
```

## Final Checklist

- [ ] All Critical/High severity issues resolved
- [ ] Medium severity issues addressed or risk-accepted
- [ ] No hardcoded secrets found
- [ ] Dependencies up to date
- [ ] Security tests passing
- [ ] Documentation updated
- [ ] Reports generated and archived

## Security Severity Guidelines

**Critical**: Fix immediately, block deployment
- SQL injection, authentication bypass, RCE
- Hardcoded admin credentials
- Known exploited CVEs

**High**: Fix before next deployment
- XSS, CSRF, insecure deserialization
- Weak crypto, missing auth checks
- High-severity dependency CVEs

**Medium**: Fix within sprint
- Information disclosure, weak validation
- Missing security headers
- Medium-severity dependency CVEs

**Low**: Document and schedule
- Code quality issues, best practices
- Low-severity dependency CVEs

## References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [pip-audit docs](https://pypi.org/project/pip-audit/)
- [safety docs](https://pypi.org/project/safety/)
- [bandit docs](https://bandit.readthedocs.io/)
- [detect-secrets docs](https://github.com/Yelp/detect-secrets)
