# Security & Secrets Management Standards

## Architecture Documentation Review
- Study security patterns documented in `docs/` directory
- Follow established security architecture and threat models
- Maintain consistency with documented security controls
- Review security documentation before implementing changes

## Secure Coding Fundamentals
- **Principle of Least Privilege**: Grant minimal necessary permissions
- **Defense in Depth**: Implement multiple security layers
- **Fail Securely**: Ensure failures don't compromise security
- **Input Validation**: Validate all inputs at trust boundaries
- **Output Encoding**: Properly encode outputs to prevent injection
- **Authentication**: Use strong, multi-factor authentication
- **Session Management**: Implement secure session handling with timeouts
- **Error Handling**: Never expose sensitive information in errors
- **Cryptography**: Use established libraries and algorithms (never roll your own)
- **Logging**: Log security events without exposing secrets
- **Secure Defaults**: Use secure configurations by default

## Common Vulnerability Prevention
- **SQL Injection**: Use parameterized queries or ORMs exclusively
- **XSS (Cross-Site Scripting)**: Implement proper output encoding and CSP
- **CSRF**: Use CSRF tokens for state-changing operations
- **Path Traversal**: Validate and sanitize all file paths
- **Command Injection**: Avoid shell execution, use safe APIs
- **Insecure Deserialization**: Validate and sanitize serialized data
- **XXE (XML External Entity)**: Disable external entity processing
- **SSRF**: Validate and whitelist URLs for external requests
- **Broken Authentication**: Implement proper session management and MFA
- **Sensitive Data Exposure**: Encrypt data at rest and in transit

## HashiCorp Vault Integration
- Use Vault for all secrets management following documented patterns
- Implement dynamic secrets where possible
- Use short-lived tokens and credentials (TTL < 24 hours)
- Implement proper secret rotation policies
- Use namespaces for multi-tenancy and isolation
- Enable comprehensive audit logging
- Use AppRole or Kubernetes auth methods (avoid root tokens)
- Never log secrets, tokens, or credentials
- Implement proper secret versioning
- Use Vault policies for fine-grained access control

## Secret Handling Best Practices
- Never commit secrets to version control
- Use .gitignore for sensitive files and patterns
- Scan commits for secrets (git-secrets, truffleHog, Gitleaks)
- Use environment variables for runtime secrets
- Implement automated secret rotation procedures
- Use encrypted storage for secrets at rest
- Implement secret versioning and rollback capabilities
- Use secret management tools (Vault, AWS Secrets Manager, Azure Key Vault)
- Implement proper secret access logging
- Use temporary credentials where possible

## Access Control & Authentication
- Implement role-based access control (RBAC)
- Use multi-factor authentication (MFA) for all human access
- Implement least privilege principle
- Regular access reviews and audits
- Use service accounts for application access
- Implement proper session management with timeouts
- Log all access to sensitive resources
- Use OAuth2/OIDC for authentication where appropriate
- Implement proper password policies (length, complexity, rotation)

## Dependency Security
- Regular dependency updates with security focus
- Use automated vulnerability scanning (Dependabot, Renovate, Snyk)
- Scan dependencies for known vulnerabilities (CVEs)
- Review security advisories for all dependencies
- Pin dependencies to known-good versions using `>=` constraints
- Use private registries for internal packages
- Implement Software Bill of Materials (SBOM) tracking
- Use dependency lock files (package-lock.json, poetry.lock, go.sum)
- Monitor for supply chain attacks

## Network Security
- Use TLS 1.2+ for all communications
- Implement proper certificate management
- Use network segmentation and firewalls
- Implement rate limiting and DDoS protection
- Use VPNs or private networks for sensitive communications
- Implement proper DNS security (DNSSEC)
- Use security groups and network policies

## Monitoring & Incident Response
- Implement security event logging
- Monitor for suspicious activities
- Set up alerts for security events
- Implement incident response procedures
- Regular security audits and penetration testing
- Maintain security incident documentation
- Implement proper backup and recovery procedures
