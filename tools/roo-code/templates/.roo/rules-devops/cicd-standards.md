# CI/CD & GitHub Actions Standards

## General Principles
- Automate everything: build, test, security scan, deploy
- Fail fast: run quick tests first
- Implement proper secret management
- Use caching to speed up workflows
- Implement proper error handling and notifications
- Follow patterns documented in `docs/` directory

## GitHub Actions Best Practices
- Pin action versions to specific commits or major versions with SHA
- Use reusable workflows for common patterns
- Implement proper matrix testing for multiple versions/platforms
- Use GitHub-hosted runners for standard tasks
- Use self-hosted runners for sensitive operations or special requirements
- Implement proper OIDC authentication (no long-lived credentials)
- Use environments for deployment protection rules
- Implement required status checks before merge
- Use concurrency controls to prevent duplicate runs
- Implement proper workflow permissions (least privilege)

## Pipeline Stages
1. **Lint & Format**: Code style checks (Black, Ruff, ESLint, Prettier)
2. **Security Scan**: Dependency and code vulnerability scanning
3. **Unit Tests**: Fast, isolated tests with coverage reporting
4. **Integration Tests**: Tests with external dependencies
5. **Build**: Create artifacts/images with proper tagging
6. **Security Scan (Artifacts)**: Scan built images/artifacts
7. **Deploy**: Environment-specific deployment with approval gates

## Testing in CI/CD
- Run tests in parallel where possible
- Generate and publish coverage reports
- Fail builds on coverage decrease below threshold (80%)
- Run security scans on every PR
- Implement smoke tests post-deployment
- Use test result caching to speed up reruns
- Implement flaky test detection and handling

## Security in CI/CD
- Scan dependencies for vulnerabilities (Dependabot, Snyk)
- Scan code for security issues (CodeQL, Semgrep)
- Scan container images (Trivy, Snyk)
- Scan IaC for misconfigurations (Checkov, tfsec)
- Never log secrets or sensitive data
- Use secret scanning tools (git-secrets, truffleHog)
- Implement SAST and DAST where appropriate
- Use signed commits and verified workflows

## Deployment Strategies
- Use blue-green or canary deployment strategies
- Implement automatic rollback on failure
- Use feature flags for gradual rollouts
- Implement proper health checks before traffic routing
- Tag releases with semantic versioning
- Generate release notes automatically
- Implement deployment approval gates for production
- Use infrastructure as code for deployment configuration

## Monitoring & Notifications
- Send notifications on build failures
- Monitor deployment success/failure
- Track deployment metrics (frequency, lead time, MTTR)
- Implement proper logging in CI/CD pipelines
- Alert on security vulnerabilities found

## Caching Strategies
- Cache dependencies (npm, pip, go modules)
- Cache build artifacts where appropriate
- Use layer caching for Docker builds
- Implement cache invalidation strategies
- Monitor cache hit rates
