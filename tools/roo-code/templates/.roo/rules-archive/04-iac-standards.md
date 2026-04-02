# Infrastructure as Code Standards

## Architecture Consistency
- Study and follow patterns established in `docs/` directory
- Maintain consistency with existing infrastructure patterns
- Document architectural decisions in ADRs (Architecture Decision Records)
- Review existing infrastructure before making changes

## General Security Principles
- All infrastructure must be defined as code
- No manual changes to production infrastructure
- Implement least privilege access everywhere
- Enable encryption at rest and in transit by default
- Regular security scanning of all IaC code
- Use version control for all IaC files
- Implement proper state management and locking

## Terraform
- Use latest stable Terraform version
- Organize code into logical modules following documented patterns
- Use remote state with state locking (S3 + DynamoDB)
- Pin provider versions using `>=` constraints for stability
- Use variables for all configurable values
- Tag all resources with: Environment, Project, ManagedBy, Owner, CostCenter
- Implement proper secret management (never hardcode secrets)
- Use terraform fmt before committing
- Run terraform validate and security scanning in CI/CD
- Use terraform-docs for module documentation
- Implement proper workspace strategy (dev/staging/prod)
- Use data sources to reference existing resources
- Implement proper dependency management with depends_on

## CloudFormation
- Use YAML format for readability
- Organize stacks by lifecycle and dependencies per documentation
- Use nested stacks for complex deployments
- Implement proper parameter validation and constraints
- Use CloudFormation Linter (cfn-lint) and security scanning in CI/CD
- Tag all resources consistently
- Use stack policies to prevent accidental deletion
- Export outputs for cross-stack references
- Use IAM roles with minimal permissions
- Implement proper rollback configuration

## Kubernetes & Helm Security
- Use Helm charts following documented patterns
- Pin chart versions using `>=` constraints
- Use values files per environment (values-dev.yaml, values-prod.yaml)
- Implement Pod Security Standards (restricted profile)
- Use network policies for micro-segmentation
- Implement proper RBAC with minimal permissions
- Use secrets management (HashiCorp Vault integration)
- Define resource limits and requests for all containers
- Define health checks (liveness, readiness, startup probes)
- Use HPA (Horizontal Pod Autoscaler) where appropriate
- Scan container images for vulnerabilities
- Use admission controllers for policy enforcement
- Implement proper namespace isolation
- Use service mesh for advanced traffic management

## Security Best Practices
- Never commit secrets or credentials
- Use secret management tools (HashiCorp Vault, AWS Secrets Manager)
- Implement least privilege access
- Enable encryption at rest and in transit
- Regular security scanning of IaC code
- Use private registries for container images
- Implement network segmentation
- Use security groups and NACLs properly
- Enable audit logging for all resources
