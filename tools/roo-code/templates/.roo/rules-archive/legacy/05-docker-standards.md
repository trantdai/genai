# Docker & Container Standards

## Architecture Alignment
- Follow containerization patterns documented in `docs/` directory
- Maintain consistency with existing container architectures
- Review existing Dockerfiles before creating new ones

## Dockerfile Security Best Practices
- Use official, minimal base images from trusted sources
- Pin specific image versions using `>=` constraints (avoid `latest`)
- Use multi-stage builds to minimize attack surface and image size
- Run containers as non-root user (create dedicated user)
- Use .dockerignore to exclude unnecessary and sensitive files
- Never include secrets in images or layers
- Implement proper HEALTHCHECK instructions
- Use COPY instead of ADD unless extracting archives
- Keep containers immutable (no runtime changes)
- Minimize layers by combining RUN commands strategically
- Order instructions from least to most frequently changing
- Set proper labels for metadata (version, maintainer, etc.)

## Image Management
- Tag images with semantic versioning and git commit SHA
- Use descriptive and consistent naming conventions
- Scan images for vulnerabilities before deployment (Trivy, Snyk, Grype)
- Sign images for supply chain security
- Use private registries for proprietary code
- Regular base image updates for security patches
- Implement image retention policies
- Use image digests for production deployments

## Container Runtime Security
- Use read-only root filesystem where possible
- Drop all unnecessary capabilities (--cap-drop=ALL)
- Use security scanning in CI/CD pipeline
- Implement resource limits (CPU, memory) to prevent DoS
- Use AppArmor or SELinux profiles
- Never run privileged containers in production
- Use seccomp profiles to restrict system calls
- Implement proper logging and monitoring
- Use tmpfs for temporary file storage

## Docker Compose
- Use version 3.8+ for compose files
- Define health checks for all services
- Use named volumes for persistent data
- Implement proper networking between services
- Use environment-specific compose files (docker-compose.dev.yml, docker-compose.prod.yml)
- Document service dependencies clearly
- Use secrets management for sensitive data
- Implement resource limits for all services

## Container Optimization
- Minimize image size by removing unnecessary files
- Use .dockerignore effectively
- Clean up package manager caches in the same RUN layer
- Use alpine or distroless base images where appropriate
- Leverage build cache effectively
- Use multi-stage builds to separate build and runtime dependencies
