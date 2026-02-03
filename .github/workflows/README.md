# GitHub Actions Workflows

This directory contains CI/CD workflows for the EST Service project.

## Workflows

### [ci.yml](ci.yml) - Continuous Integration
Runs on every push and pull request.

**Jobs:**
- **Test**: Unit tests with coverage
- **Lint**: golangci-lint checks
- **Build**: Binary build
- **Integration Test**: Integration tests against backend
- **OpenAPI Validation**: OpenAPI spec validation

### [security.yml](security.yml) - Security Scanning
Runs on push, pull request, and scheduled scans.

**Jobs:**
- **govulncheck**: Go vulnerability scanning
- **gosec**: Static security analysis
- **Trivy**: Container vulnerability scanning
- **Dependency Review**: PR dependency checks
- **Secret Scanning**: Detect leaked secrets

### [release.yml](release.yml) - Release Builds
Builds and publishes release artifacts.

### [openapi.yml](openapi.yml) / [openapi.yaml](openapi.yaml)
OpenAPI linting/validation workflows.
