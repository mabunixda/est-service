# GitHub Actions Workflows

This directory contains CI/CD workflows for the EST Service project.

## Workflows

### [ci.yml](ci.yml) - Continuous Integration
Runs on every push and pull request.

**Jobs:**
- **Test**: Unit tests across Go 1.21, 1.22, 1.23 with coverage
- **Lint**: Code quality checks with golangci-lint
- **Build**: Binary compilation and Docker image build
- **Integration Test**: Full integration tests with Vault
- **OpenAPI Validation**: API spec validation

### [security.yml](security.yml) - Security Scanning
Runs on push, pull request, and daily schedule.

**Jobs:**
- **govulncheck**: Go vulnerability scanner
- **gosec**: Static security analysis
- **Trivy**: Container vulnerability scanning
- **Dependency Review**: PR dependency analysis
- **Secret Scanning**: Detect leaked secrets with TruffleHog

### [codeql.yml](codeql.yml) - Code Analysis
Runs on push, pull request, and wee# GitHub Actions Workflows

This directory contains CI/CD workflows for the EST Service project.

## Workflows
ml
This directory contains ns 
## Workflows

### [ci.yml](ci.yml) - Continuous Integration
Runs o bi
### [ci.ym
- Runs on every push and pull request.

**JobsKu
**Jobs:**
- **Test**: Unit tests aSta- **Testes- **Lint**: Code quality checks with golangci-lint
- **Build**un- **Build**: Binary compilation and Dockerbadge.svg- **Integration Test**: Full integration tests with Vor- **OpenAPI Validation**: API spec validation

### [secu/e
### [security.yml](security.yml) - SecuritydgeRuns on push, pull request, and daily schedule.

**io
**Jobs:**
- **govulncheck**: Go vulnerabilitygit- **govuma- **gosec**: Static security analysis
- **ql- **Trivy**: Container vulnerab.com/ma- **Dependency Review**: PR dependency analy.y- **Secret Scanning**: Detect leaked secrets wto
### [codeql.yml](codeql.yml) - Code Analysis
Runs oRun workflRuns on push, pull request, and wee# GitHubui
This directory contains CI/CD workflows for the EST Servicens

## Workflows
ml
This directory contains ns 
## Workflows

### [ci.Optml
This dirDoTke## Workflows

### [ci.yml]ee
### [ci.ym.mdRuns o bi
### [ci.ym
- Runs on every push antion.
