# GitHub Actions Workflows

This directory contains CI/CD workflows for the EST Service project.

## Workflows

### [ci.yml](ci.yml) - Continuous Integration
Runs on every push and pull request.

**Jobs:**
- **Unit Tests**: Fast unit tests without external dependencies
  - Runs via `make test-unit`
  - Uploads coverage to Codecov
  - Runs in parallel with other jobs
- **Integration Tests**: Full integration tests with OpenBao
  - Uses OpenBao service container in dev mode
  - Tests are idempotent and self-initializing
  - Runs via `make test-integration`
  - Uploads integration coverage to Codecov
- **Lint**: golangci-lint checks
- **Build Binary**: Compiles the EST service binary
- **Build Container**: Builds Docker container image

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

## Testing Workflows Locally

### Using `act`

You can test workflows locally using [nektos/act](https://github.com/nektos/act):

```bash
# Install act (if not already installed)
brew install act  # macOS
# or
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash  # Linux

# List available jobs
act -l

# Run unit tests locally
act -j test-unit

# Run integration tests locally (requires Docker)
act -j test-integration

# Run all jobs
act
```

**Note**: Integration tests in `act` require Docker-in-Docker support and may have limitations with service containers.

### Manual Testing

For more reliable testing, run the commands directly:

```bash
# Unit tests
make test-unit

# Integration tests (requires OpenBao)
export BAO_ADDR=http://localhost:8200
export BAO_TOKEN=root-token
make test-integration

# Linting
make lint

# Build
make build
```

## CI/CD Architecture

### Test Strategy

The CI pipeline uses a **parallel testing strategy** for faster feedback:

```
┌─────────────┐  ┌──────────────────┐  ┌────────┐  ┌──────────────┐  ┌─────────────────┐
│  Unit Tests │  │ Integration Tests │  │  Lint  │  │ Build Binary │  │ Build Container │
│   (1-2 min) │  │    (3-5 min)     │  │(1 min) │  │   (1 min)    │  │    (2-3 min)    │
└─────────────┘  └──────────────────┘  └────────┘  └──────────────┘  └─────────────────┘
      ↓                   ↓                 ↓             ↓                    ↓
      └───────────────────┴─────────────────┴─────────────┴────────────────────┘
                                          │
                                     All Pass ✅
                                          │
                                    Merge Ready
```

**Benefits:**
- **Fast Feedback**: Unit tests complete quickly (1-2 min)
- **Parallel Execution**: Jobs run simultaneously
- **Resource Efficiency**: Only integration tests need service containers
- **Independent Failures**: One job failing doesn't block others

### Integration Test Details

The integration tests use **OpenBao** in dev mode as a service container:

- **Image**: `quay.io/openbao/openbao:latest`
- **Dev Mode**: Pre-configured root token, unsealed
- **Port**: 8200 (HTTP, no TLS in CI)
- **Initialization**: Tests are self-initializing (idempotent)

The tests automatically:
1. Wait for OpenBao to be ready
2. Create necessary PKI mounts
3. Generate root CAs
4. Configure authentication methods
5. Run all integration test suites

## Coverage Reporting

Both unit and integration tests upload coverage to Codecov:

- **Unit Tests**: Flag `unittests`
- **Integration Tests**: Flag `integration`

View combined coverage at: `https://codecov.io/gh/<org>/est-service`

## Troubleshooting

### Integration Tests Fail in CI

Check the "Wait for OpenBao" step logs:
- Ensure OpenBao container started successfully
- Check if port 8200 is accessible
- Verify dev mode environment variables

### Act Fails with Service Containers

`act` has limitations with service containers. For integration tests, use:
```bash
# Start OpenBao locally
docker run -d -p 8200:8200 \
  -e OPENBAO_DEV_ROOT_TOKEN_ID=root-token \
  quay.io/openbao/openbao:latest

# Run tests
export BAO_ADDR=http://localhost:8200
export BAO_TOKEN=root-token
make test-integration
```

### Workflow Syntax Errors

Validate YAML syntax before committing:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"
```
