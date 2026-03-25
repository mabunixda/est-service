# Copilot Instructions for est-service

## Architecture map (big picture)
- Entry point is [cmd/est-service/main.go](cmd/est-service/main.go): loads config, builds backend client, auth manager, server, and starts HTTP(S).
- Core server lives in [pkg/server/server.go](pkg/server/server.go): routing, TLS setup, middleware, rate limiting, health endpoints.
- EST protocol handlers are in [pkg/handlers/](pkg/handlers/) (e.g., enroll, reenroll, csrattrs, serverkeygen) and operate on parsed CSRs and backend operations.
- Backend abstraction is in [pkg/backend/](pkg/backend/); two concrete implementations exist (OpenBao). The server uses backend.Client which wraps a backend.Backend.
- CSR parsing/validation and PKCS7 helpers are in [pkg/est/](pkg/est/).
- Configuration structs and defaults are in [pkg/config/](pkg/config/). Example configs in [configs/](configs/).

## Key flows and why
- HTTP request → server middleware (rate-limit, request-id, security headers) → handler → backend. See [pkg/server/server.go](pkg/server/server.go).
- Cert-auth uses backend entity/alias creation to preserve per-client identity (do not forward client TLS directly). See [pkg/backend/](pkg/backend/).
- Enrollment handlers build an EnrollmentRequest and call backend signing paths via helper logic in handlers. See [pkg/handlers/](pkg/handlers/).

## Developer workflows (local/CI)
- Unit tests: `make test` or `make test-unit` (fast, no Docker). See [README.md](README.md).
- Integration tests (requires OpenBao): `make test-integration` with `BAO_ADDR/BAO_TOKEN` or `BAO_ADDR/BAO_TOKEN`. See [test/integration/README.md](test/integration/README.md).
- Full suite: `make test-all`. Coverage: `make test-coverage` or `go test -coverprofile=coverage.out ./...`.
- CI runs unit, integration, lint, build, and container build. See [.github/workflows/README.md](.github/workflows/README.md).

## Project-specific conventions
- EST endpoints are mounted under `/.well-known/est/*` and return PKCS#7 or multipart responses per RFC 7030. See [pkg/handlers/](pkg/handlers/).
- CSR size limits and signature algorithm checks are enforced in [pkg/est/csr.go](pkg/est/csr.go).
- Label-based routing uses `EnrollmentConfig.Labels` to map label → role/mount/TTL. See [pkg/handlers/types.go](pkg/handlers/types.go).
- Server TLS config supports optional client-auth via `TLSConfig.ClientCAFile` and `ClientAuthRequired`. See [pkg/server/server.go](pkg/server/server.go).

## Integration points
- Backend PKI and auth operations use OpenBao APIs via [pkg/backend/](pkg/backend/).
- Integration tests are tagged with `//go:build integration` in [pkg/backend/](pkg/backend/) and [test/integration/](test/integration/).
- Shell-based E2E scripts live in [test/scripts/](test/scripts/), designed to be portable across macOS/Linux/BSD.
