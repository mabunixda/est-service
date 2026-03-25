# EST-Service Code Review TODOs

**Date:** 2026-02-05  
**Reviewers:** GitHub Copilot (as Senior Go Engineer), Codex

---

## TODO List (Merged)

- [x] Fix `/health/deep` response body status drift: if TLS cert checks downgrade service status, update `response.Status` accordingly so JSON matches the computed status. (`pkg/server/server.go`)
- [x] Telemetry: attach all configured metric readers (Prometheus + OTLP) instead of only the first reader. (`pkg/server/telemetry.go`)
- [x] Server keygen: when `encrypt_private_key` is enabled, ensure a client certificate can receive an encrypted password (RSA) or fail fast; avoid returning unusable encrypted keys. (`pkg/handlers/serverkeygen.go`)
- [x] Auth failure metrics: use `auth.method` label correctly (avoid recording identity as method). (`pkg/handlers/base_enrollment.go`)
- [x] Rate limiter cleanup: current cleanup only removes entries at full token bucket; add last-seen tracking or cap map size to prevent unbounded growth under constant abuse. (`pkg/server/ratelimit.go`)
- [x] Re-enable or replace disabled tests (e.g., `.disabled` files) to improve coverage and prevent regressions. (Replaced with basic tests: `pkg/handlers/simpleenroll_basic_test.go`, `pkg/handlers/simplereenroll_basic_test.go`)

---

## Items From Prior Review (Verify/Close)

- [x] Verify whether handler duplication still exists between `simpleenroll` and `simplereenroll`. (Shared `baseEnrollmentHandler` already in place.)
- [x] Verify redundant authentication checks in handlers vs. middleware. (No redundant auth in middleware for EST endpoints.)
- [x] Use `encoding/json` for health responses. (Already implemented with `json.NewEncoder` in health handlers.)
- [x] Optimize Bearer token validation to a single lookup call. (Current implementation uses `LookupToken` only.)
