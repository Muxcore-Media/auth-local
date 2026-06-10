# auth-local — Implementation Roadmap

**Priority:** P0 — Required before any HTTP/gRPC access is possible.

This is the largest module. Estimated effort: 4-5 days.

## Phases

### Phase 1: Core Auth (day 1-2)
- [x] Project scaffold (this repo)
- [ ] `go mod init` with core dependency
- [ ] SQLite user store (open, migrate, close)
- [ ] Bcrypt password hashing
- [ ] `AuthProvider.Authenticate` — password → token
- [ ] `AuthProvider.Validate` — token → session
- [ ] `AuthProvider.Revoke` — invalidate token
- [ ] `IdentityProvider.ExtractIdentity` — read token from gRPC metadata / HTTP header
- [ ] Sidecar entry point (`cmd/module/main.go`)
- [ ] Unit tests: user store CRUD, auth flow, token TTL (50+ tests)

### Phase 2: RBAC (day 3)
- [ ] `Authorizer.Can` — role-based permission check
- [ ] `ResourceAuthorizer.CanWithResource` — resource-level ABAC
- [ ] Policy file parser (`policies.yaml`)
- [ ] Default role definitions (admin, manager, user, viewer)
- [ ] Role assignment in user store
- [ ] Unit tests: permission matrix, policy file loading (30+ tests)

### Phase 3: Admin CLI & Integration (day 4-5)
- [ ] `adduser` subcommand (interactive + flag-based)
- [ ] `passwd`, `rm`, `list`, `revoke` subcommands
- [ ] SIGHUP reload for policy file
- [ ] Brute-force protection (failure tracking, backoff)
- [ ] Audit logging of all auth events
- [ ] Prometheus metrics (auth success/failure counters)
- [ ] Health endpoint
- [ ] Integration test with running muxcored
- [ ] GitHub CI (build + lint + test)

### Phase 4: Polish
- [ ] API token management (scoped tokens for automation)
- [ ] Password complexity enforcement
- [ ] Session cleanup goroutine (expired token purge)
- [ ] Configurable token hashing (SHA-256 configurable)
- [ ] Graceful shutdown / SIGHUP reload of config

## Design Decisions

1. **Three contracts, one binary** — Deploying one module is simpler than three.
   The three concerns are tightly coupled in practice.
2. **SQLite** — Zero-dependency storage. Pure Go driver avoids CGO.
3. **Bcrypt cost 12** — Balances security and latency. Cost 12 ≈ 250ms on modern hardware.
4. **YAML policies** — Same format as call-policy-default for operator consistency.
5. **API tokens as a separate credential type** — Supports `CredentialTypeAPIKey` from core contracts.
