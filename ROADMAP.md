# auth-local — Implementation Roadmap

**Priority:** P0 — Required before any HTTP/gRPC access is possible.

## Phases

### Phase 1: Core Proto + Adapters (core changes) ✅
- [x] Add AuthService proto to core + generate code
- [x] SidecarAuthProvider, SidecarAuthorizer, SidecarIdentityProvider adapters
- [x] Wire auth re-discovery into main.go's post-spawn poll loop

### Phase 2: SQLite + Password Auth ✅
- [x] go.mod with modernc.org/sqlite and bcrypt
- [x] SQLite schema + auto-migration
- [x] User CRUD (create, read, delete, list)
- [x] bcrypt password hashing
- [x] AuthProvider.Authenticate (password → full or partial token)
- [x] AuthProvider.Validate (token → session)
- [x] AuthProvider.Revoke (delete session)
- [x] Partial token support (5-minute TTL, upgradeable)
- [x] gRPC AuthService server (5 RPCs)
- [x] Sidecar entry point (registration, cleanup goroutine)
- [x] 27 store tests, 9 server tests

### Phase 3: TOTP
- [ ] TOTP secret generation + QR code URL
- [ ] TOTP code verification
- [ ] Login flow: password → partial → TOTP → full session
- [ ] Admin CLI: totp enable/disable/status

### Phase 4: Passkey / WebAuthn ✅
- [x] WebAuthn dependency (go-webauthn v0.17)
- [x] Credential storage in SQLite (webauthn_credentials table)
- [x] WebAuthn session store (webauthn_sessions table)
- [x] Registration: begin (challenge) + complete (verify)
- [x] Passwordless login: begin (challenge) + complete (verify assertion)
- [x] HTTP server on separate port for browser-facing WebAuthn endpoints
- [x] RP configuration via CLI flags

### Phase 5: RBAC Policy File ✅
- [x] YAML RBAC policy file parser with glob permission matching
- [x] Replaces hardcoded authorize function when loaded
- [x] Built-in fallback (admin/manager/user/viewer) when no file given
- [x] `--policy-file` flag in entry point
- [x] SIGHUP-ready Replace() for future hot-reload
- [x] 12 unit tests for permission matching

### Phase 6: Admin CLI + API Tokens ✅
- [x] User management RPCs: CreateUser, DeleteUser, ListUsers, SetPassword, SetRoles
- [x] API token CRUD: CreateAPIToken, ListAPITokens, DeleteAPIToken
- [x] `api-key` credential type in Authenticate handler
- [x] API tokens have `mct_` prefix, SHA-256 hashed in storage
- [x] `authctl` CLI: adduser, passwd, rm, list, addrole, rmrole, totp, token
- [x] AuthService proto extended with admin + token RPCs
