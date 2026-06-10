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

### Phase 4: Passkey / WebAuthn
- [ ] WebAuthn RP configuration
- [ ] Credential registration (begin + complete)
- [ ] Passwordless authentication (begin + complete)
- [ ] 2FA authentication (password → partial → passkey → full)

### Phase 5: RBAC + IdentityProvider
- [x] Embedded RBAC in server (admin/manager/user/viewer)
- [ ] Policy file parser (YAML)
- [ ] ResourceAuthorizer.CanWithResource (ABAC support)
- [ ] IdentityProvider.ExtractIdentity (from gRPC metadata)

### Phase 6: Admin CLI + API Tokens
- [ ] Admin CLI: all user management commands
- [ ] API token CRUD
- [ ] `CredentialTypeAPIKey` support
- [ ] SIGHUP reload for RBAC policy file
