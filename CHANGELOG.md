# Changelog

## [Unreleased]

### Security
- User erasure (ADR-0035 §1, NFR-DATA-003). gRPC `DeleteUser` now requires a current, fully authenticated end-user **admin bearer** in `x-auth-token` (ADR-0026 §2 recheck); the mesh-peer bypass is removed for this method only (other admin methods keep it). Self-deletion and deleting the last admin of the tenant return `FailedPrecondition`; a target outside the caller's tenant returns `NotFound`; errors are gRPC status codes instead of `DeleteUserResponse.error`. HTTP `DELETE /api/users/{id}` runs the same store erasure. The last-admin count is now taken inside the delete's `BEGIN IMMEDIATE` write transaction, closing a race where two concurrent deletes of the last two admins could both succeed.
- Erasure now also deletes `totp` and `webauthn_sessions` rows (previously left behind), revokes the user's unredeemed invites and anonymises their `created_by` to `deleted-user`, and records a tombstone (`user_erasures`: random erasure id, user id, tenant, time, deleting admin id; no username). `DeleteUserResponse.erasure_id` returns it; repeating the deletion returns the same id.
- "The tombstone wins": every start deletes user, credential, session and token rows of tombstoned ids (restored archives), and a tombstoned id can never be created again (users, invite redemption, sessions, API tokens, TOTP, passkeys).

### Added
- Erasure ledger RPCs from core v0.6.17: `ListUserErasures` and `AckUserErasure` admit only a verified mesh client certificate whose CN is on `AUTH_ERASURE_CONSUMERS` (empty/unset fails closed; user bearers refused; the acknowledging module is the verified CN), `GetUserErasureStatus` (admin bearer) reports per-module status and completion against `AUTH_ERASURE_REQUIRED`. Paged with encrypted continuations.
- `authctl erasures export|import` for the offline restore flow (ADR-0035 §4); run while auth-local is stopped.
- `authctl` now sends `-token`/`AUTHCTL_TOKEN` as `x-auth-token` (API keys are exchanged for a session first); `authctl rm` needs an admin token.
- Upgrade snapshot from v0.1.19 (`internal/store/testdata/upgrade/v0.1.19.db`): pre-`session_id`, pre-ledger schema; opened twice, then erased and reopened.

### Changed
- Built on core v0.6.17 / sdk/go/module v0.6.7. The store's non-tombstoning `DeleteUser` is removed in favour of `EraseUser`.


## [0.1.19] - 2026-10-05


### Security
- TOTP secrets are now encrypted at rest (NFR-SEC-005) with AES-256-GCM (`v1:` + base64(nonce||ciphertext)) in both the `totp` table and the legacy `users.totp_secret` column. The key comes from `AUTH_SECRET_KEY` (32 bytes, hex or base64) or the file named by `AUTH_SECRET_KEY_FILE`; when neither is set a random key is generated once as `auth-secret.key` (0600) next to the database. Existing plaintext secrets are encrypted in place on startup (idempotent; upgrade test extended). Opening a database with the wrong key fails at startup with an explicit error instead of silently locking users out. The database directory is created 0700 and the database file is 0600.
- Session tokens are stored as `h1:` + sha256(token) hex instead of plaintext (NFR-SEC-005); lookups, logout, revoke-all and partial-to-full upgrade hash the presented token, and existing plaintext rows are hashed in place on startup (idempotent) so live sessions stay valid. No API lists or returns stored session tokens; the raw token is only returned once, at creation.
- A TOTP secret that cannot be read no longer skips the second factor at login (HTTP and gRPC now fail closed).

## [0.1.18] - 2026-10-05

### Changed
- Built on core v0.6.14 / sdk/go/module v0.6.4: unregisters on shutdown and re-registers after core restarts (ADR-0022).

## [0.1.17] - 2026-10-05


### Changed
- Reported version comes from muxcore.json (ADR-0021); built on core v0.6.12 / sdk/go/module v0.6.3 (mesh enrollment, ADR-0017).

## [0.1.16] - 2026-10-05


### Security
- The gRPC server only requests client certificates when a mesh CA is configured; without one it no longer verifies them against the system roots (a publicly issued certificate with a matching CN could otherwise claim a module identity).

### Fixed
- Login rate limiting counted successful logins and only reset when a block triggered, so ordinary use (about 6 logins from one IP) returned HTTP 429. It now counts only failed authentication attempts (wrong password, wrong TOTP code): 10 failures per 15-minute fixed window per client IP and per normalised username (per user ID for the TOTP step). A successful login clears only the per-username (per-user-ID for TOTP) counter, never the per-IP one, so a valid account cannot be used to wipe an IP's failures; counts expire with the window, and `Retry-After` reflects the remaining window. Unknown usernames are tracked and answered identically to real ones, so responses do not reveal whether an account exists. Successful logins are never throttled.
- Mesh identity (`internal/server/mesh_identity.go`) now requires a verified TLS client chain (`len(VerifiedChains) > 0`) in addition to the certificate CN; a presented but unverified (e.g. self-signed) certificate with a matching CN is rejected.

## [0.1.15] - 2026-10-05


### Added
- Upgrade test (ADR-0015, NFR-DATA-002): `internal/store/upgrade_test.go` opens a committed snapshot produced by tag v0.1.5 (`internal/store/testdata/upgrade/`) with the current code twice and checks schema superset, seeded rows, new-column defaults, and integrity. No migration bugs found.

### Changed
- Requires `core/sdk/go/module` v0.6.1 (for `moduletest`); this raises `modernc.org/sqlite` to v1.55.0.

## [0.1.14] - 2026-10-05

### Changed
- CI runs on GitHub-hosted runners from the umbrella template; retired-origin workflows removed.
- Dependencies resolve from published GitHub tags (no filesystem `replace`); requires core v0.6.0.

## [0.1.14] — 2026-09-08

### Changed
- HTTP passkey list/delete (`GET /api/webauthn/credentials`, `DELETE /api/webauthn/credentials/{id}`) now require a full session. `user_id` defaults to the caller; another user's credentials require admin.

## [0.1.13] — 2026-09-08

### Added
- HTTP household TOTP: `GET|POST|DELETE /api/totp` and `POST /api/totp/verify`. Any signed-in user manages their own authenticator. Enable returns the base32 secret and `otpauth://` URL; verify accepts `{ code }` or `{ totp_code }`.

## [0.1.12] — 2026-09-08

### Added
- HTTP household user create: `POST /api/users` `{ username, password, role? }`. Admin session required. Minimum 8-character password. Optional role defaults to `user`. Tenant is taken from the admin session when the body omits it.

## [0.1.11] — 2026-09-08

### Added
- HTTP household password set: `POST /api/users/{id}/password` `{ password }`. Admin session required. Minimum 8 characters. Used by the household BFF password-reset queue.

## [0.1.10] — 2026-09-08

### Added
- HTTP household API keys: `GET|POST /api/tokens`, `DELETE /api/tokens/{id}`, `POST /api/tokens/{id}/rotate`. Admin session required. Raw secret is returned once on create/rotate and never listed.

## [0.1.9] — 2026-09-08

### Added
- HTTP household user admin: `GET /api/users`, `PATCH /api/users/{id}` (roles), `DELETE /api/users/{id}`. Admin session required. Blocks self-delete and last-admin delete/demote.

## [0.1.8] — 2026-09-05

### Added
- gRPC household invite APIs: `CreateInvite`, `ListInvites`, `RevokeInvite`, `RedeemInvite` (admin-gated create/list/revoke; public redeem).
- HTTP `/api/invites` create/list/revoke now require an admin session (or mesh identity via gRPC).

### Changed
- Invite `created_by` is derived from the authenticated admin username, not client-supplied JSON.

## [0.1.7] — 2026-08-20

### Added
- Wizarr-style invite links: create/list/revoke via `GET|POST /api/invites`, `DELETE /api/invites/{id}`; redeem at `/invite?token=` and `POST /invite/redeem`.
- Invites are time-limited, single-use or max-uses (0 = unlimited), optional role.

## [0.1.6] — 2026-08-20

### Fixed
- `Can` for service module caller IDs (not DB users) evaluates RBAC as role `module` instead of deny-all — required for mesh StorageService from downloaders/indexers.
- Builtin RBAC includes `module: ["*"]`.

## [0.1.5] — 2026-08-10

### Changed

- Advertise `settings` capability for admin-ui Settings discovery

## [0.1.3] — 2026-08-10

### Fixed
- Sync Info()/muxcore.json version to **0.1.3**.

## [0.1.0] — Unreleased

### Added

- Load RBAC policy from `AUTH_POLICY_FILE` / `--policy-file` (builtin default when missing)
- SIGHUP policy reload
- `GET /metrics` Prometheus counters
- `AUTH_DB_PATH` / `--db-path` SQLite path (default `~/.muxcore/auth.db`)
- WebAuthn HTTP routes + `AUTH_RP_ID` / `AUTH_RP_ORIGINS` / `AUTH_RP_NAME`
- Module CLI flags mirroring env (`--db-path`, `--policy-file`, `--grpc-addr`, …)
