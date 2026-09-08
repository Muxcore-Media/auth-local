# Changelog

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
