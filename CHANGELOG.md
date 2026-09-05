# Changelog


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
