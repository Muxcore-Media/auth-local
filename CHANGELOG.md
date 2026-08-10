# Changelog


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
