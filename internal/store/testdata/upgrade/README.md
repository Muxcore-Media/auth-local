# Upgrade snapshots (ADR-0015)

Snapshot databases produced by an older release's own store code and opened by
`upgrade_test.go` with the current code.

| Snapshot | Tag | Notes |
|----------|-----|-------|
| `v0.1.5.db` / `v0.1.5.schema.sql` | `v0.1.5` (previous tag before latest `v0.1.14`) | Pre-invites, pre-`tenant_id` schema. |

Tag `v0.1.7` named by the release train does not exist in this repo (tags are
v0.1.0-v0.1.5 and v0.1.14), so v0.1.5 is the snapshot used.

## How produced

```
git worktree add /tmp/auth-local-v0.1.5 v0.1.5
cp seed_upgrade_test.go.txt /tmp/auth-local-v0.1.5/internal/store/seed_upgrade_test.go
cd /tmp/auth-local-v0.1.5
UPGRADE_SEED_DB=/tmp/seed.db GOWORK=off go test -tags upgradeseed -run TestUpgradeSeed ./internal/store/
sqlite3 /tmp/seed.db VACUUM
cp /tmp/seed.db <this dir>/v0.1.5.db && sqlite3 /tmp/seed.db .schema > v0.1.5.schema.sql
```

## Seed summary

- `users`: alice (roles admin,user; legacy `totp_secret`/`totp_enabled=1`), bob, carol (3 rows; IDs are random, look up by username)
- `sessions`: 2 (full for alice, partial for bob; expire 2099)
- `api_tokens`: 2 (`ci-token` scopes read,write; `readonly` scope read)
- `totp`: 1 (carol, verified)
- `webauthn_credentials`: 3 (alice x2, bob x1)
- `webauthn_sessions`: 1 (`seed-challenge`, expires 2099)
- `invites` does not exist in this snapshot; it must be created on upgrade.

All secrets are fake test values.
