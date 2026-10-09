# Upgrade snapshots (ADR-0015)

Snapshot databases produced by an older release's own store code and opened by
`upgrade_test.go` with the current code.

| Snapshot | Tag | Notes |
|----------|-----|-------|
| `v0.1.5.db` / `v0.1.5.schema.sql` | `v0.1.5` (previous tag before latest `v0.1.14`) | Pre-invites, pre-`tenant_id` schema. |
| `v0.1.19.db` / `v0.1.19.schema.sql` | `v0.1.19` (latest release when the erasure ledger was added) | Pre-`session_id`, pre-`user_erasures`/`erasure_acks` schema; hashed session tokens and encrypted TOTP (fake key `upgradeKeyV0119`). |

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

## v0.1.19 snapshot

Produced like the v0.1.5 one from `seed_v0.1.19_upgrade_test.go.txt`, which
also writes the schema (no `sqlite3` CLI needed) and leaves the file in
rollback-journal mode after `VACUUM`:

```
git worktree add --detach ../auth-local-v0.1.19 v0.1.19
cp seed_v0.1.19_upgrade_test.go.txt ../auth-local-v0.1.19/internal/store/seed_upgrade_test.go
cd ../auth-local-v0.1.19
UPGRADE_SEED_DB=$PWD/seed.db UPGRADE_SEED_SCHEMA=$PWD/schema.sql GOWORK=off \
  go test -count=1 -tags upgradeseed -run TestUpgradeSeed ./internal/store/
cp seed.db <this dir>/v0.1.19.db && cp schema.sql <this dir>/v0.1.19.schema.sql
```

Seed: alice (admin,user), bob, erin (redeemed bob's single-use invite) in the
default tenant; carol (admin) and dave in `household-2`. Sessions with known raw
tokens (`seed119-*`, stored hashed; expire 2099): full alice/bob/carol, partial
and api-token bob. API tokens for alice and bob, bob's TOTP (encrypted) and
passkey, alice's passkey, passkey sessions for both. Invites created by
`alice` (single-use), `bob` (unlimited, unredeemed) and `bob` (exhausted).
