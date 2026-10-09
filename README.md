# Auth Local

Local authentication and authorization for MuxCore.

Without this module, the HTTP API rejects all requests except `/health` and
`/version`, and the gRPC auth interceptor denies all unregistered callers.

This module implements **three contracts** in one binary:

| Contract | Capability | Purpose |
|----------|-----------|---------|
| `AuthProvider` | `"auth"` | Password auth → session tokens, token validation, revocation |
| `Authorizer` | `"authorizer"` | RBAC permission checks |
| `IdentityProvider` | `"identity"` | Extract caller identity from context |

## How It Works

```
Client request (HTTP or gRPC)
        │
        ▼
auth-local.IdentityProvider.ExtractIdentity(ctx)
        │
        ▼
  identity found? ───no──→ reject (401)
        │
       yes
        │
        ▼
auth-local.Authorizer.Can(session, action, resource)
        │
        ▼
  allowed? ───yes──→ dispatch request
    │
   no
    │
    ▼
  reject (403)
```

### Authentication Flow

1. Browser: `GET /login` (HTML UI); or gRPC `Authenticate` with credential type `password` / `totp` / `api-key`
2. Form login: `POST /login/password` (username/password); TOTP step via `POST /login/totp` when enabled
3. Module validates against local user store (bcrypt)
4. Returns a bearer session token (UI uses a one-time `code` redirect + `/login/exchange`)
5. Client includes `Authorization: Bearer <token>` on subsequent requests
6. Module extracts identity on every request

### Authorization (RBAC)

Loaded from `AUTH_POLICY_FILE` (default `policies.yaml`). If the file is **missing**,
the module uses a **builtin default** matching the table below (logged as a warning).
If the file exists but defines **zero roles**, every `Can()` check denies — that is
intentional deny-all, not the builtin fallback.

| Role | Permissions |
|------|------------|
| `admin` | `"*"` — full system access |
| `manager` | `media.*`, `storage.*`, `modules.read`, `modules.manage` |
| `user` | `media.request`, `media.view`, `media.search` |
| `viewer` | `media.view`, `media.search` |

Send `SIGHUP` to reload the policy file without restarting.

## Configuration

### Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_GRPC_ADDR` | `:9403` | gRPC listen address |
| `AUTH_HTTP_ADDR` | `:9401` | HTTP listen address (login UI, metrics, WebAuthn) |
| `AUTH_DB_PATH` | `~/.muxcore/auth.db` | SQLite user/session store |
| `AUTH_SECRET_KEY` | (unset) | 32-byte key (hex or base64) encrypting TOTP secrets at rest (AES-256-GCM); takes precedence over the file |
| `AUTH_SECRET_KEY_FILE` | `<AUTH_DB_PATH dir>/auth-secret.key` | File holding the key; generated once with mode 0600 if missing. Back it up with the database: losing it makes stored TOTP secrets unrecoverable |
| `AUTH_POLICY_FILE` | `policies.yaml` | RBAC policy YAML |
| `AUTH_RP_ID` | `localhost` | WebAuthn relying party ID |
| `AUTH_RP_ORIGINS` | `http://localhost:9401` | Comma-separated allowed WebAuthn origins |
| `AUTH_RP_NAME` | `MuxCore` | WebAuthn relying party display name |
| `AUTH_TRUSTED_PROXIES` | loopback | Comma-separated CIDRs whose `X-Forwarded-For` is trusted |
| `AUTH_ERASURE_CONSUMERS` | (unset) | Comma-separated module ids (mesh certificate CNs) allowed to call `ListUserErasures`/`AckUserErasure` (ADR-0035 §2, umbrella `docs/adr/0035-user-erasure-ledger.md`). Empty or unset: both RPCs fail closed with `PermissionDenied` |
| `AUTH_ERASURE_REQUIRED` | (unset) | Comma-separated module ids whose `OK` acknowledgement completes an erasure (`GetUserErasureStatus`). Deployment generates it from the enabled `personal: true` manifest entries; each should also be in `AUTH_ERASURE_CONSUMERS`. Empty: every erasure reports complete |

### gRPC TLS (production)

By default the gRPC listener on `AUTH_GRPC_ADDR` uses TLS. Plaintext is allowed only when `MUXCORE_INSECURE_DISABLE_TLS=true` or `MUXCORE_GRPC_INSECURE=true` (local dev).

| Variable | Description |
|----------|-------------|
| `MUXCORE_INSECURE_DISABLE_TLS` | `true` disables TLS on the gRPC listener (dev only) |
| `MUXCORE_TLS_CERT` / `MUXCORE_TLS_KEY` | Server (and optional client) certificate paths issued by the mesh CA |
| `MUXCORE_TLS_CA` | Mesh CA for verifying peer client certificates |
| `AUTH_TLS_CERT` / `AUTH_TLS_KEY` / `AUTH_TLS_CA` | auth-local overrides for the above |
| `AUTH_TLS_DIR` | Directory for auto-generated dev CA + server cert (default: alongside `AUTH_DB_PATH`) |

When no certificate paths are set and TLS is required, auth-local generates an ECDSA P-256 CA and server certificate on first start (logged once). Mesh modules must present a client certificate signed by the mesh CA; mesh identity is taken from the verified certificate CN ([Module TLS Authentication](https://github.com/Muxcore-Media/core/wiki/Module-TLS-Authentication)), not from `x-caller-id` metadata alone.

Session and API-token clients (e.g. `authctl` with `AUTHCTL_TOKEN`) continue to authenticate via `x-auth-token` metadata and do not need a mesh client certificate.

`X-Forwarded-For` is honored only from trusted proxy peers; otherwise client IP is `RemoteAddr`. `X-Real-IP` is not used.

### Module CLI flags

Optional flags mirror env (non-empty flags win over env):

```
auth-local \
  --db-path ~/.muxcore/auth.db \
  --policy-file policies.yaml \
  --grpc-addr :9403 \
  --http-addr :9401 \
  --rp-id localhost \
  --rp-origins http://localhost:9401 \
  --rp-name MuxCore
```

### HTTP surface

| Path | Description |
|------|-------------|
| `/login` … | Browser login UI |
| `/api/webauthn/...` | WebAuthn register/login (used by login HTML) |
| `GET /metrics` | Prometheus counters (`auth_login_*`, `auth_sessions_active`) |
| `GET /health` | Liveness |

### Admin CLI

Build: `make admin-cli` → `authctl`

```
authctl [-addr host:port] [-token <admin-token>] <command>

authctl adduser <username> [password]   # Create user (prompts if password omitted)
authctl passwd <username>               # Change password
authctl rm <username>                   # Delete user
authctl list                            # List users
authctl addrole <user> <role>           # Assign role
authctl rmrole <user> <role>            # Remove role
authctl totp enable|disable|status <user>
authctl token create <user> <name>      # Create API token
authctl token list <user>
authctl token rm <token-id>
authctl erasures export [-db <auth.db>] <ledger.json>   # offline, auth-local stopped
authctl erasures import [-db <auth.db>] <ledger.json>   # offline, auth-local stopped
```

Flags: `-addr` (default `localhost:9403`), `-token` / `AUTHCTL_TOKEN`. The token
is sent as `x-auth-token`; an API key (`mct_...`) is first exchanged for a
short-lived session. `rm` requires an admin token (see below).

### Administrative session RPCs

`AuthService.ListSessions` and `RevokeSession` implement the core v0.6.16
administrative contract. Both require a current, fully authenticated `full` or
`api-token` bearer in `x-auth-token` and recheck the user's current `admin` role.
A mesh certificate alone does not authorize these operations.

Lists include only active full/API sessions belonging to existing users, with an
optional user filter. Results contain independent management IDs, user metadata,
kind and UTC timestamps; they contain no bearer or bearer hash. Pages default to
100 records and allow at most 500. Continuations are encrypted, authenticated and
bound to the user filter; they resume after the last creation-time/ID pair even
if that session has since expired or been revoked. The existing secret key also
protects continuations with a separate cryptographic context; changing that key
invalidates outstanding continuations.

Opening an existing database transactionally backfills random session IDs and a
unique index, preserving stored bearers and timestamps. Reopening preserves IDs.
Revoke atomically matches both user ID and session ID; unknown or previously
revoked pairs succeed. The revoked bearer fails its next provider validation,
while an API key that minted the session remains usable.

This provider interface does not yet deliver the all-device UI (FR-AUTH-007).
Apps must revalidate cached upstream bearers to observe revocation; BFF Quick
Connect's local-only sessions also need a provider device-grant integration.

Provider regression checks (including migration, pagination, authorization and
gRPC revocation) run with `go test -race -count=1 ./internal/store ./internal/server`;
the module-wide check is `make test`.

`AuthService.Validate` separates invalid credentials from a provider failure.
Missing, revoked, expired, partial or orphaned sessions return `valid: false`.
Database failures and corrupt identity/session data return gRPC `Internal`;
canceled requests and elapsed deadlines retain their corresponding gRPC status.
Clients should deny access on those errors while preserving their local cookie
for a retry. Successful validation returns the user's current ID, username,
roles and tenant, including empty roles/tenant after a claims change. The lookup
does not read password hashes or decrypt TOTP secrets. Only definitively expired
sessions receive best-effort lazy cleanup; unreadable records are preserved.

### User erasure (ADR-0035)

`DeleteUser` (gRPC) and `DELETE /api/users/{id}` (HTTP) erase a user. Both
require a current, fully authenticated end-user **admin bearer** (`full` or
`api-token` session in `x-auth-token`, role rechecked on every call as for the
administrative session RPCs); a verified mesh certificate alone is refused for
this method. The target must be in the caller's tenant (empty = the single
household; another tenant's id is `NotFound`), self-deletion and deleting the
last `admin` of the tenant are refused (`FailedPrecondition` / HTTP 400).

One SQLite write transaction (`BEGIN IMMEDIATE`, so the last-admin count cannot
race a concurrent erasure in this or another process) deletes the user, every
session (full, partial, api-token), API tokens, passkeys, passkey sessions and
TOTP rows, revokes the user's unredeemed invites and replaces their
`created_by` with `deleted-user`, and inserts the tombstone
`user_erasures(erasure_id, user_id, tenant_id, deleted_at, deleted_by)`. The
erasure id is random and opaque; the tombstone has no username and is never
pruned. The response carries `erasure_id`; repeating the call for an erased id
returns the same id, an unknown id is `NotFound`.

The tombstone wins: on every start auth-local deletes any user, credential,
session or token row whose id is tombstoned (e.g. restored from an older
archive), and a tombstoned id can never be created again (user creation,
invite redemption, sessions, tokens, TOTP and passkeys all refuse it).
Usernames are reusable and get a new, unrelated id.

Ledger RPCs for personal-data owners (core `muxcore/auth/v1`, served to the
`sdk/go/module/erasure` reconciler):

| RPC | Caller | Notes |
|-----|--------|-------|
| `ListUserErasures` | verified mesh client certificate whose CN is on `AUTH_ERASURE_CONSUMERS` | Whole ledger, every tenant, ordered by `deleted_at` then `erasure_id`; pages default 100, max 500; continuations are encrypted and authenticated. `acknowledged_by_caller` is true when the caller's latest ack is `OK` |
| `AckUserErasure` | same | The acknowledging module is the verified CN (`x-caller-id` is ignored on TLS connections). Outcome `OK`/`FAILED`/`UNSUPPORTED`; `detail_code` and count keys match `[a-z0-9_.-]{1,64}`; at most 32 non-negative counts. The latest ack per (erasure, module) wins; repeats are idempotent. Unknown erasure: `NotFound` |
| `GetUserErasureStatus` | admin bearer (as `DeleteUser`) | Caller's tenant only. Per erasure: every required module (pending = `UNSPECIFIED`), then any other module that acknowledged; `complete` when every `AUTH_ERASURE_REQUIRED` module's latest ack is `OK`. `pending_only` filter and paging (continuations bound to the filter) |

A user bearer never authorizes the ledger: without a verified certificate the
call is `Unauthenticated`; with an allowlisted certificate plus a bearer it is
`PermissionDenied`. Only with `MUXCORE_INSECURE_DISABLE_TLS`/`MUXCORE_GRPC_INSECURE`
(plaintext dev listener) and `MUXCORE_PROFILE` other than `household`/`staging`
does a plaintext caller's `x-caller-id` stand in for the CN (ADR-0017 §2), still
subject to the allowlist.

**Restore (ADR-0035 §4).** Backups are not rewritten. Before replacing
auth-local's database with an archive, with auth-local **stopped**, export the
live ledger; restore; import it; then start auth-local:

```
authctl erasures export -db /data/auth.db /safe/place/ledger.json   # file mode 0600, refuses to overwrite
# ... restore the archive over /data/auth.db ...
authctl erasures import -db /data/auth.db /safe/place/ledger.json
```

Import is idempotent, refuses a tombstone whose `erasure_id` or `user_id`
already appears paired differently (nothing is imported), and deletes the
restored rows of every tombstoned user. auth-local has no database lock file, so
both commands rely on the operator stopping auth-local first. With no live
system, use the newest auth-local archive, never one older than any other
restored module.

## Implementation

- Registers with capabilities: `"auth"`, `"authorizer"`, `"identity"`
- Serves `AuthService` gRPC (authenticate, authorize, identity, users, TOTP, WebAuthn, API tokens)
- SQLite-backed user store (pure-Go via modernc.org/sqlite)
- Bcrypt password hashing (cost 12)
- Session token generation: SHA-256(random 32 bytes) → hex
- Brute-force protection on login UI: 6 attempts → 1 minute backoff per IP
- SIGHUP reloads RBAC policy from disk
