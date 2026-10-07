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
```

Flags: `-addr` (default `localhost:9403`), `-token` / `AUTHCTL_TOKEN`.

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

## Implementation

- Registers with capabilities: `"auth"`, `"authorizer"`, `"identity"`
- Serves `AuthService` gRPC (authenticate, authorize, identity, users, TOTP, WebAuthn, API tokens)
- SQLite-backed user store (pure-Go via modernc.org/sqlite)
- Bcrypt password hashing (cost 12)
- Session token generation: SHA-256(random 32 bytes) → hex
- Brute-force protection on login UI: 6 attempts → 1 minute backoff per IP
- SIGHUP reloads RBAC policy from disk
