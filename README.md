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
| `module` | `"*"` — mesh callers identified via `x-caller-id` |

Send `SIGHUP` to reload the policy file without restarting.

## Invites and tenancy

Admins create invite links via authenticated `GET|POST /api/invites` and `DELETE /api/invites/{id}` (Bearer session with `admin` role). Allowed invite roles: `user`, `viewer`, `manager`. Users redeem at `/invite?token=…` or `POST /invite/redeem` (CSRF-protected HTML form). JSON helpers: `GET /api/invite/peek`, `POST /api/invite/redeem`.

Optional `tenant_id` on invites is copied onto users created via redeem (household tenancy). Session tokens and `/login/exchange` include `tenant_id` in claims when set.

## Native device login

`POST /login/device` accepts JSON `{username, password}` for TV/mobile clients (no CSRF). When verified TOTP is enabled, the response includes `requires_2fa` and `partial_token`; complete with `POST /login/device/totp`.

## Settings capability

Registers `"settings"` for admin-ui discovery (policy file path, WebAuthn RP config). See `internal/settings.go`.

## Configuration

### Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_GRPC_ADDR` | `:9403` | gRPC listen address |
| `AUTH_HTTP_ADDR` | `:9401` | HTTP listen address (login UI, metrics, WebAuthn) |
| `AUTH_HTTP_URL` | _(unset)_ | Public base URL for this auth host (e.g. `https://auth.zem.systems`) — used for mobile misredirect hints and absolute links |
| `AUTH_DB_PATH` | `~/.muxcore/auth.db` | SQLite user/session store |
| `AUTH_POLICY_FILE` | `policies.yaml` | RBAC policy YAML |
| `AUTH_RP_ID` | `localhost` | WebAuthn relying party ID |
| `AUTH_RP_ORIGINS` | `http://localhost:9401` | Comma-separated allowed WebAuthn origins |
| `AUTH_RP_NAME` | `MuxCore` | WebAuthn relying party display name |
| `AUTH_TRUSTED_PROXIES` | loopback | Comma-separated CIDRs whose `X-Forwarded-For` is trusted |

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
| `/login/device`, `/login/device/totp` | JSON login for native clients |
| `/invite`, `/invite/redeem` | Invite redemption UI |
| `/api/invites`, `/api/invite/peek`, `/api/invite/redeem` | Invite admin + redeem API |
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

## Implementation

- Registers with capabilities: `"auth"`, `"authorizer"`, `"identity"`, `"settings"`
- Serves `AuthService` gRPC (authenticate, authorize, identity, users, TOTP, WebAuthn, API tokens)
- SQLite-backed user store (pure-Go via modernc.org/sqlite)
- Bcrypt password hashing (cost 12)
- Session token generation: SHA-256(random 32 bytes) → hex
- Brute-force protection on login UI: 6 attempts → 1 minute backoff per IP
- SIGHUP reloads RBAC policy from disk
