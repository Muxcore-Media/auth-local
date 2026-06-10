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

1. Client sends `POST /auth/login` with `{"username": "...", "password": "..."}`
2. Module validates against local user store (bcrypt)
3. Returns a bearer session token
4. Client includes `Authorization: Bearer <token>` on subsequent requests
5. Module extracts identity on every request

### Authorization (RBAC)

| Role | Permissions |
|------|------------|
| `admin` | `"*"` — full system access |
| `manager` | `media.*`, `storage.*`, `modules.*` |
| `user` | `media.request`, `media.view` |
| `viewer` | `media.view` only |

## Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--db-path` | `~/.muxcore/auth.db` | SQLite database path |
| `--token-ttl` | `24h` | Session token TTL |
| `--policy-file` | `policies.yaml` | RBAC policy file |
| `--admin-user` | `admin` | Default admin username |
| `--admin-password` | (generated) | Default admin password (printed at first start) |

### Admin CLI

```
auth-local adduser <username>          # Create user (interactive password prompt)
auth-local adduser --password <pw>     # Create user with password
auth-local passwd <username>           # Change password
auth-local rm <username>               # Delete user
auth-local list                        # List users
auth-local revoke <token-prefix>       # Invalidate session by token prefix
```

## Implementation

- Registers with capabilities: `"auth"`, `"authorizer"`, `"identity"`
- Implements `contracts.AuthProvider`, `contracts.Authorizer`, `contracts.IdentityProvider`
- Also implements `contracts.ResourceAuthorizer` for ABAC
- SQLite-backed user store (pure-Go via modernc.org/sqlite)
- Bcrypt password hashing (cost 12)
- Token generation: SHA-256(random 32 bytes) → hex
- Audits all auth failures
- Brute-force protection: 6 failures → 1 minute backoff per IP
