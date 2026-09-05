# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities to the MuxCore team by emailing
security@muxcore.io or opening a draft security advisory on GitHub.

Do not open public issues for security vulnerabilities.

## Scope

This module is part of the MuxCore ecosystem. Security issues in the core
platform should be reported to the core repository.

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |

## Security Posture

This module handles authentication and authorization. It manages user
credentials, session tokens, and permission checks. A vulnerability could
lead to unauthorized system access.

### Key Security Properties

- gRPC listener uses TLS by default; `MUXCORE_INSECURE_DISABLE_TLS=true` is dev-only plaintext
- Mesh/admin identity requires verified mTLS client certificate CN; `x-caller-id` metadata alone is never trusted
- Passwords hashed with bcrypt (cost 12)
- Session tokens are SHA-256(random 32 bytes) → hex
- Tokens never logged in full (prefix only in warn logs)
- Brute-force protection on login UI: 6 attempts → 1 minute backoff per IP
- RBAC loaded from `AUTH_POLICY_FILE` (builtin defaults if missing); SIGHUP reloads the file
- Empty policy file (zero roles) is intentional deny-all — not the builtin fallback
