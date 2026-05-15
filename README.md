# auth-local

Local accounts and API token authentication provider for MuxCore.

## Env Vars

- `MUXCORE_AUTH_LOCAL_ENABLED` — set to `true` to enable (default: false)

## Usage

This module registers as `kind: auth` and provides:
- Password-based authentication (bcrypt)
- API token generation and validation
- Role-based access control

```go
import "github.com/Muxcore-Media/auth-local"

mod := auth.NewModule()
mgr.Register(mod, nil)
```
