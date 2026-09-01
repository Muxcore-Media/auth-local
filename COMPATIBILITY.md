# Compatibility

## Core Version

Requires a MuxCore core build that provides `muxcore/auth/v1` AuthService gRPC and module SDK settings registration (current MVP stack).

## Capabilities

Registers with capabilities: `auth`, `authorizer`, `identity`, `settings`

## Contract Dependencies

- `github.com/Muxcore-Media/core/pkg/contracts` — AuthProvider, Authorizer, IdentityProvider, SettingsProvider
- gRPC ModuleRegistration service for sidecar registration
- gRPC DiscoveryService for module discovery
- gRPC HealthService for module health checks
