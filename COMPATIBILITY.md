# Compatibility

## Core Version

Requires MuxCore v1.0.0 or later.

## Capabilities

Registers with capabilities: `auth`, `authorizer`, `identity`

## Contract Dependencies

- `github.com/Muxcore-Media/core/pkg/contracts` — AuthProvider, Authorizer, IdentityProvider
- gRPC ModuleRegistration service for sidecar registration
- gRPC DiscoveryService for module discovery
- gRPC HealthService for module health checks
