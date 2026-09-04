// Package integsupport exposes auth-local internals to umbrella integration tests.
package integsupport

import (
	"context"
	"testing"

	auth "github.com/Muxcore-Media/auth-local/internal"
)

// Module is the auth-local sidecar implementation.
type Module = auth.Module

// Config configures an auth-local test module.
type Config = auth.Config

// NewModule constructs an auth-local module.
func NewModule(cfg Config) *Module {
	return auth.NewModule(cfg)
}

// NewTestModule initializes an in-memory SQLite module and registers cleanup.
func NewTestModule(t *testing.T, cfg Config) *Module {
	t.Helper()
	if cfg.DBPath == "" {
		cfg.DBPath = ":memory:"
	}
	if cfg.GRPCAddr == "" {
		cfg.GRPCAddr = "127.0.0.1:0"
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = "127.0.0.1:0"
	}
	m := auth.NewModule(cfg)
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatalf("auth-local init: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	return m
}

// Start connects the module to core when MUXCORE_GRPC_ADDR is set.
func Start(ctx context.Context, m *Module) error {
	return m.Start(ctx)
}

// GRPCListenAddr returns the bound gRPC address after Init.
func GRPCListenAddr(m *Module) string {
	return auth.IntegrationListenAddr(m)
}
