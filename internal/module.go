package internal

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"

	"google.golang.org/grpc"

	"github.com/Muxcore-Media/auth-local/internal/policy"
	"github.com/Muxcore-Media/auth-local/internal/server"
	authStore "github.com/Muxcore-Media/auth-local/internal/store"
	"github.com/Muxcore-Media/auth-local/internal/webapp"
	"github.com/Muxcore-Media/core/pkg/contracts"
)

type Module struct {
	store      *authStore.Store
	authSrv    *server.AuthServer
	grpcSrv    *grpc.Server
	httpSrv    *http.Server
	webHandler *webapp.Handler
	grpcLis    net.Listener
	httpLis    net.Listener
	id         string
	grpcAddr   string
	httpAddr   string
	policyDir  string
	rpID       string
	rpOrigins  []string
	rpName     string
}

type Config struct {
	ID              string
	GRPCAddr        string
	HTTPAddr        string
	PolicyDir       string
	WebAuthnRPID    string
	WebAuthnOrigins []string
	WebAuthnRPName  string
}

func NewModule(cfg Config) *Module {
	if cfg.ID == "" {
		cfg.ID = "auth-local"
	}
	if cfg.GRPCAddr == "" {
		cfg.GRPCAddr = ":9400"
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = ":9401"
	}
	if cfg.PolicyDir == "" {
		cfg.PolicyDir = "policies.yaml"
	}
	if v := os.Getenv("AUTH_GRPC_ADDR"); v != "" {
		cfg.GRPCAddr = v
	}
	if v := os.Getenv("AUTH_HTTP_ADDR"); v != "" {
		cfg.HTTPAddr = v
	}
	if v := os.Getenv("AUTH_WEBAUTHN_RP_ID"); v != "" {
		cfg.WebAuthnRPID = v
	}
	if v := os.Getenv("AUTH_WEBAUTHN_RP_ORIGINS"); v != "" {
		cfg.WebAuthnOrigins = strings.Split(v, ",")
	}
	if v := os.Getenv("AUTH_WEBAUTHN_RP_NAME"); v != "" {
		cfg.WebAuthnRPName = v
	}
	if cfg.WebAuthnRPID == "" {
		cfg.WebAuthnRPID = "localhost"
	}
	if len(cfg.WebAuthnOrigins) == 0 {
		cfg.WebAuthnOrigins = []string{"http://localhost:8082"}
	}
	if cfg.WebAuthnRPName == "" {
		cfg.WebAuthnRPName = "MuxCore"
	}
	return &Module{
		id:        cfg.ID,
		grpcAddr:  cfg.GRPCAddr,
		httpAddr:  cfg.HTTPAddr,
		policyDir: cfg.PolicyDir,
		rpID:      cfg.WebAuthnRPID,
		rpOrigins: cfg.WebAuthnOrigins,
		rpName:    cfg.WebAuthnRPName,
	}
}

func (m *Module) Info() contracts.ModuleInfo {
	return contracts.ModuleInfo{
		ID:           m.id,
		Name:         "Auth Local",
		Version:      "0.1.0",
		Roles:        []string{"security"},
		Description:  "Local authentication and authorization provider",
		Author:       "MuxCore",
		Capabilities: []string{contracts.CapabilityAuth, contracts.CapabilityAuthorizer, contracts.CapabilityIdentity},
		HTTPAddr:     m.grpcAddr,
	}
}

func (m *Module) Init(ctx context.Context) error {
	var err error
	m.store, err = authStore.New("")
	if err != nil {
		return fmt.Errorf("init store: %w", err)
	}
	m.authSrv = server.New(m.store, &policy.Policy{}, m.rpID, m.rpOrigins, m.rpName)

	m.grpcLis, err = net.Listen("tcp", m.grpcAddr)
	if err != nil {
		return fmt.Errorf("listen gRPC %s: %w", m.grpcAddr, err)
	}
	m.httpLis, err = net.Listen("tcp", m.httpAddr)
	if err != nil {
		return fmt.Errorf("listen HTTP %s: %w", m.httpAddr, err)
	}
	m.webHandler = webapp.New(m.store, m.httpAddr)
	slog.Info("auth-local initialized", "grpc", m.grpcAddr, "http", m.httpAddr)
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.grpcSrv = grpc.NewServer()
	m.authSrv.RegisterWithGRPC(m.grpcSrv)
	go func() {
		slog.Info("auth-local gRPC started", "addr", m.grpcAddr)
		if err := m.grpcSrv.Serve(m.grpcLis); err != nil {
			slog.Error("auth-local gRPC error", "error", err)
		}
	}()

	mux := http.NewServeMux()
	m.webHandler.RegisterRoutes(mux)
	m.httpSrv = &http.Server{Handler: mux}
	go func() {
		slog.Info("auth-local HTTP started", "addr", m.httpAddr)
		if err := m.httpSrv.Serve(m.httpLis); err != nil && err != http.ErrServerClosed {
			slog.Error("auth-local HTTP error", "error", err)
		}
	}()
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	if m.grpcSrv != nil {
		m.grpcSrv.GracefulStop()
	}
	if m.httpSrv != nil {
		m.httpSrv.Shutdown(ctx)
	}
	if m.store != nil {
		m.store.Close()
	}
	slog.Info("auth-local stopped")
	return nil
}

func (m *Module) Health(ctx context.Context) error {
	if m.store == nil {
		return fmt.Errorf("not initialized")
	}
	return nil
}
