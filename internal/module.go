package internal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"google.golang.org/grpc"

	"github.com/Muxcore-Media/auth-local/internal/policy"
	"github.com/Muxcore-Media/auth-local/internal/server"
	authStore "github.com/Muxcore-Media/auth-local/internal/store"
	"github.com/Muxcore-Media/auth-local/internal/webapp"
	"github.com/Muxcore-Media/auth-local/internal/webauthn"
	"github.com/Muxcore-Media/core/pkg/contracts"
)

type Module struct {
	store          *authStore.Store
	authSrv        *server.AuthServer
	waHandler      *webauthn.Handler
	grpcSrv        *grpc.Server
	httpSrv        *http.Server
	webHandler     *webapp.Handler
	grpcLis        net.Listener
	httpLis        net.Listener
	sighupCh       chan os.Signal
	sighupStop     chan struct{}
	sighupDone     chan struct{}
	id             string
	grpcAddr       string
	httpAddr       string
	dbPath         string
	policyFile     string
	rpID           string
	rpOrigins      []string
	rpName         string
	trustedProxies []net.IPNet
}

// Config holds module settings. Non-empty fields override environment; empty
// fields fall back to AUTH_* env vars, then built-in defaults.
type Config struct {
	ID         string
	GRPCAddr   string
	HTTPAddr   string
	DBPath     string
	PolicyFile string
	RPID       string
	RPOrigins  string // comma-separated
	RPName     string
}

func NewModule(cfg Config) *Module {
	if cfg.ID == "" {
		cfg.ID = "auth-local"
	}
	if cfg.GRPCAddr == "" {
		cfg.GRPCAddr = os.Getenv("AUTH_GRPC_ADDR")
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = os.Getenv("AUTH_HTTP_ADDR")
	}
	if cfg.DBPath == "" {
		cfg.DBPath = os.Getenv("AUTH_DB_PATH")
	}
	if cfg.PolicyFile == "" {
		cfg.PolicyFile = os.Getenv("AUTH_POLICY_FILE")
	}
	if cfg.RPID == "" {
		cfg.RPID = os.Getenv("AUTH_RP_ID")
	}
	if cfg.RPOrigins == "" {
		cfg.RPOrigins = os.Getenv("AUTH_RP_ORIGINS")
	}
	if cfg.RPName == "" {
		cfg.RPName = os.Getenv("AUTH_RP_NAME")
	}

	if cfg.GRPCAddr == "" {
		cfg.GRPCAddr = ":9403"
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = ":9401"
	}
	if cfg.PolicyFile == "" {
		cfg.PolicyFile = "policies.yaml"
	}
	if cfg.RPID == "" {
		cfg.RPID = "localhost"
	}
	if cfg.RPName == "" {
		cfg.RPName = "MuxCore"
	}
	if cfg.DBPath == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			cfg.DBPath = "auth.db"
		} else {
			cfg.DBPath = filepath.Join(home, ".muxcore", "auth.db")
		}
	}

	rpOrigins := splitCSV(cfg.RPOrigins)
	if len(rpOrigins) == 0 {
		rpOrigins = []string{"http://localhost:9401"}
	}

	var trustedProxies []net.IPNet
	if v := os.Getenv("AUTH_TRUSTED_PROXIES"); v != "" {
		trustedProxies = webapp.ParseTrustedProxies(strings.Split(v, ","))
	} else {
		trustedProxies = webapp.ParseTrustedProxies(nil)
	}

	return &Module{
		id:             cfg.ID,
		grpcAddr:       cfg.GRPCAddr,
		httpAddr:       cfg.HTTPAddr,
		dbPath:         cfg.DBPath,
		policyFile:     cfg.PolicyFile,
		rpID:           cfg.RPID,
		rpOrigins:      rpOrigins,
		rpName:         cfg.RPName,
		trustedProxies: trustedProxies,
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (m *Module) Info() contracts.ModuleInfo {
	return contracts.ModuleInfo{
		ID:           m.id,
		Name:         "Auth Local",
		Version:      "0.1.2",
		Roles:        []string{"security"},
		Description:  "Local authentication and authorization provider",
		Author:       "MuxCore",
		Capabilities: []string{contracts.CapabilityAuth, contracts.CapabilityAuthorizer, contracts.CapabilityIdentity},
		HTTPAddr:     m.grpcAddr,
	}
}

func (m *Module) Init(ctx context.Context) error {
	if dir := filepath.Dir(m.dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create db dir: %w", err)
		}
	}

	var err error
	m.store, err = authStore.New(m.dbPath)
	if err != nil {
		return fmt.Errorf("init store: %w", err)
	}

	pol, err := m.loadPolicy()
	if err != nil {
		return err
	}
	m.authSrv = server.New(m.store, pol, m.rpID, m.rpOrigins, m.rpName)

	m.waHandler, err = webauthn.New(m.rpID, m.rpOrigins, m.rpName, m.store)
	if err != nil {
		return fmt.Errorf("init webauthn: %w", err)
	}

	m.grpcLis, err = net.Listen("tcp", m.grpcAddr)
	if err != nil {
		return fmt.Errorf("listen gRPC %s: %w", m.grpcAddr, err)
	}
	m.httpLis, err = net.Listen("tcp", m.httpAddr)
	if err != nil {
		return fmt.Errorf("listen HTTP %s: %w", m.httpAddr, err)
	}
	m.webHandler = webapp.New(m.store, m.httpAddr, m.trustedProxies)
	slog.Info("auth-local initialized",
		"grpc", m.grpcAddr,
		"http", m.httpAddr,
		"db", m.dbPath,
		"policy", m.policyFile,
		"rp_id", m.rpID,
	)
	return nil
}

func (m *Module) loadPolicy() (*policy.Policy, error) {
	pol, err := policy.Load(m.policyFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Warn("policy file missing; using builtin default roles (admin/manager/user/viewer)",
				"file", m.policyFile)
			return policy.Builtin(), nil
		}
		return nil, fmt.Errorf("load policy: %w", err)
	}
	if pol.RoleCount() == 0 {
		slog.Warn("policy file has no roles — all Can() checks deny until roles are defined (not builtin)",
			"file", m.policyFile)
	} else {
		slog.Info("RBAC policy loaded", "file", m.policyFile, "roles", pol.RoleCount())
	}
	return pol, nil
}

// ReloadPolicy reloads the policy file and applies it via SetPolicy.
func (m *Module) ReloadPolicy() error {
	if m.authSrv == nil {
		return fmt.Errorf("not initialized")
	}
	pol, err := policy.Load(m.policyFile)
	if err != nil {
		return err
	}
	if pol.RoleCount() == 0 {
		slog.Warn("reloaded policy has no roles — all Can() checks deny", "file", m.policyFile)
	}
	m.authSrv.SetPolicy(pol)
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
	m.waHandler.RegisterRoutes(mux)
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(m.authSrv.Metrics()))
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	m.httpSrv = &http.Server{Handler: mux}
	go func() {
		slog.Info("auth-local HTTP started", "addr", m.httpAddr)
		if err := m.httpSrv.Serve(m.httpLis); err != nil && err != http.ErrServerClosed {
			slog.Error("auth-local HTTP error", "error", err)
		}
	}()

	sighupCh := make(chan os.Signal, 1)
	sighupStop := make(chan struct{})
	sighupDone := make(chan struct{})
	m.sighupCh = sighupCh
	m.sighupStop = sighupStop
	m.sighupDone = sighupDone
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		defer close(sighupDone)
		for {
			select {
			case <-sighupCh:
				slog.Info("SIGHUP received — reloading RBAC policy")
				if err := m.ReloadPolicy(); err != nil {
					slog.Error("policy reload failed", "error", err)
				}
			case <-sighupStop:
				return
			}
		}
	}()
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	if m.sighupStop != nil {
		select {
		case <-m.sighupStop:
		default:
			close(m.sighupStop)
		}
		if m.sighupDone != nil {
			<-m.sighupDone
		}
	}
	if m.sighupCh != nil {
		signal.Stop(m.sighupCh)
	}
	if m.webHandler != nil {
		m.webHandler.Stop()
	}
	if m.grpcSrv != nil {
		m.grpcSrv.GracefulStop()
	}
	if m.httpSrv != nil {
		_ = m.httpSrv.Shutdown(ctx)
	}
	if m.store != nil {
		_ = m.store.Close()
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

// HTTPAddr returns the bound HTTP listen address (useful after Init with :0).
func (m *Module) HTTPAddr() string {
	if m.httpLis != nil {
		return m.httpLis.Addr().String()
	}
	return m.httpAddr
}

// AuthServer exposes the gRPC auth server for tests.
func (m *Module) AuthServer() *server.AuthServer {
	return m.authSrv
}

// PolicyFile returns the configured policy path.
func (m *Module) PolicyFile() string {
	return m.policyFile
}
