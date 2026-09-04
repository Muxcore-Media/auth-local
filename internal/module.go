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
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/Muxcore-Media/auth-local/internal/policy"
	"github.com/Muxcore-Media/auth-local/internal/ratelimit"
	"github.com/Muxcore-Media/auth-local/internal/revocation"
	"github.com/Muxcore-Media/auth-local/internal/security"
	"github.com/Muxcore-Media/auth-local/internal/server"
	authStore "github.com/Muxcore-Media/auth-local/internal/store"
	"github.com/Muxcore-Media/auth-local/internal/webapp"
	"github.com/Muxcore-Media/auth-local/internal/webauthn"
	"github.com/Muxcore-Media/core/pkg/contracts"
	modulesdk "github.com/Muxcore-Media/core/sdk/go/module"
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
	runCancel      context.CancelFunc
	runDone        chan struct{}
	cfgMu          sync.RWMutex
	id             string
	grpcAddr       string
	httpAddr       string
	dbPath         string
	policyFile     string
	rpID           string
	rpOrigins      []string
	rpName         string
	trustedProxies []net.IPNet
	rateLimiter    *ratelimit.Limiter
	loginBackoff   *ratelimit.LoginBackoff
	revocations    *revocation.List
	secMetrics     *security.Collector
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
		Version:      "0.1.7",
		Roles:        []string{"security"},
		Description:  "Local authentication and authorization provider",
		Author:       "MuxCore",
		Capabilities: []string{contracts.CapabilityAuth, contracts.CapabilityAuthorizer, contracts.CapabilityIdentity, "settings"},
		// HTTPAddr is the mesh dial target for AuthService gRPC (core WireAuth convention).
		HTTPAddr: m.grpcAddr,
	}
}

func (m *Module) Init(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if dir := filepath.Dir(m.dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create db dir: %w", err)
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	var err error
	m.store, err = authStore.New(m.dbPath)
	if err != nil {
		return fmt.Errorf("init store: %w", err)
	}
	m.store.SetSessionConfig(parseSessionConfig())

	m.revocations = revocation.New()
	m.store.SetRevocationList(m.revocations)
	m.secMetrics = &security.Collector{}

	pol, err := m.loadPolicy()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	m.rateLimiter = ratelimit.New()
	m.loginBackoff = ratelimit.NewLoginBackoff()
	m.authSrv = server.New(m.store, pol, m.rpID, m.rpOrigins, m.rpName, m.rateLimiter, m.loginBackoff, m.secMetrics)

	m.waHandler, err = webauthn.New(m.rpID, m.rpOrigins, m.rpName, m.store, m.rateLimiter, m.trustedProxies, m.secMetrics)
	if err != nil {
		return fmt.Errorf("init webauthn: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	m.grpcLis, err = net.Listen("tcp", m.grpcAddr)
	if err != nil {
		return fmt.Errorf("listen gRPC %s: %w", m.grpcAddr, err)
	}
	m.httpLis, err = net.Listen("tcp", m.httpAddr)
	if err != nil {
		_ = m.grpcLis.Close()
		return fmt.Errorf("listen HTTP %s: %w", m.httpAddr, err)
	}
	if err := ctx.Err(); err != nil {
		_ = m.grpcLis.Close()
		_ = m.httpLis.Close()
		return err
	}
	publicURL := os.Getenv("AUTH_HTTP_URL")
	m.webHandler = webapp.New(m.store, publicURL, m.trustedProxies, m.rateLimiter, m.loginBackoff, m.secMetrics)
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
	m.cfgMu.RLock()
	path := m.policyFile
	m.cfgMu.RUnlock()
	pol, err := policy.Load(path)
	if err != nil {
		return err
	}
	if pol.RoleCount() == 0 {
		slog.Warn("reloaded policy has no roles — all Can() checks deny", "file", path)
	}
	m.authSrv.SetPolicy(pol)
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	runCtx, runCancel := context.WithCancel(ctx)
	m.runCancel = runCancel

	g, gCtx := errgroup.WithContext(runCtx)

	m.grpcSrv = grpc.NewServer()
	m.authSrv.RegisterWithGRPC(m.grpcSrv)
	modulesdk.RegisterSettings(m.grpcSrv, m.id, m)

	mux := http.NewServeMux()
	m.webHandler.RegisterRoutes(mux)
	m.waHandler.RegisterRoutes(mux)
	mux.HandleFunc("/metrics", webapp.MetricsHandler(m.authSrv.Metrics))
	mux.HandleFunc("/security/dashboard", webapp.SecurityDashboardHandler(m.secMetrics, func() int {
		if m.store == nil {
			return 0
		}
		return m.store.RevocationCount()
	}))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := m.Health(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(fmt.Sprintf(`{"status":"unhealthy","reason":%q}`, err.Error())))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	m.httpSrv = &http.Server{Handler: mux}

	g.Go(func() error {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigCh)

		for {
			select {
			case <-gCtx.Done():
				return nil
			case sig, ok := <-sigCh:
				if !ok {
					return nil
				}
				switch sig {
				case syscall.SIGHUP:
					slog.Info("SIGHUP received — reloading RBAC policy")
					if err := m.ReloadPolicy(); err != nil {
						slog.Error("policy reload failed", "error", err)
					}
				case syscall.SIGINT, syscall.SIGTERM:
					slog.Info("shutdown signal received", "signal", sig.String())
					runCancel()
					return nil
				}
			}
		}
	})

	g.Go(func() error {
		slog.Info("auth-local gRPC started", "addr", m.grpcAddr)
		errCh := make(chan error, 1)
		go func() {
			errCh <- m.grpcSrv.Serve(m.grpcLis)
		}()
		select {
		case <-gCtx.Done():
			m.grpcSrv.GracefulStop()
			err := <-errCh
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				slog.Error("auth-local gRPC shutdown error", "error", err)
			}
			return nil
		case err := <-errCh:
			if err != nil {
				slog.Error("auth-local gRPC error", "error", err)
				return err
			}
			return nil
		}
	})

	g.Go(func() error {
		slog.Info("auth-local HTTP started", "addr", m.httpAddr)
		errCh := make(chan error, 1)
		go func() {
			errCh <- m.httpSrv.Serve(m.httpLis)
		}()
		select {
		case <-gCtx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := m.httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("auth-local HTTP shutdown error", "error", err)
			}
			err := <-errCh
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("auth-local HTTP serve error after shutdown", "error", err)
			}
			return nil
		case err := <-errCh:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("auth-local HTTP error", "error", err)
				return err
			}
			return nil
		}
	})

	g.Go(func() error {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-gCtx.Done():
				return nil
			case <-ticker.C:
				if err := m.store.CleanupExpiredSessions(); err != nil {
					slog.Warn("session cleanup failed", "error", err)
				}
			}
		}
	})

	runDone := make(chan struct{})
	m.runDone = runDone
	go func() {
		defer close(runDone)
		if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("auth-local runtime error", "error", err)
		}
	}()

	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	var errs []error
	logStopErr := func(msg string, err error) {
		if err == nil {
			return
		}
		slog.Error(msg, "error", err)
		errs = append(errs, err)
	}

	if m.runCancel != nil {
		m.runCancel()
	}
	if m.runDone != nil {
		select {
		case <-m.runDone:
		case <-ctx.Done():
			logStopErr("auth-local stop: timed out waiting for background tasks", ctx.Err())
		}
	} else {
		if m.grpcSrv != nil {
			m.grpcSrv.GracefulStop()
		}
		if m.httpSrv != nil {
			if err := m.httpSrv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logStopErr("auth-local HTTP shutdown error", err)
			}
		}
	}

	if m.webHandler != nil {
		m.webHandler.Stop()
	}
	if m.rateLimiter != nil {
		m.rateLimiter.Stop()
	}
	if m.loginBackoff != nil {
		m.loginBackoff.Stop()
	}
	if m.revocations != nil {
		m.revocations.Stop()
	}
	if m.store != nil {
		if err := m.store.Close(); err != nil {
			logStopErr("auth-local store close error", err)
		}
	}
	slog.Info("auth-local stopped")
	return errors.Join(errs...)
}

func (m *Module) Health(ctx context.Context) error {
	if m.store == nil {
		return fmt.Errorf("not initialized")
	}
	if err := m.store.Ping(ctx); err != nil {
		return fmt.Errorf("database ping: %w", err)
	}
	if m.authSrv == nil || m.authSrv.PolicyRoleCount() == 0 {
		return fmt.Errorf("policy not loaded")
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
