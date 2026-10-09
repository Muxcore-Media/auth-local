package internal

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testModule(t *testing.T, policyYAML string) *Module {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.yaml")
	if policyYAML != "" {
		if err := os.WriteFile(policyPath, []byte(policyYAML), 0644); err != nil {
			t.Fatalf("write policy: %v", err)
		}
	} else {
		policyPath = filepath.Join(dir, "missing-policies.yaml")
	}
	m := NewModule(Config{
		GRPCAddr:   "127.0.0.1:0",
		HTTPAddr:   "127.0.0.1:0",
		PolicyFile: policyPath,
		DBPath:     filepath.Join(dir, "auth.db"),
		RPID:       "localhost",
		RPOrigins:  "http://localhost:9401",
		RPName:     "MuxCore Test",
	})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		_ = m.Stop(context.Background())
	})
	return m
}

func TestInitLoadsPolicy(t *testing.T) {
	m := testModule(t, `
roles:
  admin:
    permissions: ["*"]
  custom:
    permissions: ["media.view"]
`)
	allowed, _ := m.AuthServer().AuthorizeForTest([]string{"custom"}, "view", "media")
	if !allowed {
		t.Fatal("expected custom role from loaded policy")
	}
}

func TestInitUsesBuiltinWhenPolicyMissing(t *testing.T) {
	m := testModule(t, "")
	allowed, _ := m.AuthServer().AuthorizeForTest([]string{"admin"}, "anything", "anything")
	if !allowed {
		t.Fatal("expected builtin admin * permission")
	}
	allowed, _ = m.AuthServer().AuthorizeForTest([]string{"viewer"}, "view", "media")
	if !allowed {
		t.Fatal("expected builtin viewer media.view")
	}
	allowed, _ = m.AuthServer().AuthorizeForTest([]string{"viewer"}, "delete", "media")
	if allowed {
		t.Fatal("expected builtin viewer denied delete")
	}
}

func TestReloadPolicy(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.yaml")
	if err := os.WriteFile(policyPath, []byte(`
roles:
  admin:
    permissions: ["*"]
`), 0644); err != nil {
		t.Fatal(err)
	}
	m := NewModule(Config{
		GRPCAddr:   "127.0.0.1:0",
		HTTPAddr:   "127.0.0.1:0",
		PolicyFile: policyPath,
		DBPath:     filepath.Join(dir, "auth.db"),
		RPID:       "localhost",
		RPOrigins:  "http://localhost",
	})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })

	if err := os.WriteFile(policyPath, []byte(`
roles:
  viewer:
    permissions: ["media.view"]
`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := m.ReloadPolicy(); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}
	allowed, _ := m.AuthServer().AuthorizeForTest([]string{"admin"}, "x", "y")
	if allowed {
		t.Fatal("expected admin removed after reload")
	}
	allowed, _ = m.AuthServer().AuthorizeForTest([]string{"viewer"}, "view", "media")
	if !allowed {
		t.Fatal("expected viewer after reload")
	}
}

func TestSIGHUPReloadsPolicy(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.yaml")
	if err := os.WriteFile(policyPath, []byte(`
roles:
  admin:
    permissions: ["*"]
`), 0644); err != nil {
		t.Fatal(err)
	}
	m := NewModule(Config{
		GRPCAddr:   "127.0.0.1:0",
		HTTPAddr:   "127.0.0.1:0",
		PolicyFile: policyPath,
		DBPath:     filepath.Join(dir, "auth.db"),
		RPID:       "localhost",
		RPOrigins:  "http://localhost",
	})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })

	if err := os.WriteFile(policyPath, []byte(`
roles:
  viewer:
    permissions: ["media.view"]
`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("SIGHUP: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		allowed, _ := m.AuthServer().AuthorizeForTest([]string{"viewer"}, "view", "media")
		if allowed {
			adminOK, _ := m.AuthServer().AuthorizeForTest([]string{"admin"}, "x", "y")
			if !adminOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("SIGHUP did not reload policy in time")
}

func TestMetricsRouteRequiresAuth(t *testing.T) {
	m := testModule(t, `
roles:
  admin:
    permissions: ["*"]
`)
	resp, err := http.Get("http://" + m.HTTPAddr() + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d want 401", resp.StatusCode)
	}
}

func TestHealthRouteChecksDatabase(t *testing.T) {
	m := testModule(t, `
roles:
  admin:
    permissions: ["*"]
`)
	resp, err := http.Get("http://" + m.HTTPAddr() + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("health body = %s", body)
	}
	if err := m.Health(context.Background()); err != nil {
		t.Fatalf("Module.Health: %v", err)
	}
}

func TestWebAuthnRoutesMounted(t *testing.T) {
	m := testModule(t, `
roles:
  admin:
    permissions: ["*"]
`)
	resp, err := http.Get("http://" + m.HTTPAddr() + "/api/webauthn/login/begin")
	if err != nil {
		t.Fatalf("GET webauthn: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		t.Fatal("webauthn route not mounted")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 (missing username), got %d", resp.StatusCode)
	}
}

func TestDBPathUsed(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "custom.db")
	policyPath := filepath.Join(dir, "policies.yaml")
	_ = os.WriteFile(policyPath, []byte(`roles: {admin: {permissions: ["*"]}}`), 0644)
	m := NewModule(Config{
		GRPCAddr:   "127.0.0.1:0",
		HTTPAddr:   "127.0.0.1:0",
		PolicyFile: policyPath,
		DBPath:     dbPath,
		RPID:       "localhost",
		RPOrigins:  "http://localhost",
	})
	if err := m.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected db at %s: %v", dbPath, err)
	}
}

func TestErasureConfigFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cfg := erasureConfigFromEnv(env(map[string]string{
		"AUTH_ERASURE_CONSUMERS": "userdata-local, request-media,,",
		"AUTH_ERASURE_REQUIRED":  "userdata-local",
	}))
	if strings.Join(cfg.Consumers, ",") != "userdata-local,request-media" || strings.Join(cfg.Required, ",") != "userdata-local" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if empty := erasureConfigFromEnv(env(nil)); len(empty.Consumers) != 0 || len(empty.Required) != 0 {
		t.Fatalf("unset env = %+v; want no consumers (fail closed)", empty)
	}
	t.Setenv("MUXCORE_INSECURE_DISABLE_TLS", "true")
	if !erasureConfigFromEnv(env(nil)).TrustCallerIDWithoutTLS {
		t.Fatal("dev insecure listener should trust x-caller-id on plaintext")
	}
	for _, profile := range []string{"household", "staging", " Household "} {
		if erasureConfigFromEnv(env(map[string]string{"MUXCORE_PROFILE": profile})).TrustCallerIDWithoutTLS {
			t.Fatalf("profile %q must never trust x-caller-id", profile)
		}
	}
	t.Setenv("MUXCORE_INSECURE_DISABLE_TLS", "")
	if erasureConfigFromEnv(env(nil)).TrustCallerIDWithoutTLS {
		t.Fatal("TLS listener must not trust x-caller-id")
	}
}
