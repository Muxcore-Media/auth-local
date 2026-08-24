package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSettingsPolicyAndRP(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policies.yaml")
	if err := os.WriteFile(policyPath, []byte("roles:\n  admin:\n    permissions: [\"*\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewModule(Config{
		DBPath:     filepath.Join(dir, "auth.db"),
		PolicyFile: policyPath,
		GRPCAddr:   "127.0.0.1:0",
		HTTPAddr:   "127.0.0.1:0",
		RPID:       "localhost",
		RPOrigins:  "http://localhost:9401",
		RPName:     "MuxCore",
	})
	if err := m.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Stop(t.Context()) }()

	defs := m.Settings()
	if len(defs) != 4 {
		t.Fatalf("settings=%d", len(defs))
	}
	if err := m.UpdateSetting("rp_name", "MuxCore Auth"); err != nil {
		t.Fatal(err)
	}
	if got := m.Settings()[3].Value; got != "MuxCore Auth" {
		t.Fatalf("rp_name=%q", got)
	}
	if err := m.UpdateSetting("rp_origins", ""); err == nil {
		t.Fatal("expected error")
	}
	alt := filepath.Join(dir, "alt.yaml")
	if err := os.WriteFile(alt, []byte("roles:\n  viewer:\n    permissions: [\"read\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateSetting("policy_file", alt); err != nil {
		t.Fatal(err)
	}
}
