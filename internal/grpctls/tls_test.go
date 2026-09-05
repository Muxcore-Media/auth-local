package grpctls

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServerConfig_AutoGenerate(t *testing.T) {
	t.Setenv(envInsecureDisableTLS, "")
	t.Setenv(envGRPCInsecure, "")
	t.Setenv(envAuthTLSCert, "")
	t.Setenv(envAuthTLSKey, "")
	t.Setenv(envTLSCert, "")
	t.Setenv(envTLSKey, "")

	dir := t.TempDir()
	t.Setenv(envAuthTLSDir, dir)

	cfg, err := ServerConfig(filepath.Join(dir, "auth.db"))
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected TLS config")
	}
	if len(cfg.Certificates) == 0 {
		t.Fatal("expected server certificate")
	}
	for _, name := range []string{"server.crt", "server.key", "ca.crt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
}

func TestServerConfig_InsecureDisabled(t *testing.T) {
	t.Setenv(envInsecureDisableTLS, "true")
	cfg, err := ServerConfig("")
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected nil TLS config when insecure enabled")
	}
}
