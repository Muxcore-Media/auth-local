package grpctls

import (
	"crypto/tls"
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
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven || cfg.ClientCAs == nil {
		t.Fatalf("auto TLS must verify client certs against the mesh CA: ClientAuth=%v ClientCAs=%v", cfg.ClientAuth, cfg.ClientCAs != nil)
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

// Without a mesh CA, client certificates must not be requested at all: they
// would otherwise be verified against the system roots.
func TestServerConfig_NoCANoClientCerts(t *testing.T) {
	t.Setenv(envInsecureDisableTLS, "")
	t.Setenv(envGRPCInsecure, "")
	gen := t.TempDir()
	if err := ensureAutoCerts(gen); err != nil {
		t.Fatalf("ensureAutoCerts: %v", err)
	}
	t.Setenv(envAuthTLSDir, "")
	t.Setenv(envAuthTLSCert, filepath.Join(gen, "server.crt"))
	t.Setenv(envAuthTLSKey, filepath.Join(gen, "server.key"))
	t.Setenv(envTLSCert, "")
	t.Setenv(envTLSKey, "")
	t.Setenv(envAuthTLSCA, "")
	t.Setenv(envTLSCA, "")

	cfg, err := ServerConfig(t.TempDir())
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	if cfg == nil || cfg.ClientAuth != tls.NoClientCert || cfg.ClientCAs != nil {
		t.Fatalf("expected NoClientCert without a CA, got %+v", cfg)
	}
}
