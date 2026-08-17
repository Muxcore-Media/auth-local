package redirectallow

import "testing"

func TestHostAllowedLoopbackDefaults(t *testing.T) {
	if !HostAllowed("127.0.0.1:9401", "localhost:8082") {
		t.Fatal("localhost:8082 should be allowed")
	}
	if !HostAllowed("127.0.0.1:9401", "127.0.0.1:5173") {
		t.Fatal("127.0.0.1:5173 should be allowed")
	}
	if HostAllowed("127.0.0.1:9401", "evil.example:8082") {
		t.Fatal("unknown host must be rejected")
	}
	if !HostAllowed("192.168.40.153:9401", "192.168.40.153:9401") {
		t.Fatal("same host as the auth request should be allowed")
	}
}

func TestHostAllowedFromPublicURLs(t *testing.T) {
	t.Setenv("ADMIN_UI_PUBLIC_URL", "http://192.168.40.153:8082")
	t.Setenv("MEDIA_UI_PUBLIC_URL", "http://192.168.40.153:5173/")
	t.Setenv("AUTH_ALLOWED_REDIRECT_HOSTS", "vault.lan:8082")

	if !HostAllowed("127.0.0.1:9401", "192.168.40.153:8082") {
		t.Fatal("admin public URL host should be allowed")
	}
	if !HostAllowed("127.0.0.1:9401", "192.168.40.153:5173") {
		t.Fatal("media public URL host should be allowed")
	}
	if !HostAllowed("127.0.0.1:9401", "vault.lan:8082") {
		t.Fatal("AUTH_ALLOWED_REDIRECT_HOSTS should be allowed")
	}
}
