package webapp

import (
	"net/url"
	"testing"
)

func TestSafeRedirectAllowsLANPublicURLs(t *testing.T) {
	t.Setenv("ADMIN_UI_PUBLIC_URL", "http://192.168.40.153:8082")
	t.Setenv("MEDIA_UI_PUBLIC_URL", "http://192.168.40.153:5173")

	req, err := url.Parse("http://192.168.40.153:9401/login")
	if err != nil {
		t.Fatal(err)
	}
	got := safeRedirect(req, "http://192.168.40.153:8082/auth/callback")
	if got != "http://192.168.40.153:8082/auth/callback" {
		t.Fatalf("admin callback: got %q", got)
	}
	got = safeRedirect(req, "http://192.168.40.153:5173/auth/callback")
	if got != "http://192.168.40.153:5173/auth/callback" {
		t.Fatalf("media callback: got %q", got)
	}
	got = safeRedirect(req, "https://evil.example/phish")
	if got != "/" {
		t.Fatalf("open redirect: got %q", got)
	}
}
