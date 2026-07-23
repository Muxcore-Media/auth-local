package webapp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractIPTrustedXFF(t *testing.T) {
	h := New(nil, ":9401", nil)
	t.Cleanup(h.Stop)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.1")
	if ip := h.extractIP(r); ip != "203.0.113.1" {
		t.Fatalf("expected 203.0.113.1, got %s", ip)
	}
}

func TestExtractIPUntrustedXFFIgnored(t *testing.T) {
	h := New(nil, ":9401", nil)
	t.Cleanup(h.Stop)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.168.1.50:9999"
	r.Header.Set("X-Forwarded-For", "203.0.113.1")
	if ip := h.extractIP(r); ip != "192.168.1.50" {
		t.Fatalf("expected 192.168.1.50, got %s", ip)
	}
}

func TestExtractIPXRealIPIgnored(t *testing.T) {
	h := New(nil, ":9401", nil)
	t.Cleanup(h.Stop)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Real-IP", "203.0.113.9")
	if ip := h.extractIP(r); ip != "127.0.0.1" {
		t.Fatalf("expected 127.0.0.1, got %s", ip)
	}
}

func TestExtractIPRightmostXFF(t *testing.T) {
	h := New(nil, ":9401", nil)
	t.Cleanup(h.Stop)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.1")
	if ip := h.extractIP(r); ip != "203.0.113.1" {
		t.Fatalf("expected 203.0.113.1, got %s", ip)
	}
}
