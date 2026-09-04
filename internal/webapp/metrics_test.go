package webapp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetricsHandlerLoopbackOnly(t *testing.T) {
	h := MetricsHandler(func() string { return "auth_login_success_total 0\n" })

	t.Run("loopback", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if got := rec.Body.String(); got != "auth_login_success_total 0\n" {
			t.Fatalf("body = %q", got)
		}
	})

	t.Run("non_loopback", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "192.168.1.50:9999"
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("xff_spoof_ignored", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "10.0.0.1:443"
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", rec.Code)
		}
	})
}
