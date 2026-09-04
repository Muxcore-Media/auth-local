package webapp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRootHandlerRedirectsToLogin(t *testing.T) {
	h := New(nil, "https://auth.zem.systems", nil, nil, nil, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/login" {
		t.Fatalf("location=%q want /login", got)
	}
}

func TestRootHandlerMisredirectWithCode(t *testing.T) {
	t.Setenv("MEDIA_UI_PUBLIC_URL", "https://mux.zem.systems")

	h := New(nil, "https://auth.zem.systems", nil, nil, nil, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/?code=abc123", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "https://mux.zem.systems") {
		t.Fatalf("expected media URL hint in body: %s", body)
	}
	if strings.Contains(body, "404") {
		t.Fatalf("unexpected 404 page: %s", body)
	}
}

func TestRootHandlerNotFoundForOtherPaths(t *testing.T) {
	h := New(nil, "https://auth.zem.systems", nil, nil, nil, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}
