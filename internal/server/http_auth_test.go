package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequireAdminHTTP(t *testing.T) {
	srv := newTestServer(t)
	admin, _ := srv.store.CreateUser("admin", "pw")
	_ = srv.store.SetRoles(admin.ID, []string{"admin"})
	adminSess, _ := srv.store.CreateFullSession(admin.ID)
	user, _ := srv.store.CreateUser("alice", "pw")
	userSess, _ := srv.store.CreateFullSession(user.ID)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/invites", nil)
	if srv.RequireAdminHTTP(rec, req) {
		t.Fatal("expected unauthenticated request to be denied")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d want 401", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/invites", nil)
	req.Header.Set("Authorization", "Bearer "+userSess.Token)
	if srv.RequireAdminHTTP(rec, req) {
		t.Fatal("expected non-admin to be denied")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d want 403", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/invites", nil)
	req.Header.Set("Authorization", "Bearer "+adminSess.Token)
	if !srv.RequireAdminHTTP(rec, req) {
		t.Fatalf("expected admin to pass, status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthenticateHTTPRequest(t *testing.T) {
	srv := newTestServer(t)
	user, _ := srv.store.CreateUser("alice", "pw")
	sess, _ := srv.store.CreateFullSession(user.ID)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if srv.AuthenticateHTTPRequest(req) {
		t.Fatal("expected unauthenticated request to fail")
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	if !srv.AuthenticateHTTPRequest(req) {
		t.Fatal("expected bearer session to authenticate")
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("x-auth-token", sess.Token)
	if !srv.AuthenticateHTTPRequest(req) {
		t.Fatal("expected x-auth-token session to authenticate")
	}
}

func TestMetricsHandlerRequiresAuth(t *testing.T) {
	srv := newTestServer(t)
	user, _ := srv.store.CreateUser("alice", "pw")
	sess, _ := srv.store.CreateFullSession(user.ID)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !srv.AuthenticateHTTPRequest(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(srv.Metrics()))
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d want 401", rec.Code)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"auth_login_success_total", "auth_sessions_active"} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q: %s", want, body)
		}
	}
}

func TestAuthenticateHTTPRequest_InvalidToken(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	if srv.AuthenticateHTTPRequest(req) {
		t.Fatal("expected invalid token to fail")
	}
}
