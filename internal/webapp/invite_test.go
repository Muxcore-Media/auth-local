package webapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Muxcore-Media/auth-local/internal/policy"
	"github.com/Muxcore-Media/auth-local/internal/server"
	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

func newInviteTestHandler(t *testing.T) (*Handler, *server.AuthServer, *authStore.Store) {
	st, err := authStore.New(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	srv := server.New(st, policy.Builtin(), "localhost", []string{"http://localhost"}, "test")
	h := NewWithAuth(st, srv, "127.0.0.1:0", nil)
	return h, srv, st
}

func adminAuthHeader(t *testing.T, st *authStore.Store) string {
	user, err := st.CreateUser("admin", "password123")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetRoles(user.ID, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	sess, err := st.CreateFullSession(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	return "Bearer " + sess.Token
}

func TestInviteAPICreateRedeemExpireRevoke(t *testing.T) {
	h, _, st := newInviteTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	auth := adminAuthHeader(t, st)

	// Create
	body := `{"role":"user","maxUses":1,"ttlHours":1}`
	req := httptest.NewRequest(http.MethodPost, "/api/invites", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create status %d body=%s", w.Code, w.Body.String())
	}
	var inv authStore.Invite
	if err := json.Unmarshal(w.Body.Bytes(), &inv); err != nil || inv.Token == "" {
		t.Fatalf("parse invite: %v %+v", err, inv)
	}

	// List
	w = httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/api/invites", nil)
	listReq.Header.Set("Authorization", auth)
	mux.ServeHTTP(w, listReq)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), inv.Prefix) {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}

	// Redeem page (sets CSRF cookie)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/invite?token="+inv.Token, nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Join MuxCore") {
		t.Fatalf("invite page: %d", w.Code)
	}
	var csrfCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "muxcore-auth-csrf" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil || csrfCookie.Value == "" {
		t.Fatal("missing CSRF cookie on invite page")
	}

	// Redeem
	form := "csrf_token=" + csrfCookie.Value + "&token=" + inv.Token + "&username=newuser&password=password123"
	req = httptest.NewRequest(http.MethodPost, "/invite/redeem", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Account created") {
		t.Fatalf("redeem: %d %s", w.Code, w.Body.String())
	}

	// Expire path via short TTL invite
	inv2, err := st.CreateInvite("admin", "user", "", 1, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/invite?token="+inv2.Token, nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expired page want 400 got %d", w.Code)
	}

	// Revoke
	inv3, err := st.CreateInvite("admin", "user", "", 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodDelete, "/api/invites/"+inv3.ID, nil)
	req.Header.Set("Authorization", auth)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	_, _, err = st.RedeemInvite(inv3.Token, "x", "password123")
	if err == nil {
		t.Fatal("expected revoked redeem fail")
	}
}

func TestInviteAPI_NonAdminCannotMint(t *testing.T) {
	h, _, st := newInviteTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	user, err := st.CreateUser("alice", "password123")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := st.CreateFullSession(user.ID)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/invites", strings.NewReader(`{"role":"user","ttlHours":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("create status %d want 403 body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/api/invites", nil)
	listReq.Header.Set("Authorization", "Bearer "+sess.Token)
	mux.ServeHTTP(w, listReq)
	if w.Code != http.StatusForbidden {
		t.Fatalf("list status %d want 403", w.Code)
	}
}

func TestInviteAPI_UnauthenticatedDenied(t *testing.T) {
	h, _, _ := newInviteTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/invites", strings.NewReader(`{"role":"user"}`)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("create status %d want 401", w.Code)
	}
}
