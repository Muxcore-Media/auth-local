package webapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

func adminSession(t *testing.T, st *authStore.Store) string {
	t.Helper()
	user, err := st.CreateUser("administrator", "adminpass123")
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
	return sess.Token
}

func TestInviteAPICreateRedeemExpireRevoke(t *testing.T) {
	dir := t.TempDir()
	st, err := authStore.New(filepath.Join(dir, "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	token := adminSession(t, st)
	h := New(st, "127.0.0.1:0", nil, nil, nil, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	authHeader := "Bearer " + token

	// Create
	body := `{"role":"user","maxUses":1,"ttlHours":1}`
	req := httptest.NewRequest(http.MethodPost, "/api/invites", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create status %d body=%s", w.Code, w.Body.String())
	}
	var inv authStore.Invite
	if err := json.Unmarshal(w.Body.Bytes(), &inv); err != nil || inv.Token == "" {
		t.Fatalf("parse invite: %v %+v", err, inv)
	}

	// Reject admin role on create
	req = httptest.NewRequest(http.MethodPost, "/api/invites", strings.NewReader(`{"role":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("admin role create want 400 got %d", w.Code)
	}

	// Unauthenticated create denied
	req = httptest.NewRequest(http.MethodPost, "/api/invites", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth create want 401 got %d", w.Code)
	}

	// List
	w = httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/api/invites", nil)
	listReq.Header.Set("Authorization", authHeader)
	mux.ServeHTTP(w, listReq)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), inv.Prefix) {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}

	// Redeem page
	pageRec := httptest.NewRecorder()
	mux.ServeHTTP(pageRec, httptest.NewRequest(http.MethodGet, "/invite?token="+inv.Token, nil))
	if pageRec.Code != http.StatusOK || !strings.Contains(pageRec.Body.String(), "Join MuxCore") {
		t.Fatalf("invite page: %d", pageRec.Code)
	}
	var csrfVal string
	var pageCookies []*http.Cookie
	for _, c := range pageRec.Result().Cookies() {
		if c.Name == authCSRFCookie {
			csrfVal = c.Value
		}
		pageCookies = append(pageCookies, c)
	}
	if csrfVal == "" {
		t.Fatal("missing csrf cookie on invite page")
	}

	// Redeem without CSRF denied
	form := "token=" + inv.Token + "&username=newuser&password=password123"
	req = httptest.NewRequest(http.MethodPost, "/invite/redeem", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("redeem without csrf want 403 got %d", w.Code)
	}

	// Redeem with CSRF
	form = "token=" + inv.Token + "&username=newuser&password=password123&csrf_token=" + csrfVal
	req = httptest.NewRequest(http.MethodPost, "/invite/redeem", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range pageCookies {
		req.AddCookie(c)
	}
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
	req.Header.Set("Authorization", authHeader)
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
