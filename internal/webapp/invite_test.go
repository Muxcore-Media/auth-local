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

func TestInviteAPICreateRedeemExpireRevoke(t *testing.T) {
	dir := t.TempDir()
	st, err := authStore.New(filepath.Join(dir, "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	h := New(st, "127.0.0.1:0", nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Create
	body := `{"createdBy":"admin","role":"user","maxUses":1,"ttlHours":1}`
	req := httptest.NewRequest(http.MethodPost, "/api/invites", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
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
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/invites", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), inv.Prefix) {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}

	// Redeem page
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/invite?token="+inv.Token, nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Join MuxCore") {
		t.Fatalf("invite page: %d", w.Code)
	}

	// Redeem
	form := "token=" + inv.Token + "&username=newuser&password=password123"
	req = httptest.NewRequest(http.MethodPost, "/invite/redeem", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
