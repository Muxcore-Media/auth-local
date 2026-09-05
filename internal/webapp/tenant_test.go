package webapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

func TestLoginExchangeIncludesTenantClaim(t *testing.T) {
	dir := t.TempDir()
	st, err := authStore.New(filepath.Join(dir, "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	user, err := st.CreateUserTenant("carol", "password123", "tenant-z")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := st.CreateFullSession(user.ID)
	if err != nil {
		t.Fatal(err)
	}

	h := New(st, "127.0.0.1:0", nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Generate a one-time code via redirect helpers: call exchange with a code
	// produced through generateCode.
	code := h.generateCode(sess.Token)
	body := `{"code":"` + code + `"}`
	req := httptest.NewRequest(http.MethodPost, "/login/exchange", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", w.Code, w.Body.String())
	}
	var out struct {
		TenantID string         `json:"tenant_id"`
		Claims   map[string]any `json:"claims"`
		Username string         `json:"username"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.TenantID != "tenant-z" || out.Username != "carol" {
		t.Fatalf("out=%+v", out)
	}
	if out.Claims["tenant_id"] != "tenant-z" {
		t.Fatalf("claims=%v", out.Claims)
	}
}

func TestInviteAPIAcceptsTenant(t *testing.T) {
	h, _, st := newInviteTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	auth := adminAuthHeader(t, st)

	body := `{"role":"user","tenantId":"hh-1","maxUses":1,"ttlHours":1}`
	req := httptest.NewRequest(http.MethodPost, "/api/invites", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create %d %s", w.Code, w.Body.String())
	}
	var inv authStore.Invite
	if err := json.Unmarshal(w.Body.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	if inv.TenantID != "hh-1" || inv.Token == "" {
		t.Fatalf("%+v", inv)
	}
	user, _, err := st.RedeemInvite(inv.Token, "dave", "password123")
	if err != nil {
		t.Fatal(err)
	}
	if user.TenantID != "hh-1" {
		t.Fatalf("user tenant=%q", user.TenantID)
	}
}
