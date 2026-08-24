package webauthn

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

func newTestHandler(t *testing.T) (*Handler, *authStore.Store) {
	t.Helper()
	st, err := authStore.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	h, err := New("localhost", []string{"http://localhost:8080"}, "MuxCore Test", st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h, st
}

func TestMuxEndpointsRegistered(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := h.Mux()

	eps := []string{
		"/api/webauthn/register/begin",
		"/api/webauthn/register/complete",
		"/api/webauthn/login/begin",
		"/api/webauthn/login/complete",
		"/health",
	}
	for _, ep := range eps {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code == 404 {
			t.Errorf("expected %s to be registered, got 404", ep)
		}
	}
}

func TestHealthEndpoint(t *testing.T) {
	h, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected ok, got %s", resp["status"])
	}
}

func TestBeginRegistrationRequiresAuth(t *testing.T) {
	h, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/webauthn/register/begin", nil)
	w := httptest.NewRecorder()
	h.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestBeginRegistrationReturnsOptions(t *testing.T) {
	h, st := newTestHandler(t)
	_, _ = st.CreateUser("alice", "password123")
	user, _ := st.GetUserByUsername("alice")
	sess, _ := st.CreateFullSession(user.ID)

	req := httptest.NewRequest(http.MethodGet, "/api/webauthn/register/begin", nil)
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	w := httptest.NewRecorder()
	h.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var options map[string]any
	if err := json.NewDecoder(w.Body).Decode(&options); err != nil {
		t.Fatalf("decode: %v", err)
	}
	pk, ok := options["publicKey"].(map[string]any)
	if !ok {
		t.Fatal("expected publicKey in response")
	}
	if pk["challenge"] == nil {
		t.Error("expected challenge in publicKey")
	}
	if pk["rp"] == nil {
		t.Error("expected rp in publicKey")
	}
	if pk["user"] == nil {
		t.Error("expected user in publicKey")
	}
}

func TestBeginLoginWithoutUsername(t *testing.T) {
	h, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/webauthn/login/begin", nil)
	w := httptest.NewRecorder()
	h.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBeginLoginNonexistentUser(t *testing.T) {
	h, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/webauthn/login/begin?username=nobody", nil)
	w := httptest.NewRecorder()
	h.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestBeginLoginReturnsOptions(t *testing.T) {
	h, st := newTestHandler(t)
	_, _ = st.CreateUser("alice", "pw")

	req := httptest.NewRequest(http.MethodGet, "/api/webauthn/login/begin?username=alice", nil)
	w := httptest.NewRecorder()
	h.Mux().ServeHTTP(w, req)

	// User exists but has no WebAuthn credentials — expect error, not 200.
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 (no credentials), got %d: %s", w.Code, w.Body.String())
	}
}

func TestCompleteRegistrationWithoutBody(t *testing.T) {
	h, st := newTestHandler(t)
	_, _ = st.CreateUser("alice", "pw")
	user, _ := st.GetUserByUsername("alice")
	sess, _ := st.CreateFullSession(user.ID)

	req := httptest.NewRequest(http.MethodPost, "/api/webauthn/register/complete", nil)
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	w := httptest.NewRecorder()
	h.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing body, got %d", w.Code)
	}
}

func TestStoreSatisfiesInterface(t *testing.T) {
	h, _ := newTestHandler(t)
	_ = h.store // compile-time check: *store.Store implements WebAuthnStore
}
