package webauthn

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

func TestListCredentialsRequiresSession(t *testing.T) {
	st, err := authStore.New(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h, err := New("localhost", []string{"http://localhost"}, "test", st)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/webauthn/credentials", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
}

func TestListAndDeleteOwnCredentials(t *testing.T) {
	st, err := authStore.New(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	user, err := st.CreateUser("sam", "password123")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddWebAuthnCredential(user.ID, []byte(`{"id":"cred-1"}`)); err != nil {
		t.Fatal(err)
	}
	sess, err := st.CreateFullSession(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New("localhost", []string{"http://localhost"}, "test", st)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	listReq := httptest.NewRequest(http.MethodGet, "/api/webauthn/credentials", nil)
	listReq.Header.Set("Authorization", "Bearer "+sess.Token)
	listW := httptest.NewRecorder()
	mux.ServeHTTP(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("list %d %s", listW.Code, listW.Body.String())
	}
	var listed struct {
		Count       int `json:"count"`
		Credentials []struct {
			ID string `json:"id"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(listW.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed.Count != 1 || listed.Credentials[0].ID == "" {
		t.Fatalf("%#v", listed)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/api/webauthn/credentials/"+listed.Credentials[0].ID, nil)
	delReq.Header.Set("Authorization", "Bearer "+sess.Token)
	delW := httptest.NewRecorder()
	mux.ServeHTTP(delW, delReq)
	if delW.Code != http.StatusOK {
		t.Fatalf("delete %d %s", delW.Code, delW.Body.String())
	}
	infos, err := st.ListWebAuthnCredentialMeta(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 0 {
		t.Fatalf("still listed %#v", infos)
	}
}

func TestListOtherUserCredentialsForbidden(t *testing.T) {
	st, err := authStore.New(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	member, err := st.CreateUser("sam", "password123")
	if err != nil {
		t.Fatal(err)
	}
	other, err := st.CreateUser("pat", "password123")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := st.CreateFullSession(member.ID)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New("localhost", []string{"http://localhost"}, "test", st)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, "/api/webauthn/credentials?user_id="+other.ID, nil)
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
}
