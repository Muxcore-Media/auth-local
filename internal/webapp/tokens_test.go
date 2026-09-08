package webapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTokensAPIRequiresAdmin(t *testing.T) {
	h, _, _ := newInviteTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/tokens", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestTokensAPICreateListRotateRevoke(t *testing.T) {
	h, _, st := newInviteTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	auth := adminAuthHeader(t, st)

	createReq := httptest.NewRequest(http.MethodPost, "/api/tokens", strings.NewReader(`{"name":"laptop"}`))
	createReq.Header.Set("Authorization", auth)
	createW := httptest.NewRecorder()
	mux.ServeHTTP(createW, createReq)
	if createW.Code != http.StatusOK {
		t.Fatalf("create %d %s", createW.Code, createW.Body.String())
	}
	var created struct {
		Secret string `json:"secret"`
		Token  struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Prefix string `json:"prefix"`
		} `json:"token"`
	}
	if err := json.NewDecoder(createW.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Secret == "" || !strings.HasPrefix(created.Secret, "mct_") || created.Token.ID == "" || created.Token.Name != "laptop" {
		t.Fatalf("%#v", created)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/tokens", nil)
	listReq.Header.Set("Authorization", auth)
	listW := httptest.NewRecorder()
	mux.ServeHTTP(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("list %d %s", listW.Code, listW.Body.String())
	}
	if strings.Contains(listW.Body.String(), created.Secret) {
		t.Fatal("list must not echo the raw secret")
	}
	var listed struct {
		Tokens []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"tokens"`
	}
	if err := json.NewDecoder(listW.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Tokens) != 1 || listed.Tokens[0].ID != created.Token.ID {
		t.Fatalf("%#v", listed)
	}

	rotateReq := httptest.NewRequest(http.MethodPost, "/api/tokens/"+created.Token.ID+"/rotate", nil)
	rotateReq.Header.Set("Authorization", auth)
	rotateW := httptest.NewRecorder()
	mux.ServeHTTP(rotateW, rotateReq)
	if rotateW.Code != http.StatusOK {
		t.Fatalf("rotate %d %s", rotateW.Code, rotateW.Body.String())
	}
	var rotated struct {
		Secret string `json:"secret"`
		Token  struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"token"`
	}
	if err := json.NewDecoder(rotateW.Body).Decode(&rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Secret == "" || rotated.Secret == created.Secret || rotated.Token.ID == created.Token.ID || rotated.Token.Name != "laptop" {
		t.Fatalf("%#v", rotated)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/api/tokens/"+rotated.Token.ID, nil)
	delReq.Header.Set("Authorization", auth)
	delW := httptest.NewRecorder()
	mux.ServeHTTP(delW, delReq)
	if delW.Code != http.StatusOK {
		t.Fatalf("delete %d %s", delW.Code, delW.Body.String())
	}
}
