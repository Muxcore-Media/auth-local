package webapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUsersAPIListRequiresAdmin(t *testing.T) {
	h, _, _ := newInviteTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/users", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestUsersAPIListAndRoleAndDelete(t *testing.T) {
	h, _, st := newInviteTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	auth := adminAuthHeader(t, st)

	member, err := st.CreateUser("pat", "password123")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetRoles(member.ID, []string{"user"}); err != nil {
		t.Fatal(err)
	}

	createReq := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(`{"username":"sam","password":"password123","role":"viewer"}`))
	createReq.Header.Set("Authorization", auth)
	createW := httptest.NewRecorder()
	mux.ServeHTTP(createW, createReq)
	if createW.Code != http.StatusCreated {
		t.Fatalf("create %d %s", createW.Code, createW.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	listReq.Header.Set("Authorization", auth)
	listW := httptest.NewRecorder()
	mux.ServeHTTP(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("list %d %s", listW.Code, listW.Body.String())
	}
	var listed struct {
		Users []struct {
			ID       string   `json:"id"`
			Username string   `json:"username"`
			Roles    []string `json:"roles"`
		} `json:"users"`
	}
	if err := json.NewDecoder(listW.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Users) < 2 {
		t.Fatalf("%#v", listed)
	}

	patchReq := httptest.NewRequest(http.MethodPatch, "/api/users/"+member.ID, strings.NewReader(`{"role":"viewer"}`))
	patchReq.Header.Set("Authorization", auth)
	patchW := httptest.NewRecorder()
	mux.ServeHTTP(patchW, patchReq)
	if patchW.Code != http.StatusOK {
		t.Fatalf("patch %d %s", patchW.Code, patchW.Body.String())
	}

	pwReq := httptest.NewRequest(http.MethodPost, "/api/users/"+member.ID+"/password", strings.NewReader(`{"password":"newpass99"}`))
	pwReq.Header.Set("Authorization", auth)
	pwW := httptest.NewRecorder()
	mux.ServeHTTP(pwW, pwReq)
	if pwW.Code != http.StatusOK {
		t.Fatalf("password %d %s", pwW.Code, pwW.Body.String())
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/api/users/"+member.ID, nil)
	delReq.Header.Set("Authorization", auth)
	delW := httptest.NewRecorder()
	mux.ServeHTTP(delW, delReq)
	if delW.Code != http.StatusOK {
		t.Fatalf("delete %d %s", delW.Code, delW.Body.String())
	}
}

func TestUsersAPIRejectsSelfDeleteAndLastAdmin(t *testing.T) {
	h, _, st := newInviteTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	auth := adminAuthHeader(t, st)
	users, err := st.ListUsers()
	if err != nil || len(users) != 1 {
		t.Fatalf("users=%v err=%v", users, err)
	}
	adminID := users[0].ID

	selfReq := httptest.NewRequest(http.MethodDelete, "/api/users/"+adminID, nil)
	selfReq.Header.Set("Authorization", auth)
	selfW := httptest.NewRecorder()
	mux.ServeHTTP(selfW, selfReq)
	if selfW.Code != http.StatusBadRequest {
		t.Fatalf("self-delete %d %s", selfW.Code, selfW.Body.String())
	}

	demote := httptest.NewRequest(http.MethodPatch, "/api/users/"+adminID, strings.NewReader(`{"role":"user"}`))
	demote.Header.Set("Authorization", auth)
	demoteW := httptest.NewRecorder()
	mux.ServeHTTP(demoteW, demote)
	if demoteW.Code != http.StatusBadRequest {
		t.Fatalf("demote %d %s", demoteW.Code, demoteW.Body.String())
	}
}

// TestUsersAPIDeleteIsErasure: HTTP DELETE runs the same ADR-0035 erasure as
// gRPC DeleteUser: admin only, tenant-scoped, idempotent with the same
// erasure id, and every bearer of the user stops working.
func TestUsersAPIDeleteIsErasure(t *testing.T) {
	h, srv, st := newInviteTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	auth := adminAuthHeader(t, st)
	member, err := st.CreateUser("pat", "password123")
	if err != nil {
		t.Fatal(err)
	}
	memberSess, err := st.CreateFullSession(member.ID)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := st.CreateUserTenant("far", "password123", "household-2")
	if err != nil {
		t.Fatal(err)
	}
	del := func(id, authz string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/api/users/"+id, nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	if w := del(member.ID, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous delete %d", w.Code)
	}
	if w := del(foreign.ID, "Bearer "+memberSess.Token); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin delete %d", w.Code)
	}
	if w := del(foreign.ID, auth); w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete %d %s", w.Code, w.Body.String())
	}
	if _, err := st.GetUser(foreign.ID); err != nil {
		t.Fatal("cross-tenant target deleted")
	}
	if w := del("never-seen", auth); w.Code != http.StatusNotFound {
		t.Fatalf("unknown delete %d", w.Code)
	}

	w := del(member.ID, auth)
	if w.Code != http.StatusOK {
		t.Fatalf("delete %d %s", w.Code, w.Body.String())
	}
	var body struct {
		Removed   bool   `json:"removed"`
		ErasureID string `json:"erasure_id"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil || !body.Removed || body.ErasureID == "" {
		t.Fatalf("delete body = %+v, %v", body, err)
	}
	probe := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	probe.Header.Set("Authorization", "Bearer "+memberSess.Token)
	if srv.AuthenticateHTTPRequest(probe) {
		t.Fatal("erased user's bearer still authenticates")
	}
	w = del(member.ID, auth)
	var again struct {
		ErasureID string `json:"erasure_id"`
	}
	if w.Code != http.StatusOK || json.NewDecoder(w.Body).Decode(&again) != nil || again.ErasureID != body.ErasureID {
		t.Fatalf("repeat delete %d %+v; want the same erasure id", w.Code, again)
	}
}
