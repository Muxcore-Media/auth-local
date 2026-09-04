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

func TestAPIInvitePeekAndRedeem(t *testing.T) {
	st, err := authStore.New(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}

	h := New(st, "http://127.0.0.1:9401", nil, nil, nil, nil)
	inv, err := st.CreateInvite("admin", "viewer", "", 1, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	peekReq := httptest.NewRequest(http.MethodGet, "/api/invite/peek?token="+inv.Token, nil)
	peekRec := httptest.NewRecorder()
	h.apiInvitePeek(peekRec, peekReq)
	if peekRec.Code != http.StatusOK {
		t.Fatalf("peek status %d body %s", peekRec.Code, peekRec.Body.String())
	}
	var peek map[string]any
	if err := json.Unmarshal(peekRec.Body.Bytes(), &peek); err != nil {
		t.Fatal(err)
	}
	if peek["valid"] != true || peek["role"] != "viewer" {
		t.Fatalf("peek %+v", peek)
	}

	body := `{"token":"` + inv.Token + `","username":"newbie","password":"password123"}`
	redeemReq := httptest.NewRequest(http.MethodPost, "/api/invite/redeem", strings.NewReader(body))
	redeemReq.Header.Set("Content-Type", "application/json")
	redeemRec := httptest.NewRecorder()
	h.apiInviteRedeem(redeemRec, redeemReq)
	if redeemRec.Code != http.StatusOK {
		t.Fatalf("redeem status %d body %s", redeemRec.Code, redeemRec.Body.String())
	}
}
