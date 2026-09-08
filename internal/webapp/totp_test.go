package webapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestTOTPAPIRequiresSession(t *testing.T) {
	h, _, _ := newInviteTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/totp", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestTOTPAPIEnableVerifyDisable(t *testing.T) {
	h, _, st := newInviteTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	user, err := st.CreateUser("sam", "password123")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := st.CreateFullSession(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	auth := "Bearer " + sess.Token

	statusReq := httptest.NewRequest(http.MethodGet, "/api/totp", nil)
	statusReq.Header.Set("Authorization", auth)
	statusW := httptest.NewRecorder()
	mux.ServeHTTP(statusW, statusReq)
	if statusW.Code != http.StatusOK {
		t.Fatalf("status %d %s", statusW.Code, statusW.Body.String())
	}
	var before struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(statusW.Body.Bytes(), &before); err != nil || before.Enabled {
		t.Fatalf("before %#v %v", before, err)
	}

	enableReq := httptest.NewRequest(http.MethodPost, "/api/totp", nil)
	enableReq.Header.Set("Authorization", auth)
	enableW := httptest.NewRecorder()
	mux.ServeHTTP(enableW, enableReq)
	if enableW.Code != http.StatusOK {
		t.Fatalf("enable %d %s", enableW.Code, enableW.Body.String())
	}
	var enabled struct {
		Enabled   bool   `json:"enabled"`
		Secret    string `json:"secret"`
		QRCodeURL string `json:"qr_code_url"`
	}
	if err := json.Unmarshal(enableW.Body.Bytes(), &enabled); err != nil {
		t.Fatal(err)
	}
	if !enabled.Enabled || enabled.Secret == "" || !strings.Contains(enabled.QRCodeURL, "otpauth://totp/") {
		t.Fatalf("%#v", enabled)
	}

	code, err := totp.GenerateCode(enabled.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/totp/verify", strings.NewReader(`{"code":"`+code+`"}`))
	verifyReq.Header.Set("Authorization", auth)
	verifyW := httptest.NewRecorder()
	mux.ServeHTTP(verifyW, verifyReq)
	if verifyW.Code != http.StatusOK {
		t.Fatalf("verify %d %s", verifyW.Code, verifyW.Body.String())
	}

	badReq := httptest.NewRequest(http.MethodPost, "/api/totp/verify", strings.NewReader(`{"code":"000000"}`))
	badReq.Header.Set("Authorization", auth)
	badW := httptest.NewRecorder()
	mux.ServeHTTP(badW, badReq)
	if badW.Code != http.StatusBadRequest {
		t.Fatalf("bad verify %d %s", badW.Code, badW.Body.String())
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/api/totp", nil)
	delReq.Header.Set("Authorization", auth)
	delW := httptest.NewRecorder()
	mux.ServeHTTP(delW, delReq)
	if delW.Code != http.StatusOK {
		t.Fatalf("disable %d %s", delW.Code, delW.Body.String())
	}
	_, stillEnabled, _ := st.GetTOTPSecret(user.ID)
	if stillEnabled {
		t.Fatal("totp still enabled")
	}
}
