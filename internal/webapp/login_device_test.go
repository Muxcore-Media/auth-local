package webapp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc/metadata"

	"github.com/Muxcore-Media/auth-local/internal/policy"
	"github.com/Muxcore-Media/auth-local/internal/server"
	authStore "github.com/Muxcore-Media/auth-local/internal/store"
	"github.com/Muxcore-Media/auth-local/internal/webapp"
	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"
)

func TestDeviceLoginTOTPFlow(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "auth.db")
	store, err := authStore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	user, err := store.CreateUser("totp-user", "secret")
	if err != nil {
		t.Fatal(err)
	}

	srv := server.New(store, policy.Builtin(), "localhost", []string{"http://localhost"}, "test")
	sess, err := store.CreateFullSession(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-auth-token", sess.Token))
	enable, err := srv.EnableTOTP(ctx, &authv1.EnableTOTPRequest{UserId: user.ID})
	if err != nil || enable.GetError() != "" {
		t.Fatalf("EnableTOTP: %v %+v", err, enable)
	}
	code, err := totp.GenerateCode(enable.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verify, err := srv.VerifyTOTPSetup(ctx, &authv1.VerifyTOTPSetupRequest{UserId: user.ID, TotpCode: code})
	if err != nil || !verify.Verified {
		t.Fatalf("VerifyTOTPSetup: %v %+v", err, verify)
	}

	h := webapp.New(store, "http://127.0.0.1:9401", nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Password step returns partial token.
	body, _ := json.Marshal(map[string]string{"username": "totp-user", "password": "secret"})
	req := httptest.NewRequest(http.MethodPost, "/login/device", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("device login status %d: %s", rec.Code, rec.Body.String())
	}
	var step1 struct {
		Requires2FA  bool   `json:"requires_2fa"`
		PartialToken string `json:"partial_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &step1); err != nil {
		t.Fatal(err)
	}
	if !step1.Requires2FA || step1.PartialToken == "" {
		t.Fatalf("expected partial 2fa: %+v", step1)
	}

	secret, enabled, err := store.GetTOTPSecret(user.ID)
	if err != nil || !enabled {
		t.Fatalf("totp not login-ready: err=%v enabled=%v secret=%q", err, enabled, secret)
	}
	code, err = totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	body2, _ := json.Marshal(map[string]string{"partial_token": step1.PartialToken, "totp_code": code})
	req2 := httptest.NewRequest(http.MethodPost, "/login/device/totp", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	req2.RemoteAddr = "127.0.0.1:12345"
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("device totp status %d: %s", rec2.Code, rec2.Body.String())
	}
	var step2 struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &step2); err != nil {
		t.Fatal(err)
	}
	if step2.Token == "" {
		t.Fatal("expected session token")
	}
}
