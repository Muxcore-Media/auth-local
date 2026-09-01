package server

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc/metadata"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"

	"github.com/Muxcore-Media/auth-local/internal/policy"
	"github.com/Muxcore-Media/auth-local/internal/store"
)

func newTestServer(t *testing.T) *AuthServer {
	t.Helper()
	s, err := store.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return New(s, policy.Builtin(), "localhost", []string{"http://localhost"}, "test")
}

func ctxWithSession(t *testing.T, srv *AuthServer, userID string) context.Context {
	t.Helper()
	sess, err := srv.store.CreateFullSession(userID)
	if err != nil {
		t.Fatalf("CreateFullSession: %v", err)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-auth-token", sess.Token))
}

func TestAuthenticate_Password(t *testing.T) {
	srv := newTestServer(t)
	_, _ = srv.store.CreateUser("alice", "password123")

	creds, _ := json.Marshal(map[string]string{
		"username": "alice",
		"password": "password123",
	})
	resp, err := srv.Authenticate(context.Background(), &authv1.AuthenticateRequest{
		CredentialType: "password",
		CredentialData: creds,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !resp.Authenticated {
		t.Fatalf("expected authenticated, got error: %s", resp.Error)
	}
	if resp.SessionToken == "" {
		t.Fatal("expected non-empty session token")
	}
}

func TestAuthenticate_WrongPassword(t *testing.T) {
	srv := newTestServer(t)
	_, _ = srv.store.CreateUser("alice", "correct")

	creds, _ := json.Marshal(map[string]string{
		"username": "alice",
		"password": "wrong",
	})
	resp, err := srv.Authenticate(context.Background(), &authv1.AuthenticateRequest{
		CredentialType: "password",
		CredentialData: creds,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.Authenticated {
		t.Fatal("expected authentication to fail")
	}
}

func TestValidate(t *testing.T) {
	srv := newTestServer(t)
	_, _ = srv.store.CreateUser("alice", "pw")
	user, _ := srv.store.GetUserByUsername("alice")
	sess, _ := srv.store.CreateFullSession(user.ID)

	resp, err := srv.Validate(context.Background(), &authv1.ValidateRequest{Token: sess.Token})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !resp.Valid {
		t.Fatalf("expected valid: %s", resp.Error)
	}
	if resp.Username != "alice" {
		t.Errorf("Username = %q, want %q", resp.Username, "alice")
	}
}

func TestValidate_Invalid(t *testing.T) {
	srv := newTestServer(t)
	resp, err := srv.Validate(context.Background(), &authv1.ValidateRequest{Token: "nonexistent"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if resp.Valid {
		t.Fatal("expected invalid")
	}
}

func TestRevoke(t *testing.T) {
	srv := newTestServer(t)
	_, _ = srv.store.CreateUser("alice", "pw")
	user, _ := srv.store.GetUserByUsername("alice")
	sess, _ := srv.store.CreateFullSession(user.ID)

	_, _ = srv.Revoke(context.Background(), &authv1.RevokeRequest{Token: sess.Token})
	resp, _ := srv.Validate(context.Background(), &authv1.ValidateRequest{Token: sess.Token})
	if resp.Valid {
		t.Fatal("expected session to be revoked")
	}
}

func TestCan(t *testing.T) {
	srv := newTestServer(t)
	_, _ = srv.store.CreateUser("alice", "pw")
	user, _ := srv.store.GetUserByUsername("alice")
	_ = srv.store.SetRoles(user.ID, []string{"admin"})

	resp, err := srv.Can(context.Background(), &authv1.CanRequest{
		UserId:   user.ID,
		Action:   "delete",
		Resource: "anything",
	})
	if err != nil {
		t.Fatalf("Can: %v", err)
	}
	if !resp.Allowed {
		t.Fatal("expected admin to have permission")
	}

	_ = srv.store.SetRoles(user.ID, []string{"viewer"})
	resp2, _ := srv.Can(context.Background(), &authv1.CanRequest{
		UserId:   user.ID,
		Action:   "delete",
		Resource: "media",
	})
	if resp2.Allowed {
		t.Fatal("expected viewer to be denied delete")
	}
}

func TestExtractIdentity(t *testing.T) {
	srv := newTestServer(t)
	_, _ = srv.store.CreateUser("alice", "pw")
	user, _ := srv.store.GetUserByUsername("alice")
	sess, _ := srv.store.CreateFullSession(user.ID)

	resp, err := srv.ExtractIdentity(context.Background(), &authv1.ExtractIdentityRequest{Token: sess.Token})
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}
	if !resp.Found {
		t.Fatal("expected identity found")
	}
	if resp.Kind != "user" {
		t.Errorf("Kind = %q, want %q", resp.Kind, "user")
	}

	// Module identity.
	resp2, _ := srv.ExtractIdentity(context.Background(), &authv1.ExtractIdentityRequest{CallerId: "downloader"})
	if !resp2.Found {
		t.Fatal("expected module identity found")
	}
}

func TestExtractIdentity_NoToken(t *testing.T) {
	srv := newTestServer(t)
	resp, err := srv.ExtractIdentity(context.Background(), &authv1.ExtractIdentityRequest{})
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}
	if resp.Found {
		t.Fatal("expected no identity for empty request")
	}
}

// --- TOTP Tests ---

func TestEnableTOTP(t *testing.T) {
	srv := newTestServer(t)
	user, _ := srv.store.CreateUser("alice", "pw")
	ctx := ctxWithSession(t, srv, user.ID)

	resp, err := srv.EnableTOTP(ctx, &authv1.EnableTOTPRequest{UserId: user.ID})
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	if resp.Secret == "" {
		t.Fatal("expected non-empty TOTP secret")
	}
	if resp.QrCodeUrl == "" {
		t.Fatal("expected non-empty QR code URL")
	}

	// TOTP is pending until VerifyTOTPSetup — not required at login yet.
	status, _ := srv.TOTPStatus(context.Background(), &authv1.TOTPStatusRequest{UserId: user.ID})
	if status.Enabled {
		t.Fatal("expected TOTP pending until verified")
	}
}

func TestTOTP_LoginFlow(t *testing.T) {
	srv := newTestServer(t)
	user, _ := srv.store.CreateUser("alice", "pw")
	ctx := ctxWithSession(t, srv, user.ID)

	enableResp, _ := srv.EnableTOTP(ctx, &authv1.EnableTOTPRequest{UserId: user.ID})
	secret := enableResp.Secret

	realCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	verifyResp, err := srv.VerifyTOTPSetup(ctx, &authv1.VerifyTOTPSetupRequest{
		UserId:   user.ID,
		TotpCode: realCode,
	})
	if err != nil || !verifyResp.Verified {
		t.Fatalf("VerifyTOTPSetup: err=%v resp=%+v", err, verifyResp)
	}

	// Login with password — should get partial token (TOTP requires 2FA).
	creds, _ := json.Marshal(map[string]string{"username": "alice", "password": "pw"})
	loginResp, err := srv.Authenticate(context.Background(), &authv1.AuthenticateRequest{
		CredentialType: "password",
		CredentialData: creds,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if loginResp.Authenticated {
		t.Fatal("expected not authenticated (TOTP required)")
	}
	if !loginResp.Requires_2Fa {
		t.Fatal("expected requires_2fa = true")
	}
	if loginResp.PartialToken == "" {
		t.Fatal("expected non-empty partial token")
	}

	// Complete with a valid TOTP code.
	realCode, err = totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	totpCreds, _ := json.Marshal(map[string]string{
		"partial_token": loginResp.PartialToken,
		"totp_code":     realCode,
	})
	finalResp, err := srv.Authenticate(context.Background(), &authv1.AuthenticateRequest{
		CredentialType: "totp",
		CredentialData: totpCreds,
	})
	if err != nil {
		t.Fatalf("TOTP Authenticate: %v", err)
	}
	if !finalResp.Authenticated {
		t.Fatalf("expected authenticated after TOTP: %s", finalResp.Error)
	}
	if finalResp.SessionToken == "" {
		t.Fatal("expected non-empty session token")
	}
	if finalResp.Username != "alice" {
		t.Errorf("Username = %q, want %q", finalResp.Username, "alice")
	}
}

func TestTOTP_InvalidCode(t *testing.T) {
	srv := newTestServer(t)
	user, _ := srv.store.CreateUser("alice", "pw")
	ctx := ctxWithSession(t, srv, user.ID)
	enableResp, _ := srv.EnableTOTP(ctx, &authv1.EnableTOTPRequest{UserId: user.ID})
	code, _ := totp.GenerateCode(enableResp.Secret, time.Now())
	_, _ = srv.VerifyTOTPSetup(ctx, &authv1.VerifyTOTPSetupRequest{UserId: user.ID, TotpCode: code})

	// Login to get partial token.
	creds, _ := json.Marshal(map[string]string{"username": "alice", "password": "pw"})
	loginResp, _ := srv.Authenticate(context.Background(), &authv1.AuthenticateRequest{
		CredentialType: "password",
		CredentialData: creds,
	})

	// Try with wrong code.
	totpCreds, _ := json.Marshal(map[string]string{
		"partial_token": loginResp.PartialToken,
		"totp_code":     "000000",
	})
	resp, err := srv.Authenticate(context.Background(), &authv1.AuthenticateRequest{
		CredentialType: "totp",
		CredentialData: totpCreds,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.Authenticated {
		t.Fatal("expected authentication to fail with wrong TOTP code")
	}
}

func TestDisableTOTP(t *testing.T) {
	srv := newTestServer(t)
	user, _ := srv.store.CreateUser("alice", "pw")
	ctx := ctxWithSession(t, srv, user.ID)
	enableResp, _ := srv.EnableTOTP(ctx, &authv1.EnableTOTPRequest{UserId: user.ID})
	code, _ := totp.GenerateCode(enableResp.Secret, time.Now())
	_, _ = srv.VerifyTOTPSetup(ctx, &authv1.VerifyTOTPSetupRequest{UserId: user.ID, TotpCode: code})

	status, _ := srv.TOTPStatus(context.Background(), &authv1.TOTPStatusRequest{UserId: user.ID})
	if !status.Enabled {
		t.Fatal("expected TOTP enabled before disable")
	}

	_, _ = srv.DisableTOTP(ctx, &authv1.DisableTOTPRequest{UserId: user.ID})

	status, _ = srv.TOTPStatus(context.Background(), &authv1.TOTPStatusRequest{UserId: user.ID})
	if status.Enabled {
		t.Fatal("expected TOTP disabled after disable")
	}
}

func TestCreateUser_FirstUserIsAdmin(t *testing.T) {
	srv := newTestServer(t)
	resp, err := srv.CreateUser(context.Background(), &authv1.CreateUserRequest{
		Username: "bootstrap",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("CreateUser error: %s", resp.Error)
	}
	user, err := srv.store.GetUser(resp.UserId)
	if err != nil {
		t.Fatal(err)
	}
	if len(user.Roles) != 1 || user.Roles[0] != "admin" {
		t.Fatalf("first user roles = %v, want [admin]", user.Roles)
	}
}
