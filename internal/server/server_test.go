package server

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"

	"github.com/Muxcore-Media/auth-local/internal/store"
)

func newTestServer(t *testing.T) *AuthServer {
	t.Helper()
	s, err := store.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return New(s)
}

func TestAuthenticate_Password(t *testing.T) {
	srv := newTestServer(t)
	// Create user directly.
	srv.store.CreateUser("alice", "password123")

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
	srv.store.CreateUser("alice", "correct")

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
	srv.store.CreateUser("alice", "pw")
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
	srv.store.CreateUser("alice", "pw")
	user, _ := srv.store.GetUserByUsername("alice")
	sess, _ := srv.store.CreateFullSession(user.ID)

	srv.Revoke(context.Background(), &authv1.RevokeRequest{Token: sess.Token})

	resp, _ := srv.Validate(context.Background(), &authv1.ValidateRequest{Token: sess.Token})
	if resp.Valid {
		t.Fatal("expected session to be revoked")
	}
}

func TestCan(t *testing.T) {
	srv := newTestServer(t)
	srv.store.CreateUser("alice", "pw")
	user, _ := srv.store.GetUserByUsername("alice")
	srv.store.SetRoles(user.ID, []string{"admin"})

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

	srv.store.SetRoles(user.ID, []string{"viewer"})
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
	srv.store.CreateUser("alice", "pw")
	user, _ := srv.store.GetUserByUsername("alice")
	sess, _ := srv.store.CreateFullSession(user.ID)

	resp, err := srv.ExtractIdentity(context.Background(), &authv1.ExtractIdentityRequest{
		Token: sess.Token,
	})
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
	resp2, _ := srv.ExtractIdentity(context.Background(), &authv1.ExtractIdentityRequest{
		CallerId: "downloader-qbittorrent",
	})
	if !resp2.Found {
		t.Fatal("expected module identity found")
	}
	if resp2.Kind != "service" {
		t.Errorf("Kind = %q, want %q", resp2.Kind, "service")
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
