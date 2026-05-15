package auth_test

import (
	"context"
	"testing"

	"github.com/Muxcore-Media/core/internal/auth"
)

func TestCreateAccountAndAuthenticate(t *testing.T) {
	mod := auth.NewModule()
	ctx := context.Background()

	account, err := mod.CreateAccount(ctx, "testuser", "hunter2", []string{"admin"})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	if account.Username != "testuser" {
		t.Fatalf("expected testuser, got %s", account.Username)
	}

	session, err := mod.Authenticate(ctx, auth.Credentials{
		Username: "testuser",
		Password: "hunter2",
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if session.Username != "testuser" {
		t.Fatalf("expected testuser session, got %s", session.Username)
	}
}

func TestAuthenticateWrongPassword(t *testing.T) {
	mod := auth.NewModule()
	ctx := context.Background()

	_, err := mod.CreateAccount(ctx, "testuser", "hunter2", nil)
	if err != nil {
		t.Fatalf("create account: %v", err)
	}

	_, err = mod.Authenticate(ctx, auth.Credentials{
		Username: "testuser",
		Password: "wrongpassword",
	})
	if err == nil {
		t.Fatal("expected authentication error")
	}
}

func TestAPITokenAuth(t *testing.T) {
	mod := auth.NewModule()
	ctx := context.Background()

	_, err := mod.CreateAccount(ctx, "testuser", "hunter2", nil)
	if err != nil {
		t.Fatalf("create account: %v", err)
	}

	tok, err := mod.CreateAPIToken(ctx, "testuser", "test-token")
	if err != nil {
		t.Fatalf("create api token: %v", err)
	}
	if tok.Token == "" {
		t.Fatal("expected token value")
	}

	session, err := mod.Authenticate(ctx, auth.Credentials{Token: tok.Token})
	if err != nil {
		t.Fatalf("authenticate with token: %v", err)
	}
	if session.Username != "testuser" {
		t.Fatalf("expected testuser session, got %s", session.Username)
	}
}

func TestRevokeToken(t *testing.T) {
	mod := auth.NewModule()
	ctx := context.Background()

	_, err := mod.CreateAccount(ctx, "testuser", "hunter2", nil)
	if err != nil {
		t.Fatalf("create account: %v", err)
	}

	tok, err := mod.CreateAPIToken(ctx, "testuser", "test-token")
	if err != nil {
		t.Fatalf("create api token: %v", err)
	}

	if err := mod.Revoke(ctx, tok.Token); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	_, err = mod.Authenticate(ctx, auth.Credentials{Token: tok.Token})
	if err == nil {
		t.Fatal("expected error after revoke")
	}
}
