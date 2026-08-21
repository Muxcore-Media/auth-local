package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestInviteCreateRedeem(t *testing.T) {
	s := newTestStore(t)
	inv, err := s.CreateInvite("admin", "user", "", 1, time.Hour)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if inv.Token == "" || inv.ID == "" {
		t.Fatalf("missing token/id: %+v", inv)
	}
	user, _, err := s.RedeemInvite(inv.Token, "newbie", "password123")
	if err != nil {
		t.Fatalf("RedeemInvite: %v", err)
	}
	if user.Username != "newbie" || len(user.Roles) != 1 || user.Roles[0] != "user" {
		t.Fatalf("user=%+v", user)
	}
	_, _, err = s.RedeemInvite(inv.Token, "other", "password123")
	if err == nil {
		t.Fatal("expected single-use exhaust")
	}
}

func TestInviteExpire(t *testing.T) {
	s := newTestStore(t)
	inv, err := s.CreateInvite("admin", "user", "", 1, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	_, _, err = s.RedeemInvite(inv.Token, "late", "pw")
	if err == nil {
		t.Fatal("expected expired")
	}
}

func TestInviteRevoke(t *testing.T) {
	s := newTestStore(t)
	inv, err := s.CreateInvite("admin", "manager", "", 5, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeInvite(inv.ID); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.RedeemInvite(inv.Token, "x", "pw")
	if err == nil {
		t.Fatal("expected revoked")
	}
	list, err := s.ListInvites()
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%v err=%v", list, err)
	}
	if list[0].RevokedAt.IsZero() {
		t.Fatal("expected revoked_at set")
	}
}

func TestInviteMaxUses(t *testing.T) {
	s := newTestStore(t)
	inv, err := s.CreateInvite("admin", "user", "", 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RedeemInvite(inv.Token, "a", "pw1pw1pw1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RedeemInvite(inv.Token, "b", "pw1pw1pw1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RedeemInvite(inv.Token, "c", "pw1pw1pw1"); err == nil {
		t.Fatal("expected exhausted")
	}
}

func TestInviteRole(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	inv, err := s.CreateInvite("admin", "viewer", "", 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	user, _, err := s.RedeemInvite(inv.Token, "v", "password123")
	if err != nil {
		t.Fatal(err)
	}
	if user.Roles[0] != "viewer" {
		t.Fatalf("role=%v", user.Roles)
	}
}
