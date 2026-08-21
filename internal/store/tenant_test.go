package store

import (
	"testing"
	"time"
)

func TestInviteTenantPropagatesToUser(t *testing.T) {
	s := newTestStore(t)
	inv, err := s.CreateInvite("admin", "user", "household-a", 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if inv.TenantID != "household-a" {
		t.Fatalf("invite tenant=%q", inv.TenantID)
	}
	user, _, err := s.RedeemInvite(inv.Token, "alice", "password123")
	if err != nil {
		t.Fatal(err)
	}
	if user.TenantID != "household-a" {
		t.Fatalf("user tenant=%q", user.TenantID)
	}
	got, err := s.GetUser(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TenantID != "household-a" {
		t.Fatalf("persisted tenant=%q", got.TenantID)
	}
	claims := got.Claims()
	if claims["tenant_id"] != "household-a" {
		t.Fatalf("claims=%v", claims)
	}
}

func TestCreateUserTenant(t *testing.T) {
	s := newTestStore(t)
	u, err := s.CreateUserTenant("bob", "password123", "org-x")
	if err != nil {
		t.Fatal(err)
	}
	if u.TenantID != "org-x" {
		t.Fatalf("tenant=%q", u.TenantID)
	}
}
