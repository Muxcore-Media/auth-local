package store

import (
	"path/filepath"
	"testing"
)

func TestBootstrapAdminFromEnv_CreatesAdminOnEmptyDB(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_USER", "bootstrap-admin")
	t.Setenv("AUTH_BOOTSTRAP_PASSWORD", "bootstrap-secret")

	s, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := BootstrapAdminFromEnv(s); err != nil {
		t.Fatalf("BootstrapAdminFromEnv: %v", err)
	}

	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("user count = %d, want 1", len(users))
	}
	if users[0].Username != "bootstrap-admin" {
		t.Fatalf("username = %q, want bootstrap-admin", users[0].Username)
	}
	if len(users[0].Roles) != 1 || users[0].Roles[0] != "admin" {
		t.Fatalf("roles = %v, want [admin]", users[0].Roles)
	}

	if _, err := s.VerifyPassword("bootstrap-admin", "bootstrap-secret"); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
}

func TestBootstrapAdminFromEnv_SkipsWhenUsersExist(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	s1, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Setenv("AUTH_BOOTSTRAP_USER", "bootstrap-admin")
	t.Setenv("AUTH_BOOTSTRAP_PASSWORD", "bootstrap-secret")
	if err := BootstrapAdminFromEnv(s1); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	_ = s1.Close()

	s2, err := New(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	t.Setenv("AUTH_BOOTSTRAP_USER", "other-admin")
	t.Setenv("AUTH_BOOTSTRAP_PASSWORD", "other-secret")
	if err := BootstrapAdminFromEnv(s2); err != nil {
		t.Fatalf("second bootstrap: %v", err)
	}

	users, err := s2.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("user count = %d, want 1", len(users))
	}
	if users[0].Username != "bootstrap-admin" {
		t.Fatalf("username = %q, want bootstrap-admin (unchanged)", users[0].Username)
	}
}

func TestBootstrapAdminFromEnv_SkipsWhenPartialEnv(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_USER", "bootstrap-admin")

	s, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := BootstrapAdminFromEnv(s); err != nil {
		t.Fatalf("BootstrapAdminFromEnv: %v", err)
	}

	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("user count = %d, want 0", len(users))
	}
}

func TestBootstrapAdminFromEnv_IdempotentOnRestart(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	t.Setenv("AUTH_BOOTSTRAP_USER", "bootstrap-admin")
	t.Setenv("AUTH_BOOTSTRAP_PASSWORD", "bootstrap-secret")

	for i := 0; i < 2; i++ {
		s, err := New(dbPath)
		if err != nil {
			t.Fatalf("New #%d: %v", i+1, err)
		}
		if err := BootstrapAdminFromEnv(s); err != nil {
			t.Fatalf("bootstrap #%d: %v", i+1, err)
		}
		_ = s.Close()
	}

	s, err := New(dbPath)
	if err != nil {
		t.Fatalf("final New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("user count = %d, want 1", len(users))
	}
}
