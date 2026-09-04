package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestCreateUser(t *testing.T) {
	s := newTestStore(t)
	user, err := s.CreateUser("alice", "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.Username != "alice" {
		t.Errorf("Username = %q, want %q", user.Username, "alice")
	}
	if user.ID == "" {
		t.Fatal("expected non-empty ID")
	}
}

func TestCreateUser_Duplicate(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.CreateUser("alice", "pw1")
	_, err := s.CreateUser("alice", "pw2")
	if err == nil {
		t.Fatal("expected error for duplicate username")
	}
}

func TestCreateUser_EmptyFields(t *testing.T) {
	s := newTestStore(t)
	_, err := s.CreateUser("", "pw")
	if err == nil {
		t.Fatal("expected error for empty username")
	}
	_, err = s.CreateUser("bob", "")
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestGetUserByUsername(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.CreateUser("alice", "pw")
	user, err := s.GetUserByUsername("alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if user.Username != "alice" {
		t.Errorf("Username = %q, want %q", user.Username, "alice")
	}
	if user.Password == "" {
		t.Error("expected non-empty password hash")
	}
	if len(user.Roles) == 0 {
		t.Error("expected non-empty roles")
	}

	_, err = s.GetUserByUsername("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestGetUser(t *testing.T) {
	s := newTestStore(t)
	created, _ := s.CreateUser("alice", "pw")
	fetched, err := s.GetUser(created.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if fetched.Username != "alice" {
		t.Errorf("Username = %q, want %q", fetched.Username, "alice")
	}
}

func TestListUsers(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.CreateUser("alice", "pw1")
	_, _ = s.CreateUser("bob", "pw2")
	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}
}

func TestDeleteUser(t *testing.T) {
	s := newTestStore(t)
	user, _ := s.CreateUser("alice", "pw")
	if err := s.DeleteUser(user.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	_, err := s.GetUser(user.ID)
	if err == nil {
		t.Fatal("expected error after delete")
	}

	if err := s.DeleteUser("nonexistent"); err == nil {
		t.Fatal("expected error deleting nonexistent user")
	}
}

func TestSetPassword(t *testing.T) {
	s := newTestStore(t)
	user, _ := s.CreateUser("alice", "pw1")
	_ = s.SetPassword(user.ID, "pw2")

	// Verify old password fails, new works.
	_, err := s.VerifyPassword("alice", "pw1")
	if err == nil {
		t.Fatal("expected old password to fail")
	}
	_, err = s.VerifyPassword("alice", "pw2")
	if err != nil {
		t.Fatalf("VerifyPassword with new password: %v", err)
	}
}

func TestVerifyPassword(t *testing.T) {
	s := newTestStore(t)
	_, _ = s.CreateUser("alice", "correct-horse-battery-staple")

	_, err := s.VerifyPassword("alice", "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}

	_, err = s.VerifyPassword("alice", "wrong")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}

	_, err = s.VerifyPassword("nonexistent", "pw")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestSessions(t *testing.T) {
	s := newTestStore(t)
	user, _ := s.CreateUser("alice", "pw")

	// Full session.
	sess, err := s.CreateFullSession(user.ID)
	if err != nil {
		t.Fatalf("CreateFullSession: %v", err)
	}
	if sess.Kind != "full" {
		t.Errorf("Kind = %q, want %q", sess.Kind, "full")
	}
	if sess.Token == "" {
		t.Fatal("expected non-empty token")
	}

	// Get and validate.
	got, err := s.GetSession(sess.Token)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.UserID != user.ID {
		t.Errorf("UserID = %q, want %q", got.UserID, user.ID)
	}

	// Delete.
	_ = s.DeleteSession(sess.Token)
	_, err = s.GetSession(sess.Token)
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestPartialSession(t *testing.T) {
	s := newTestStore(t)
	user, _ := s.CreateUser("alice", "pw")

	sess, err := s.CreatePartialSession(user.ID)
	if err != nil {
		t.Fatalf("CreatePartialSession: %v", err)
	}
	if sess.Kind != "partial" {
		t.Errorf("Kind = %q, want %q", sess.Kind, "partial")
	}

	// Upgrade.
	full, err := s.UpgradeSession(sess.Token)
	if err != nil {
		t.Fatalf("UpgradeSession: %v", err)
	}
	if full.Kind != "full" {
		t.Errorf("Upgrade Kind = %q, want %q", full.Kind, "full")
	}

	// Original partial token should be dead.
	_, err = s.GetSession(sess.Token)
	if err == nil {
		t.Fatal("expected partial token to be deleted after upgrade")
	}
}

func TestUpgradeSession_Invalid(t *testing.T) {
	s := newTestStore(t)
	user, _ := s.CreateUser("alice", "pw")
	full, _ := s.CreateFullSession(user.ID)

	// Trying to upgrade a full session should fail.
	_, err := s.UpgradeSession(full.Token)
	if err == nil {
		t.Fatal("expected error upgrading full session")
	}
}

func TestCleanup(t *testing.T) {
	// Use a file-based DB to test cleanup against real timestamps.
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()

	user, _ := s.CreateUser("alice", "pw")
	// Create a session directly with an expired timestamp.
	_, _ = s.db.Exec(`INSERT INTO sessions (token, user_id, kind, expires_at) VALUES (?, ?, 'full', '2020-01-01T00:00:00Z')`,
		"expired-token", user.ID)

	if err := s.CleanupExpiredSessions(); err != nil {
		t.Fatalf("CleanupExpiredSessions: %v", err)
	}
	_, err = s.GetSession("expired-token")
	if err == nil {
		t.Fatal("expected expired session to be deleted after cleanup")
	}
}

func TestSetRoles(t *testing.T) {
	s := newTestStore(t)
	user, _ := s.CreateUser("alice", "pw")
	_ = s.SetRoles(user.ID, []string{"admin", "manager"})
	updated, _ := s.GetUser(user.ID)
	if len(updated.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(updated.Roles))
	}
}

func TestDeleteUserSessions(t *testing.T) {
	s := newTestStore(t)
	user, _ := s.CreateUser("alice", "pw")
	_, _ = s.CreateFullSession(user.ID)
	_, _ = s.CreateFullSession(user.ID)
	_ = s.DeleteUserSessions(user.ID)
	users, _ := s.ListUsers()
	if len(users) != 1 {
		t.Errorf("expected user to still exist, got %d users", len(users))
	}
}

func TestPing(t *testing.T) {
	s := newTestStore(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("expected Ping to fail after Close")
	}
}

func init() {
	// Ensure SQLite temp files go to the test temp dir.
	_ = os.Setenv("SQLITE_TMPDIR", os.TempDir())
}
