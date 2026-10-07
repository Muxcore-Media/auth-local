package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestValidateSessionCurrentClaimsWithoutSecrets(t *testing.T) {
	s := newSessionManagementStore(t)
	seedSessionUser(t, s, "owner")
	for _, kind := range []string{"full", "api-token"} {
		seedManagedSession(t, s, kind, "owner", kind, "2025-01-01 00:00:00", "2099-01-01T03:00:00+03:00")
	}
	// Unrelated secret corruption must not turn bearer validation into an outage.
	if _, err := s.db.Exec(`UPDATE users SET totp_secret = 'v1:unreadable', totp_enabled = 1 WHERE id = 'owner'`); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		username, roles, tenant string
		wantRoles               []string
	}{
		{"renamed", `["admin","user"]`, "household-2", []string{"admin", "user"}},
		{"renamed-again", `[]`, "", []string{}},
	} {
		if _, err := s.db.Exec(`UPDATE users SET username = ?, roles = ?, tenant_id = ? WHERE id = 'owner'`, want.username, want.roles, want.tenant); err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"full", "api-token"} {
			identity, err := s.ValidateSession(context.Background(), "bearer-"+kind)
			if err != nil {
				t.Fatal(err)
			}
			if identity.UserID != "owner" || identity.Username != want.username || identity.TenantID != want.tenant || !reflect.DeepEqual(identity.Roles, want.wantRoles) {
				t.Fatalf("current identity = %+v", identity)
			}
		}
	}
}

func TestValidateSessionDefinitiveInvalidAndExpiryCleanup(t *testing.T) {
	s := newSessionManagementStore(t)
	seedSessionUser(t, s, "owner")
	for _, row := range []struct{ id, owner, kind, expires string }{
		{"active", "owner", "full", "2099-01-01T00:00:00Z"},
		{"revoked", "owner", "full", "2099-01-01T00:00:00Z"},
		{"expired-rfc", "owner", "full", "2020-01-01T03:00:00+03:00"},
		{"expired-sqlite", "owner", "full", "2020-01-01 00:00:00"},
		{"partial", "owner", "partial", "2099-01-01T00:00:00Z"},
		{"unknown-kind", "owner", "pending", "2099-01-01T00:00:00Z"},
		{"orphan", "removed-user", "full", "2099-01-01T00:00:00Z"},
	} {
		seedManagedSession(t, s, row.id, row.owner, row.kind, "2019-01-01 00:00:00", row.expires)
	}
	if err := s.RevokeSession(context.Background(), "owner", "revoked"); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", "unknown", "bearer-revoked", "bearer-expired-rfc", "bearer-expired-sqlite", "bearer-partial", "bearer-unknown-kind", "bearer-orphan"} {
		if identity, err := s.ValidateSession(context.Background(), token); identity != nil || !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("invalid token %q = %+v, %v", token, identity, err)
		}
	}
	var expired int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE session_id IN ('expired-rfc', 'expired-sqlite')`).Scan(&expired); err != nil || expired != 0 {
		t.Fatalf("expired rows not cleaned up: %d, %v", expired, err)
	}
	var retained int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE session_id IN ('active', 'partial', 'unknown-kind', 'orphan')`).Scan(&retained); err != nil || retained != 4 {
		t.Fatalf("unrelated rows removed: %d, %v", retained, err)
	}
	if _, err := s.ValidateSession(context.Background(), "bearer-active"); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSessionOperationalFailuresDoNotDelete(t *testing.T) {
	for _, tc := range []struct{ name, mutate string }{
		{"roles-json", `UPDATE users SET roles = 'invalid-json' WHERE id = 'owner'`},
		{"roles-type", `UPDATE users SET roles = '{"admin":true}' WHERE id = 'owner'`},
		{"expiry", `UPDATE sessions SET expires_at = 'corrupt-sensitive-value' WHERE session_id = 'target'`},
		{"empty-user-id", `UPDATE users SET id = ''; UPDATE sessions SET user_id = ''`},
		{"query", `ALTER TABLE users RENAME TO unavailable_users`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSessionManagementStore(t)
			seedSessionUser(t, s, "owner")
			seedManagedSession(t, s, "target", "owner", "full", "2025-01-01 00:00:00", "2099-01-01T00:00:00Z")
			if _, err := s.db.Exec(tc.mutate); err != nil {
				t.Fatal(err)
			}
			if identity, err := s.ValidateSession(context.Background(), "bearer-target"); identity != nil || err == nil || errors.Is(err, ErrInvalidSession) {
				t.Fatalf("operational error classified as invalid: %+v, %v", identity, err)
			}
			var count int
			if err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token = ?`, hashSessionToken("bearer-target")).Scan(&count); err != nil || count != 1 {
				t.Fatalf("failed validation removed row: %d, %v", count, err)
			}
		})
	}
	t.Run("closed-database", func(t *testing.T) {
		s := newSessionManagementStore(t)
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ValidateSession(context.Background(), "bearer"); err == nil || errors.Is(err, ErrInvalidSession) {
			t.Fatalf("closed database classified as invalid: %v", err)
		}
	})
}

func TestValidateSessionContextAndBestEffortCleanup(t *testing.T) {
	s := newSessionManagementStore(t)
	seedSessionUser(t, s, "owner")
	seedManagedSession(t, s, "target", "owner", "full", "2025-01-01 00:00:00", "2099-01-01T00:00:00Z")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, deadlineCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer deadlineCancel()
	for _, tc := range []struct {
		ctx  context.Context
		want error
	}{{canceled, context.Canceled}, {deadline, context.DeadlineExceeded}} {
		if _, err := s.ValidateSession(tc.ctx, "bearer-target"); !errors.Is(err, tc.want) {
			t.Fatalf("context error = %v, want %v", err, tc.want)
		}
	}
	if _, err := s.ValidateSession(context.Background(), "bearer-target"); err != nil {
		t.Fatal("context failure changed the session")
	}
	seedManagedSession(t, s, "expired", "owner", "full", "2019-01-01 00:00:00", "2020-01-01T00:00:00Z")
	if _, err := s.db.Exec(`CREATE TRIGGER deny_cleanup BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, 'fixture cleanup failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateSession(context.Background(), "bearer-expired"); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("failed maintenance hid definitive expiry: %v", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("unexpected deletion after failed cleanup: %d, %v", count, err)
	}
}
