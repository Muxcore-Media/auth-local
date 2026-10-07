package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func newSessionManagementStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewWithKey(filepath.Join(t.TempDir(), "sessions.db"), testKey('s'))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedSessionUser(t *testing.T, s *Store, userID string) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO users (id, username, password, roles) VALUES (?, ?, 'unused', '["user"]')`, userID, userID); err != nil {
		t.Fatal(err)
	}
}

func seedManagedSession(t *testing.T, s *Store, id, userID, kind, created, expires string) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO sessions (token, session_id, user_id, kind, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, hashSessionToken("bearer-"+id), id, userID, kind, created, expires); err != nil {
		t.Fatal(err)
	}
}

func managedIDs(entries []ActiveSession) []string {
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.ID)
	}
	return ids
}

func TestSessionManagementMigrationLegacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE sessions (
		token TEXT PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT (datetime('now')), expires_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"legacy-plaintext", hashSessionToken("existing-hashed")} {
		if _, err := db.Exec(`INSERT INTO sessions VALUES (?, 'owner', 'full', '2025-01-02 03:04:05', '2099-01-01T03:00:00+03:00')`, token); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for attempt := 0; attempt < 2; attempt++ {
		s, err := NewWithKey(path, testKey('s'))
		if err != nil {
			t.Fatal(err)
		}
		for _, bearer := range []string{"legacy-plaintext", "existing-hashed"} {
			var id, stored, created, expiry string
			if err := s.db.QueryRow(`SELECT session_id, token, created_at, expires_at FROM sessions WHERE token = ?`, hashSessionToken(bearer)).Scan(&id, &stored, &created, &expiry); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(id, "sid_") || id == bearer || id == stored || stored != hashSessionToken(bearer) {
				t.Fatalf("management ID or bearer preservation failed: %q / %q", id, stored)
			}
			if created != "2025-01-02 03:04:05" || expiry != "2099-01-01T03:00:00+03:00" {
				t.Fatal("migration rewrote timestamps")
			}
			if attempt == 0 {
				ids[bearer] = id
			} else if ids[bearer] != id {
				t.Fatal("ID changed after reopen")
			}
			if _, err := s.GetSession(bearer); err != nil {
				t.Fatalf("bearer invalid after migration: %v", err)
			}
			if _, err := s.GetSession(id); err == nil {
				t.Fatal("management ID authenticated")
			}
		}
		if ids["legacy-plaintext"] == ids["existing-hashed"] {
			t.Fatal("duplicate IDs")
		}
		if _, err := s.db.Exec(`UPDATE sessions SET session_id = ? WHERE token = ?`, ids["legacy-plaintext"], hashSessionToken("existing-hashed")); err == nil {
			t.Fatal("unique index missing")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSessionManagementMigrationRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, query := range []string{
		`CREATE TABLE sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL)`,
		`INSERT INTO sessions VALUES ('legacy', 'owner', 'full', '2025-01-01 00:00:00', '2099-01-01T00:00:00Z')`,
		`CREATE TRIGGER reject_backfill BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT, 'fixture migration failure'); END`,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if s, err := NewWithKey(path, testKey('s')); err == nil {
		_ = s.Close()
		t.Fatal("migration should fail")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'session_id'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("column not rolled back: %d, %v", count, err)
	}
	var stored string
	if err := db.QueryRow(`SELECT token FROM sessions`).Scan(&stored); err != nil || stored != "legacy" {
		t.Fatalf("failed migration mutated bearer: %q, %v", stored, err)
	}
}

func TestSessionManagementCreationPathsAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	s, err := NewWithKey(path, testKey('s'))
	if err != nil {
		t.Fatal(err)
	}
	seedSessionUser(t, s, "owner")
	full, err := s.CreateFullSession("owner")
	if err != nil {
		t.Fatal(err)
	}
	partial, err := s.CreatePartialSession("owner")
	if err != nil {
		t.Fatal(err)
	}
	var partialID string
	if err := s.db.QueryRow(`SELECT session_id FROM sessions WHERE token = ?`, hashSessionToken(partial.Token)).Scan(&partialID); err != nil || partialID == "" {
		t.Fatalf("partial ID: %q, %v", partialID, err)
	}
	upgraded, err := s.UpgradeSession(partial.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(partial.Token); err == nil {
		t.Fatal("partial bearer survived upgrade")
	}
	key, _, err := s.CreateAPIToken("owner", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	api, err := s.ValidateAPIToken(key)
	if err != nil {
		t.Fatal(err)
	}
	entries, next, err := s.ListActiveSessions(context.Background(), "owner", 0, "")
	if err != nil || len(entries) != 3 || next != "" {
		t.Fatalf("list: %+v, %q, %v", entries, next, err)
	}
	bearerIDs := map[string]string{}
	for _, sess := range []*Session{full, upgraded, api} {
		var id string
		if err := s.db.QueryRow(`SELECT session_id FROM sessions WHERE token = ?`, hashSessionToken(sess.Token)).Scan(&id); err != nil || id == "" || id == partialID {
			t.Fatalf("created ID: %q, %v", id, err)
		}
		bearerIDs[sess.Token] = id
		if _, err := s.GetSession(id); err == nil {
			t.Fatal("management ID authenticated")
		}
	}
	serialized, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	for bearer := range bearerIDs {
		if strings.Contains(string(serialized), bearer) || strings.Contains(string(serialized), hashSessionToken(bearer)) {
			t.Fatal("management view contains credential material")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewWithKey(path, testKey('s'))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	for bearer, want := range bearerIDs {
		var id string
		if err := s.db.QueryRow(`SELECT session_id FROM sessions WHERE token = ?`, hashSessionToken(bearer)).Scan(&id); err != nil || id != want {
			t.Fatalf("reopened ID: %q, %v", id, err)
		}
		if _, err := s.GetSession(bearer); err != nil {
			t.Fatal(err)
		}
	}
}

func TestListActiveSessionsBoundsFiltersAndTimezones(t *testing.T) {
	s := newSessionManagementStore(t)
	seedSessionUser(t, s, "owner")
	seedSessionUser(t, s, "other")
	now := time.Now().UTC()
	future := now.Add(24 * time.Hour).Format(time.RFC3339)
	// These three creation strings denote the same instant: ID breaks the tie.
	seedManagedSession(t, s, "a", "owner", "full", "2025-01-01T03:00:00+03:00", future)
	seedManagedSession(t, s, "b", "owner", "api-token", "2025-01-01 00:00:00", future)
	seedManagedSession(t, s, "c", "other", "full", "2024-12-31T19:00:00-05:00", future)
	// Lexicographically future-looking expiration is actually in the past.
	seedManagedSession(t, s, "expired-offset", "owner", "full", "2025-01-01 00:00:00", now.Add(-time.Minute).In(time.FixedZone("east", 14*3600)).Format(time.RFC3339))
	seedManagedSession(t, s, "expired-today", "owner", "full", "2025-01-01 00:00:00", now.Add(-time.Minute).Format(time.RFC3339))
	seedManagedSession(t, s, "invalid-expiry", "owner", "full", "2025-01-01 00:00:00", "invalid")
	seedManagedSession(t, s, "partial", "owner", "partial", "2025-01-01 00:00:00", future)
	seedManagedSession(t, s, "unknown-kind", "owner", "device-pending", "2025-01-01 00:00:00", future)
	seedManagedSession(t, s, "orphan", "deleted-user", "full", "2025-01-01 00:00:00", future)
	// Lexicographically old-looking expiration is still active, in SQLite form.
	seedManagedSession(t, s, "d", "owner", "full", "2025-01-01T00:00:01Z", now.Add(time.Minute).In(time.FixedZone("west", -12*3600)).Format(time.RFC3339))
	seedManagedSession(t, s, "e", "owner", "full", "2025-01-01T00:00:02Z", now.Add(time.Minute).Format("2006-01-02 15:04:05"))
	entries, next, err := s.ListActiveSessions(context.Background(), "", 0, "")
	if err != nil || next != "" || !reflect.DeepEqual(managedIDs(entries), []string{"a", "b", "c", "d", "e"}) {
		t.Fatalf("active list: %v, %q, %v", managedIDs(entries), next, err)
	}
	for _, entry := range entries {
		if entry.CreatedAt.Location() != time.UTC || entry.ExpiresAt.Location() != time.UTC {
			t.Fatal("timestamps must be UTC")
		}
	}
	for filter, want := range map[string][]string{"owner": {"a", "b", "d", "e"}, "other": {"c"}, "missing": {}} {
		entries, _, err := s.ListActiveSessions(context.Background(), filter, 500, "")
		if err != nil || !reflect.DeepEqual(managedIDs(entries), want) {
			t.Fatalf("filter %s: %v, %v", filter, managedIDs(entries), err)
		}
	}
	for _, size := range []int{-1, 501} {
		if _, _, err := s.ListActiveSessions(context.Background(), "", size, ""); !errors.Is(err, ErrInvalidSessionPage) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
}

func TestListActiveSessionsPageLimits(t *testing.T) {
	s := newSessionManagementStore(t)
	seedSessionUser(t, s, "owner")
	for i := 0; i < 501; i++ {
		seedManagedSession(t, s, fmt.Sprintf("%04d", i), "owner", "full", "2025-01-01 00:00:00", "2099-01-01T00:00:00Z")
	}
	for size, want := range map[int]int{0: 100, 1: 1, 500: 500} {
		entries, next, err := s.ListActiveSessions(context.Background(), "", size, "")
		if err != nil || len(entries) != want || next == "" {
			t.Fatalf("size %d: %d, %q, %v", size, len(entries), next, err)
		}
		if size == 500 {
			last, end, err := s.ListActiveSessions(context.Background(), "", size, next)
			if err != nil || len(last) != 1 || last[0].ID != "0500" || end != "" {
				t.Fatalf("last page: %+v, %q, %v", last, end, err)
			}
		}
	}
}

func TestListActiveSessionsFractionalTimeOrderingAndExpiry(t *testing.T) {
	s := newSessionManagementStore(t)
	seedSessionUser(t, s, "owner")
	now := time.Date(2026, 10, 7, 12, 0, 0, 400000, time.UTC)
	for _, row := range []struct{ id, created, expiry string }{
		{"z", "2025-01-01T00:00:00.000100Z", "2099-01-01T00:00:00Z"},
		{"a", "2025-01-01T00:00:00.000400Z", "2099-01-01T00:00:00Z"},
		{"b", "2025-01-01T02:00:00.000400+02:00", "2099-01-01T00:00:00Z"},
		{"c", "2024-12-31T19:00:00.999900-05:00", "2099-01-01T00:00:00Z"},
		{"d", "2025-01-01 00:00:01.000001", "2026-10-07T14:00:00.000700+02:00"},
		{"expired", "2025-01-01T00:00:00Z", "2026-10-07T14:00:00.000100+02:00"},
		{"exact-boundary", "2025-01-01T00:00:00Z", "2026-10-07T07:00:00.000400-05:00"},
	} {
		seedManagedSession(t, s, row.id, "owner", "full", row.created, row.expiry)
	}
	entries, end, err := s.listActiveSessions(context.Background(), "owner", 100, "", now)
	want := []string{"z", "a", "b", "c", "d"}
	if err != nil || end != "" || !reflect.DeepEqual(managedIDs(entries), want) {
		t.Fatalf("fractional list: %v, %q, %v", managedIDs(entries), end, err)
	}
	var got []string
	var token string
	for i := 0; i < len(want); i++ {
		page, next, err := s.listActiveSessions(context.Background(), "owner", 1, token, now)
		if err != nil || len(page) != 1 {
			t.Fatalf("fractional page %d: %+v, %v", i, page, err)
		}
		got = append(got, page[0].ID)
		token = next
	}
	if !reflect.DeepEqual(got, want) || token != "" {
		t.Fatalf("fractional pagination: %v, %q", got, token)
	}
}

func TestListActiveSessionsContinuationAfterBoundaryRemoved(t *testing.T) {
	for _, remove := range []string{"revoke", "expire"} {
		t.Run(remove, func(t *testing.T) {
			s := newSessionManagementStore(t)
			seedSessionUser(t, s, "owner")
			for _, id := range []string{"a", "b", "c", "d"} {
				seedManagedSession(t, s, id, "owner", "full", "2025-01-01 00:00:00", "2099-01-01T00:00:00Z")
			}
			page, next, err := s.ListActiveSessions(context.Background(), "owner", 2, "")
			if err != nil || !reflect.DeepEqual(managedIDs(page), []string{"a", "b"}) || next == "" {
				t.Fatalf("first page: %+v, %q, %v", page, next, err)
			}
			if remove == "revoke" {
				if err := s.RevokeSession(context.Background(), "owner", "b"); err != nil {
					t.Fatal(err)
				}
			} else if _, err := s.db.Exec(`UPDATE sessions SET expires_at = '2020-01-01T00:00:00Z' WHERE session_id = 'b'`); err != nil {
				t.Fatal(err)
			}
			page, end, err := s.ListActiveSessions(context.Background(), "owner", 2, next)
			if err != nil || !reflect.DeepEqual(managedIDs(page), []string{"c", "d"}) || end != "" {
				t.Fatalf("continuation: %+v, %q, %v", page, end, err)
			}
		})
	}
}

func TestSessionCursorRejectsUntrustedInput(t *testing.T) {
	s := newSessionManagementStore(t)
	seedSessionUser(t, s, "owner")
	for _, id := range []string{"a", "b"} {
		seedManagedSession(t, s, id, "owner", "full", "2025-01-01 00:00:00", "2099-01-01T00:00:00Z")
	}
	_, token, err := s.ListActiveSessions(context.Background(), "owner", 1, "")
	if err != nil || token == "" {
		t.Fatalf("cursor: %q, %v", token, err)
	}
	_, another, err := s.ListActiveSessions(context.Background(), "owner", 1, "")
	if err != nil || token == another {
		t.Fatal("cursor nonce must be fresh")
	}
	cursor, err := s.decodeSessionCursor(token, "owner")
	if err != nil || cursor.SessionID != "a" || cursor.CreatedAt != "2025-01-01T00:00:00.000000000Z" {
		t.Fatalf("cursor contents: %+v, %v", cursor, err)
	}
	plain, err := json.Marshal(cursor)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		if strings.Contains(string(plain), "bearer-"+id) || strings.Contains(string(plain), hashSessionToken("bearer-"+id)) {
			t.Fatal("cursor contains credential")
		}
	}
	totpCiphertext, err := s.box.encrypt(string(plain))
	if err != nil {
		t.Fatal(err)
	}
	totpRaw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(totpCiphertext, secretPrefix))
	if err != nil {
		t.Fatal(err)
	}
	tamperedRaw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, sessionCursorPrefix))
	if err != nil {
		t.Fatal(err)
	}
	tamperedRaw[len(tamperedRaw)-1] ^= 1
	invalidVersion := cursor
	invalidVersion.Version = 2
	wrongVersion, err := s.encodeSessionCursor(invalidVersion)
	if err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]string{
		"plaintext": string(plain), "legacy": "anything", "oversized": strings.Repeat("x", maxSessionCursorSize+1),
		"truncated": sessionCursorPrefix + "AA", "bad-base64": sessionCursorPrefix + "!", "wrong-version": wrongVersion,
		"tampered":     sessionCursorPrefix + base64.RawURLEncoding.EncodeToString(tamperedRaw),
		"totp-domain":  sessionCursorPrefix + base64.RawURLEncoding.EncodeToString(totpRaw),
		"noncanonical": token + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := s.ListActiveSessions(context.Background(), "owner", 1, invalid); !errors.Is(err, ErrInvalidSessionPage) {
				t.Fatalf("accepted invalid cursor: %v", err)
			}
		})
	}
	for _, filter := range []string{"", "other"} {
		if _, _, err := s.ListActiveSessions(context.Background(), filter, 1, token); !errors.Is(err, ErrInvalidSessionPage) {
			t.Fatalf("filter-swapped cursor accepted: %v", err)
		}
	}
	other := newSessionManagementStore(t)
	box, err := newSecretBox(testKey('x'))
	if err != nil {
		t.Fatal(err)
	}
	other.box = box
	if _, _, err := other.ListActiveSessions(context.Background(), "owner", 1, token); !errors.Is(err, ErrInvalidSessionPage) {
		t.Fatalf("wrong key accepted: %v", err)
	}
	if _, err := s.GetSession(token); err == nil {
		t.Fatal("cursor authenticated")
	}
}

func TestManagedSessionRevokeScopeAndFailures(t *testing.T) {
	s := newSessionManagementStore(t)
	seedSessionUser(t, s, "owner")
	for _, id := range []string{"target", "sibling"} {
		seedManagedSession(t, s, id, "owner", "full", "2025-01-01 00:00:00", "2099-01-01T00:00:00Z")
	}
	for _, pair := range [][2]string{{"wrong-owner", "target"}, {"owner", "missing"}, {"owner", "target' OR 1=1 --"}} {
		if err := s.RevokeSession(context.Background(), pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.GetSession("bearer-target"); err != nil {
		t.Fatal("wrong pair revoked target")
	}
	for i := 0; i < 2; i++ {
		if err := s.RevokeSession(context.Background(), "owner", "target"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.GetSession("bearer-target"); err == nil {
		t.Fatal("revoked bearer still valid")
	}
	if _, err := s.GetSession("bearer-sibling"); err != nil {
		t.Fatal("sibling affected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.ListActiveSessions(ctx, "", 1, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("list ignored canceled context: %v", err)
	}
	if err := s.RevokeSession(ctx, "owner", "sibling"); !errors.Is(err, context.Canceled) {
		t.Fatalf("revoke ignored canceled context: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ListActiveSessions(context.Background(), "", 1, ""); err == nil {
		t.Fatal("list hid database failure")
	}
	if err := s.RevokeSession(context.Background(), "owner", "sibling"); err == nil {
		t.Fatal("revoke hid database failure")
	}
}
