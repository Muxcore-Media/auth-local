package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type defaultProfileRecord struct {
	ID, CreatedAt string
}

func defaultProfileRecords(t *testing.T, s *Store) map[string]defaultProfileRecord {
	t.Helper()
	rows, err := s.db.Query(`SELECT user_id, profile_id, created_at FROM account_default_profiles`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := make(map[string]defaultProfileRecord)
	for rows.Next() {
		var userID string
		var record defaultProfileRecord
		if err := rows.Scan(&userID, &record.ID, &record.CreatedAt); err != nil {
			t.Fatal(err)
		}
		out[userID] = record
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func requireDefaultProfiles(t *testing.T, s *Store) map[string]defaultProfileRecord {
	t.Helper()
	records := defaultProfileRecords(t, s)
	users, err := s.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != len(users) {
		t.Fatalf("mapping count = %d, users = %d", len(records), len(users))
	}
	ids := make(map[string]bool)
	for _, user := range users {
		record, ok := records[user.ID]
		if !ok || !validDefaultProfileID(record.ID) || ids[record.ID] {
			t.Fatal("missing, malformed, or duplicate default profile")
		}
		at, err := time.Parse(time.RFC3339Nano, record.CreatedAt)
		if err != nil || at.UTC().Format(time.RFC3339Nano) != record.CreatedAt {
			t.Fatalf("noncanonical mapping creation time %q", record.CreatedAt)
		}
		ids[record.ID] = true
	}
	return records
}

func execProfileSQL(t *testing.T, s *Store, query string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultProfileCreationAndDormancy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := NewWithKey(path, testKey('p'))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s != nil {
			_ = s.Close()
		}
	})
	t.Setenv("AUTH_BOOTSTRAP_USER", "parent")
	t.Setenv("AUTH_BOOTSTRAP_PASSWORD", "fixture-password")
	if err := BootstrapAdminFromEnv(s); err != nil {
		t.Fatal(err)
	}
	user, err := s.CreateUserTenant("viewer", "fixture-password", "household-a")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := s.CreateInvite("parent", "viewer", "household-b", 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RedeemInvite(inv.Token, "invited", "fixture-password"); err != nil {
		t.Fatal(err)
	}
	before := requireDefaultProfiles(t, s)
	if len(before) != 3 {
		t.Fatalf("created mappings = %d, want 3", len(before))
	}
	sess, err := s.CreateFullSession(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRoles(user.ID, []string{"viewer"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTenantID(user.ID, "household-c"); err != nil {
		t.Fatal(err)
	}
	identity, err := s.ValidateSession(context.Background(), sess.Token)
	if err != nil || identity.UserID != user.ID || identity.TenantID != "household-c" || !reflect.DeepEqual(identity.Roles, []string{"viewer"}) {
		t.Fatalf("account identity changed: %+v, %v", identity, err)
	}
	if _, err := s.ValidateSession(context.Background(), before[user.ID].ID); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("profile ID authenticated: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewWithKey(path, testKey('p'))
	if err != nil {
		t.Fatal(err)
	}
	if after := requireDefaultProfiles(t, s); !reflect.DeepEqual(before, after) {
		t.Fatal("reopen or account metadata change replaced a mapping")
	}
	if _, err := s.ValidateSession(context.Background(), sess.Token); err != nil {
		t.Fatalf("existing account bearer rejected after reopen: %v", err)
	}
}

func TestDefaultProfileSchemaConstraints(t *testing.T) {
	s := newTestStore(t)
	u, err := s.CreateUser("owner", "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	id := requireDefaultProfiles(t, s)[u.ID].ID
	for _, args := range [][]any{
		{nil, strings.Repeat("a", 32), "2026-10-12T00:00:00Z"},
		{"other", nil, "2026-10-12T00:00:00Z"},
		{"other", strings.Repeat("b", 32), nil},
		{u.ID, strings.Repeat("c", 32), "2026-10-12T00:00:00Z"},
		{"other", id, "2026-10-12T00:00:00Z"},
	} {
		if _, err := s.db.Exec(`INSERT INTO account_default_profiles VALUES (?, ?, ?)`, args...); err == nil {
			t.Fatal("null or duplicate mapping accepted")
		}
	}
	var declared int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_foreign_key_list('account_default_profiles') WHERE "table" = 'users' AND "from" = 'user_id' AND "to" = 'id'`).Scan(&declared); err != nil || declared != 1 {
		t.Fatalf("owner foreign key declarations = %d, %v", declared, err)
	}
}

func TestDefaultProfileEntropyAndMigrationRollback(t *testing.T) {
	if _, err := readDefaultProfileID(bytes.NewReader(make([]byte, 15))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short entropy read = %v", err)
	}
	id, err := readDefaultProfileID(bytes.NewReader(bytes.Repeat([]byte{0xab}, 16)))
	if err != nil || id != strings.Repeat("ab", 16) {
		t.Fatalf("entropy encoding = %q, %v", id, err)
	}
	s := newTestStore(t)
	for _, name := range []string{"first", "second"} {
		if _, err := s.CreateUser(name, "fixture-password"); err != nil {
			t.Fatal(err)
		}
	}
	// A unit migration fixture, not a released-tag snapshot or its provenance.
	execProfileSQL(t, s, `DROP TABLE account_default_profiles`)
	want := errors.New("fixture entropy unavailable")
	calls := 0
	err = s.migrateDefaultProfiles(context.Background(), func() (string, error) {
		calls++
		if calls == 2 {
			return "", want
		}
		return strings.Repeat("a", 32), nil
	})
	if !errors.Is(err, want) || calls != 2 {
		t.Fatalf("backfill failure = %v, calls %d", err, calls)
	}
	var tables int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'account_default_profiles'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("partially committed mapping table = %d, %v", tables, err)
	}
	if err := s.migrateDefaultProfiles(context.Background(), func() (string, error) { return strings.Repeat("b", 32), nil }); err == nil {
		t.Fatal("duplicate generated identity did not abort SQL backfill")
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'account_default_profiles'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("SQL failure partially committed mapping table = %d, %v", tables, err)
	}
	if err := s.migrateDefaultProfiles(context.Background(), newDefaultProfileID); err != nil {
		t.Fatal(err)
	}
	before := requireDefaultProfiles(t, s)
	if err := s.migrateDefaultProfiles(context.Background(), func() (string, error) { return "", want }); err != nil {
		t.Fatalf("repeat migration generated an identity: %v", err)
	}
	if !reflect.DeepEqual(before, requireDefaultProfiles(t, s)) {
		t.Fatal("repeat migration changed mappings")
	}
}

func TestDefaultProfileInsertionRollback(t *testing.T) {
	s := newTestStore(t)
	inv, err := s.CreateInvite("fixture-module", "user", "", 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	execProfileSQL(t, s, `CREATE TRIGGER refuse_profile BEFORE INSERT ON account_default_profiles BEGIN SELECT RAISE(ABORT, 'fixture mapping failure'); END`)
	if _, err := s.CreateUser("ordinary", "fixture-password"); err == nil {
		t.Fatal("ordinary user creation ignored mapping failure")
	}
	if _, _, err := s.RedeemInvite(inv.Token, "invited", "fixture-password"); err == nil {
		t.Fatal("invite redemption ignored mapping failure")
	}
	users, err := s.ListUsers()
	if err != nil || len(users) != 0 || len(defaultProfileRecords(t, s)) != 0 {
		t.Fatalf("failed creation left users or mappings: %d, %v", len(users), err)
	}
	if got := inviteByID(t, s, inv.ID); got.UseCount != 0 {
		t.Fatal("failed mapping consumed invite")
	}
	execProfileSQL(t, s, `DROP TRIGGER refuse_profile`)
	if _, _, err := s.RedeemInvite(inv.Token, "invited", "fixture-password"); err != nil {
		t.Fatalf("rolled-back invite could not be redeemed: %v", err)
	}
	requireDefaultProfiles(t, s)
}

func TestDefaultProfileInitialBackfillExcludesTombstoned(t *testing.T) {
	s := newTestStore(t)
	live, err := s.CreateUser("living", "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	victim, err := s.CreateUser("erased", "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	insertDefaultProfileTombstone(t, s, defaultProfileTombstone(victim.ID))
	execProfileSQL(t, s, `DROP TABLE account_default_profiles`)
	calls := 0
	if err := s.migrateDefaultProfiles(context.Background(), func() (string, error) {
		calls++
		return strings.Repeat("a", 32), nil
	}); err != nil {
		t.Fatal(err)
	}
	profiles := defaultProfileRecords(t, s)
	if calls != 1 || len(profiles) != 1 || profiles[live.ID].ID != strings.Repeat("a", 32) {
		t.Fatal("first backfill included an erased account or omitted the live one")
	}
	if _, err := s.SweepTombstoned(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireNoUserRows(t, s, victim.ID)
	requireDefaultProfiles(t, s)
}

func TestDefaultProfileDuplicateIdentityRefused(t *testing.T) {
	for _, duplicateOwner := range []bool{false, true} {
		t.Run(map[bool]string{false: "profile", true: "owner"}[duplicateOwner], func(t *testing.T) {
			s := newTestStore(t)
			first, err := s.CreateUser("first", "fixture-password")
			if err != nil {
				t.Fatal(err)
			}
			second := first
			if !duplicateOwner {
				second, err = s.CreateUser("second", "fixture-password")
				if err != nil {
					t.Fatal(err)
				}
			}
			// Simulate a damaged table whose unique constraints were lost.
			execProfileSQL(t, s, `DROP TABLE account_default_profiles`)
			execProfileSQL(t, s, `CREATE TABLE account_default_profiles (user_id TEXT, profile_id TEXT, created_at TEXT)`)
			otherOwner, otherProfile := second.ID, strings.Repeat("a", 32)
			if duplicateOwner {
				otherOwner, otherProfile = first.ID, strings.Repeat("b", 32)
			}
			execProfileSQL(t, s, `INSERT INTO account_default_profiles VALUES (?, ?, '2026-10-12T00:00:00Z'), (?, ?, '2026-10-12T00:00:00Z')`,
				first.ID, strings.Repeat("a", 32), otherOwner, otherProfile)
			if _, err := s.SweepTombstoned(context.Background()); err == nil {
				t.Fatal("duplicate mapping identity accepted")
			}
		})
	}
}

func TestDefaultProfileCorruptionRefusesOpen(t *testing.T) {
	cases := map[string]string{
		"missing":      `DELETE FROM account_default_profiles`,
		"uppercase":    `UPDATE account_default_profiles SET profile_id = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'`,
		"short":        `UPDATE account_default_profiles SET profile_id = 'abc'`,
		"nonhex":       `UPDATE account_default_profiles SET profile_id = 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'`,
		"nonutc":       `UPDATE account_default_profiles SET created_at = '2026-10-12T01:00:00+01:00'`,
		"noncanonical": `UPDATE account_default_profiles SET created_at = '2026-10-12T00:00:00.000Z'`,
		"invalidtime":  `UPDATE account_default_profiles SET created_at = 'yesterday'`,
		"orphan":       `INSERT INTO account_default_profiles VALUES ('unknown-owner', 'dddddddddddddddddddddddddddddddd', '2026-10-12T00:00:00Z')`,
	}
	for name, query := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "auth.db")
			s, err := NewWithKey(path, testKey('p'))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.CreateUser("owner", "fixture-password"); err != nil {
				t.Fatal(err)
			}
			execProfileSQL(t, s, query)
			before := defaultProfileRecords(t, s)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if reopened, err := NewWithKey(path, testKey('p')); err == nil {
				_ = reopened.Close()
				t.Fatal("corrupt mapping accepted")
			}
			db, err := openExisting(path, true)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			if after := defaultProfileRecords(t, &Store{db: db}); !reflect.DeepEqual(before, after) {
				t.Fatal("failed open repaired mapping")
			}
		})
	}
}

func TestDefaultProfileConcurrentOpensAndCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := NewWithKey(path, testKey('p'))
	if err != nil {
		t.Fatal(err)
	}
	existing, err := s.CreateUser("existing", "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	execProfileSQL(t, s, `DROP TABLE account_default_profiles`)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	type observation struct {
		mapping defaultProfileRecord
		err     error
	}
	results := make(chan observation, 3)
	start := make(chan struct{})
	for i := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			opened, err := NewWithKey(path, testKey('p'))
			if err != nil {
				results <- observation{err: err}
				return
			}
			defer func() { _ = opened.Close() }()
			var mapping defaultProfileRecord
			if err := opened.db.QueryRow(`SELECT profile_id, created_at FROM account_default_profiles WHERE user_id = ?`, existing.ID).Scan(&mapping.ID, &mapping.CreatedAt); err != nil {
				results <- observation{err: err}
				return
			}
			_, err = opened.CreateUser(fmt.Sprintf("concurrent-%d", i), "fixture-password")
			results <- observation{mapping: mapping, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	s, err = NewWithKey(path, testKey('p'))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	profiles := requireDefaultProfiles(t, s)
	if len(profiles) != 4 {
		t.Fatal("concurrent creation lost mappings")
	}
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.mapping != profiles[existing.ID] {
			t.Fatal("concurrent open replaced the existing mapping")
		}
	}
}
