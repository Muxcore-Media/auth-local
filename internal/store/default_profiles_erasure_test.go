package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func defaultProfileTombstone(userID string) Tombstone {
	return Tombstone{ErasureID: "er-profile-fixture", UserID: userID, DeletedBy: "fixture-admin", DeletedAt: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)}
}

func insertDefaultProfileTombstone(t *testing.T, s *Store, tombstone Tombstone) {
	t.Helper()
	execProfileSQL(t, s, `INSERT INTO user_erasures (erasure_id, user_id, tenant_id, deleted_at, deleted_by) VALUES (?, ?, ?, ?, ?)`,
		tombstone.ErasureID, tombstone.UserID, tombstone.TenantID, formatErasureTime(tombstone.DeletedAt), tombstone.DeletedBy)
}

func TestDefaultProfileTombstoneCleanup(t *testing.T) {
	for _, restoreOwner := range []bool{false, true} {
		t.Run(map[bool]string{false: "owner-absent", true: "owner-restored"}[restoreOwner], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "auth.db")
			s, err := NewWithKey(path, testKey('p'))
			if err != nil {
				t.Fatal(err)
			}
			admin := makeAdmin(t, s, "parent", "")
			victim, err := s.CreateUser("victim", "fixture-password")
			if err != nil {
				t.Fatal(err)
			}
			parentMapping := requireDefaultProfiles(t, s)[admin.ID]
			if _, err := s.EraseUser(context.Background(), admin.ID, "", victim.ID); err != nil {
				t.Fatal(err)
			}
			requireNoUserRows(t, s, victim.ID)
			// Malformed restored mappings must be purged before validation.
			execProfileSQL(t, s, `INSERT INTO account_default_profiles VALUES (?, 'invalid', 'invalid')`, victim.ID)
			if restoreOwner {
				execProfileSQL(t, s, `INSERT INTO users (id, username, password, roles) VALUES (?, 'victim', 'fixture', '["user"]')`, victim.ID)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = NewWithKey(path, testKey('p'))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			requireNoUserRows(t, s, victim.ID)
			if got := requireDefaultProfiles(t, s)[admin.ID]; got != parentMapping {
				t.Fatal("startup replaced bystander mapping")
			}
		})
	}
}

func TestDefaultProfileSweepValidationRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := NewWithKey(path, testKey('p'))
	if err != nil {
		t.Fatal(err)
	}
	victim, err := s.CreateUser("victim", "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	bystander, err := s.CreateUser("bystander", "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	insertDefaultProfileTombstone(t, s, defaultProfileTombstone(victim.ID))
	execProfileSQL(t, s, `UPDATE account_default_profiles SET profile_id = 'invalid' WHERE user_id = ?`, bystander.ID)
	before := defaultProfileRecords(t, s)
	if count, err := s.SweepTombstoned(context.Background()); err == nil || count != 0 {
		t.Fatalf("failed sweep = %d, %v; want zero committed rows and error", count, err)
	}
	if _, err := s.GetUser(victim.ID); err != nil || !reflect.DeepEqual(before, defaultProfileRecords(t, s)) {
		t.Fatalf("failed sweep committed deletions: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := NewWithKey(path, testKey('p')); err == nil {
		_ = reopened.Close()
		t.Fatal("startup accepted invalid bystander")
	}
	db, err := openExisting(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	stored := &Store{db: db}
	if _, err := stored.GetUser(victim.ID); err != nil || !reflect.DeepEqual(before, defaultProfileRecords(t, stored)) {
		t.Fatalf("failed startup committed sweep: %v", err)
	}
}

func TestDefaultProfileImportValidationRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := NewWithKey(path, testKey('p'))
	if err != nil {
		t.Fatal(err)
	}
	victim, err := s.CreateUser("victim", "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	bystander, err := s.CreateUser("bystander", "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	before := requireDefaultProfiles(t, s)
	execProfileSQL(t, s, `UPDATE account_default_profiles SET created_at = 'invalid' WHERE user_id = ?`, bystander.ID)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	ledger := &Ledger{Version: LedgerVersion, Erasures: []Tombstone{defaultProfileTombstone(victim.ID)}}
	if result, err := ImportLedger(context.Background(), path, ledger); err == nil || result != (ImportResult{}) {
		t.Fatalf("invalid import = %+v, %v", result, err)
	}
	db, err := openExisting(path, false)
	if err != nil {
		t.Fatal(err)
	}
	stored := &Store{db: db}
	var tombstones int
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_erasures`).Scan(&tombstones); err != nil || tombstones != 0 {
		t.Fatalf("failed import committed tombstones = %d, %v", tombstones, err)
	}
	if _, err := stored.GetUser(victim.ID); err != nil || defaultProfileRecords(t, stored)[victim.ID] != before[victim.ID] {
		t.Fatalf("failed import removed victim: %v", err)
	}
	execProfileSQL(t, stored, `UPDATE account_default_profiles SET created_at = ? WHERE user_id = ?`, before[bystander.ID].CreatedAt, bystander.ID)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportLedger(context.Background(), path, ledger); err != nil {
		t.Fatalf("valid retry failed: %v", err)
	}
	s, err = NewWithKey(path, testKey('p'))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	requireNoUserRows(t, s, victim.ID)
	if got := requireDefaultProfiles(t, s)[bystander.ID]; got != before[bystander.ID] {
		t.Fatal("successful reconciliation changed surviving mapping")
	}
}

func TestDefaultProfileImportPriorMigrationBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := NewWithKey(path, testKey('p'))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("living", "fixture-password"); err != nil {
		t.Fatal(err)
	}
	insertDefaultProfileTombstone(t, s, defaultProfileTombstone("already-erased"))
	// Model the schema boundary in a unit test, not a previous-tag snapshot.
	execProfileSQL(t, s, `DROP TABLE account_default_profiles`)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	conflict := &Ledger{Version: LedgerVersion, Erasures: []Tombstone{defaultProfileTombstone("different-user")}}
	if _, err := ImportLedger(context.Background(), path, conflict); !errors.Is(err, ErrErasureConflict) {
		t.Fatalf("conflicting import = %v", err)
	}
	s, err = NewWithKey(path, testKey('p'))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if len(requireDefaultProfiles(t, s)) != 1 {
		t.Fatal("prior forward mapping migration did not persist")
	}
	var owner string
	if err := s.db.QueryRow(`SELECT user_id FROM user_erasures WHERE erasure_id = 'er-profile-fixture'`).Scan(&owner); err != nil || owner != "already-erased" {
		t.Fatalf("failed import changed existing ledger = %q, %v", owner, err)
	}
}
