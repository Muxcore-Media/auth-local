package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

// Default profiles are dormant ownership records (ADR-0040). They are never
// returned in account identities, credentials, or consumer APIs.
const defaultProfilesSchema = `CREATE TABLE account_default_profiles (
	user_id TEXT NOT NULL PRIMARY KEY REFERENCES users(id),
	profile_id TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL
)`

func newDefaultProfileID() (string, error) {
	return readDefaultProfileID(rand.Reader)
}

func readDefaultProfileID(entropy io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(entropy, b[:]); err != nil {
		return "", fmt.Errorf("default profile entropy: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func validDefaultProfileID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func insertDefaultProfile(ctx context.Context, q sqlExecer, userID string, generate func() (string, error)) error {
	id, err := generate()
	if err != nil {
		return err
	}
	if !validDefaultProfileID(id) {
		return errors.New("invalid generated default profile ID")
	}
	_, err = q.ExecContext(ctx, `INSERT INTO account_default_profiles (user_id, profile_id, created_at) VALUES (?, ?, ?)`,
		userID, id, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("insert default profile: %w", err)
	}
	return nil
}

// Table absence is the first-migration marker. An existing table is never
// backfilled or repaired: its rows are validated after the tombstone sweep.
// A private generator argument permits transactional failure tests without
// replacing global randomness.
func (s *Store) migrateDefaultProfiles(ctx context.Context, generate func() (string, error)) error {
	return s.writeTx(ctx, func(q sqlExecer) error {
		var exists int
		if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'account_default_profiles'`).Scan(&exists); err != nil {
			return err
		}
		if exists != 0 {
			return nil
		}
		if _, err := q.ExecContext(ctx, defaultProfilesSchema); err != nil {
			return fmt.Errorf("create default profiles: %w", err)
		}
		rows, err := q.QueryContext(ctx, `SELECT id FROM users WHERE NOT EXISTS (SELECT 1 FROM user_erasures e WHERE e.user_id = users.id) ORDER BY id`)
		if err != nil {
			return err
		}
		var users []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			users = append(users, id)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, id := range users {
			if err := insertDefaultProfile(ctx, q, id, generate); err != nil {
				return err
			}
		}
		return nil
	})
}

// validateDefaultProfiles runs in the same write transaction as a preceding
// tombstone sweep, including offline ledger import. It checks only mappings;
// existing session/credential orphan behavior is outside this invariant.
func validateDefaultProfiles(ctx context.Context, q sqlExecer) error {
	rows, err := q.QueryContext(ctx, `SELECT p.user_id, p.profile_id, p.created_at, u.id IS NOT NULL, e.user_id IS NOT NULL
		FROM account_default_profiles p LEFT JOIN users u ON u.id = p.user_id
		LEFT JOIN user_erasures e ON e.user_id = p.user_id`)
	if err != nil {
		return fmt.Errorf("read default profiles: %w", err)
	}
	users, profiles := make(map[string]bool), make(map[string]bool)
	for rows.Next() {
		var userID, profileID, createdAt string
		var present, erased bool
		if err := rows.Scan(&userID, &profileID, &createdAt, &present, &erased); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read default profile: %w", err)
		}
		created, parseErr := time.Parse(time.RFC3339Nano, createdAt)
		if !present || erased || users[userID] || profiles[profileID] || !validDefaultProfileID(profileID) ||
			parseErr != nil || created.UTC().Format(time.RFC3339Nano) != createdAt {
			_ = rows.Close()
			return errors.New("invalid default profile mapping")
		}
		users[userID], profiles[profileID] = true, true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var missing int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM users u
		WHERE NOT EXISTS (SELECT 1 FROM user_erasures e WHERE e.user_id = u.id)
		AND NOT EXISTS (SELECT 1 FROM account_default_profiles p WHERE p.user_id = u.id)`).Scan(&missing); err != nil {
		return err
	}
	if missing != 0 {
		return errors.New("missing default profile mapping")
	}
	return nil
}
