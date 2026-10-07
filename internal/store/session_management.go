package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	DefaultSessionPageSize = 100
	MaxSessionPageSize     = 500
	sessionCursorPrefix    = "sc1."
	maxSessionCursorSize   = 4096
	sessionCursorAAD       = "auth-local/ListActiveSessions/v1"
	sessionTimeLayout      = "2006-01-02T15:04:05.000000000Z"
)

// ErrInvalidSessionPage denotes invalid pagination input, including a cursor
// from another filter, another key or an unsupported version.
var ErrInvalidSessionPage = errors.New("invalid session pagination")

// ActiveSession is the administrative view. It deliberately has no bearer or
// bearer hash; Session remains the separate authentication result.
type ActiveSession struct {
	ID        string
	UserID    string
	Username  string
	Kind      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type sessionCursor struct {
	Version   int    `json:"v"`
	UserID    string `json:"u"`
	CreatedAt string `json:"c"`
	SessionID string `json:"s"`
}

func newManagementSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sid_" + hex.EncodeToString(b), nil
}

// migrateSessionIDs installs the column, backfill and unique index atomically.
// Existing bearer hashes and timestamps are never rewritten. Nullable legacy
// rows are permitted in the schema, but every application insertion supplies an
// ID and reopening backfills any row from an older writer.
func (s *Store) migrateSessionIDs() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`ALTER TABLE sessions ADD COLUMN session_id TEXT`); err != nil &&
		!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
		return fmt.Errorf("add session IDs: %w", err)
	}
	rows, err := tx.Query(`SELECT token FROM sessions WHERE session_id IS NULL OR session_id = ''`)
	if err != nil {
		return err
	}
	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			_ = rows.Close()
			return err
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, token := range tokens {
		id, err := newManagementSessionID()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE sessions SET session_id = ? WHERE token = ?`, id, token); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_id ON sessions(session_id)`); err != nil {
		return err
	}
	return tx.Commit()
}

// ListActiveSessions returns at most pageSize current, fully authenticated
// sessions for existing users. The extra row detects continuation without
// loading the full result set. Ordering and expiry normalize both historical
// SQLite timestamps and RFC3339 timestamps (including timezone offsets).
func (s *Store) ListActiveSessions(ctx context.Context, userID string, pageSize int, pageToken string) ([]ActiveSession, string, error) {
	return s.listActiveSessions(ctx, userID, pageSize, pageToken, time.Now())
}

func (s *Store) listActiveSessions(ctx context.Context, userID string, pageSize int, pageToken string, now time.Time) ([]ActiveSession, string, error) {
	if pageSize < 0 || pageSize > MaxSessionPageSize {
		return nil, "", ErrInvalidSessionPage
	}
	if pageSize == 0 {
		pageSize = DefaultSessionPageSize
	}
	var cursor sessionCursor
	if pageToken != "" {
		var err error
		cursor, err = s.decodeSessionCursor(pageToken, userID)
		if err != nil {
			return nil, "", err
		}
	}
	query := `WITH session_times AS (SELECT sessions.*, ` + sessionTimeOrderSQL("created_at") + ` AS created_order, ` +
		sessionTimeOrderSQL("expires_at") + ` AS expires_order FROM sessions)
		SELECT s.session_id, s.user_id, u.username, s.kind, s.created_at, s.expires_at
		FROM session_times s JOIN users u ON u.id = s.user_id
		WHERE s.kind IN ('full', 'api-token') AND s.session_id IS NOT NULL AND s.session_id <> ''
		AND s.expires_order > ? AND s.created_order IS NOT NULL`
	args := []any{now.UTC().Format(sessionTimeLayout)}
	if userID != "" {
		query += ` AND s.user_id = ?`
		args = append(args, userID)
	}
	if pageToken != "" {
		query += ` AND (s.created_order > ? OR (s.created_order = ? AND s.session_id > ?))`
		args = append(args, cursor.CreatedAt, cursor.CreatedAt, cursor.SessionID)
	}
	query += ` ORDER BY s.created_order, s.session_id LIMIT ?`
	args = append(args, pageSize+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()
	entries := make([]ActiveSession, 0, pageSize+1)
	for rows.Next() {
		var entry ActiveSession
		var createdAt, expiresAt string
		if err := rows.Scan(&entry.ID, &entry.UserID, &entry.Username, &entry.Kind, &createdAt, &expiresAt); err != nil {
			return nil, "", err
		}
		entry.CreatedAt = parseTime(createdAt).UTC()
		entry.ExpiresAt = parseTime(expiresAt).UTC()
		if entry.CreatedAt.IsZero() || entry.ExpiresAt.IsZero() {
			return nil, "", errors.New("invalid stored session timestamp")
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(entries) <= pageSize {
		return entries, "", nil
	}
	entries = entries[:pageSize]
	last := entries[len(entries)-1]
	next, err := s.encodeSessionCursor(sessionCursor{
		Version: 1, UserID: userID, CreatedAt: last.CreatedAt.Format(sessionTimeLayout), SessionID: last.ID,
	})
	if err != nil {
		return nil, "", err
	}
	return entries, next, nil
}

// sessionTimeOrderSQL normalizes a fixed internal timestamp column to the same
// UTC, fixed-width nanosecond key as sessionTimeLayout. SQLite date functions
// round fractions to milliseconds: pass them only whole seconds plus the zone,
// then append the original fractional digits. This preserves ordering even for
// legacy RFC3339 fractions, without modifying the stored timestamp. Column names
// here are source constants, never request data.
func sessionTimeOrderSQL(column string) string {
	zone := `CASE WHEN substr(` + column + `, -1) = 'Z' THEN 'Z'
		WHEN substr(` + column + `, -6, 1) IN ('+', '-') THEN substr(` + column + `, -6) ELSE '' END`
	return `strftime('%Y-%m-%dT%H:%M:%S', substr(` + column + `, 1, 19) || (` + zone + `)) || '.' ||
		CASE WHEN substr(` + column + `, 20, 1) IN ('.', ',') THEN
			substr(substr(` + column + `, 21, length(` + column + `) - 20 - length(` + zone + `)) || '000000000', 1, 9)
			ELSE '000000000' END || 'Z'`
}

func (s *Store) encodeSessionCursor(cursor sessionCursor) (string, error) {
	plain, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.box.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := s.box.aead.Seal(nonce, nonce, plain, []byte(sessionCursorAAD))
	return sessionCursorPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *Store) decodeSessionCursor(token, userID string) (sessionCursor, error) {
	invalid := func() (sessionCursor, error) { return sessionCursor{}, ErrInvalidSessionPage }
	if len(token) > maxSessionCursorSize || !strings.HasPrefix(token, sessionCursorPrefix) {
		return invalid()
	}
	encoded := strings.TrimPrefix(token, sessionCursorPrefix)
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	n := s.box.aead.NonceSize()
	if err != nil || len(raw) < n+s.box.aead.Overhead() || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return invalid()
	}
	// Never use secretBox.decrypt here: its legacy plaintext fallback is only
	// appropriate for at-rest TOTP migration, never untrusted continuation.
	plain, err := s.box.aead.Open(nil, raw[:n], raw[n:], []byte(sessionCursorAAD))
	if err != nil {
		return invalid()
	}
	var cursor sessionCursor
	if err := json.Unmarshal(plain, &cursor); err != nil || cursor.Version != 1 || cursor.UserID != userID || cursor.SessionID == "" {
		return invalid()
	}
	if _, err := time.Parse(time.RFC3339Nano, cursor.CreatedAt); err != nil {
		return invalid()
	}
	return cursor, nil
}

// RevokeSession deletes only the exact management pair. Unknown or already
// revoked pairs succeed, and the API key that minted a session is unaffected.
func (s *Store) RevokeSession(ctx context.Context, userID, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND session_id = ?`, userID, sessionID)
	return err
}

// SessionAdminRoles loads current roles through a current bearer session. It is
// separate from mesh authorization and has no fallback to a module identity.
// ErrInvalidSession covers missing/expired/partial sessions and deleted users;
// operational errors remain visible to the RPC for Internal status mapping.
func (s *Store) SessionAdminRoles(ctx context.Context, token string) ([]string, error) {
	identity, err := s.ValidateSession(ctx, token)
	if err != nil {
		return nil, err
	}
	return identity.Roles, nil
}
