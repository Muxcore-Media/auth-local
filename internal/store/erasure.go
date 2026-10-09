package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"
)

// User erasure (ADR-0035). EraseUser revokes every credential and session of a
// user and records a tombstone in user_erasures in ONE write transaction. The
// tombstone ledger is the only authority other modules act on; it carries no
// username and is never pruned.

// Erasure errors. Callers map them to transport status codes.
var (
	// ErrUserNotFound: the target does not exist in the caller's tenant (an
	// unknown id and another tenant's id are indistinguishable).
	ErrUserNotFound = errors.New("user not found")
	// ErrSelfErasure: an administrator may not erase their own account.
	ErrSelfErasure = errors.New("cannot delete your own account")
	// ErrLastAdmin: the target is the last user holding admin in its tenant.
	ErrLastAdmin = errors.New("cannot delete the last admin")
	// ErrUserIDErased: the id is tombstoned and may never be created again.
	ErrUserIDErased = errors.New("user id has been erased")
	// ErrErasureNotFound: no tombstone has this erasure id (in this tenant).
	ErrErasureNotFound = errors.New("erasure not found")
	// ErrInvalidErasurePage: invalid page size or continuation token.
	ErrInvalidErasurePage = errors.New("invalid erasure pagination")
	// ErrErasureConflict: an imported tombstone disagrees with the ledger.
	ErrErasureConflict = errors.New("conflicting erasure tombstone")
)

// DeletedUserMarker replaces the username of an erased invite creator.
const DeletedUserMarker = "deleted-user"

// Erasure ack outcomes as stored in erasure_acks.outcome.
const (
	ErasureOutcomeOK          = "OK"
	ErasureOutcomeFailed      = "FAILED"
	ErasureOutcomeUnsupported = "UNSUPPORTED"
)

// Ledger paging bounds (core auth proto: 0 selects 100, at most 500).
const (
	DefaultErasurePageSize = 100
	MaxErasurePageSize     = 500
)

const (
	erasureTimeLayout     = "2006-01-02T15:04:05.000000000Z"
	erasureCursorPrefix   = "ec1."
	maxErasureCursorSize  = 4096
	erasureListCursorAAD  = "auth-local/ListUserErasures/v1"
	erasureStatusCursorAD = "auth-local/GetUserErasureStatus/v1"
	maxErasureIDLen       = 128
	maxErasureUserIDLen   = 256
)

var erasureIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// ValidErasureID reports whether id is syntactically a ledger erasure id.
func ValidErasureID(id string) bool { return erasureIDPattern.MatchString(id) }

// Tombstone is one row of the erasure ledger. It has no username.
type Tombstone struct {
	ErasureID string    `json:"erasure_id"`
	UserID    string    `json:"user_id"`
	TenantID  string    `json:"tenant_id"`
	DeletedAt time.Time `json:"deleted_at"`
	DeletedBy string    `json:"deleted_by"`
}

// LedgerEntry is a tombstone as listed to a consumer module.
type LedgerEntry struct {
	Tombstone
	// AcknowledgedByCaller: the listing module's latest ack is OK.
	AcknowledgedByCaller bool
}

// ErasureAck is the latest acknowledgement of one erasure by one module.
type ErasureAck struct {
	AckedAt    time.Time
	ModuleID   string
	Outcome    string
	DetailCode string
}

// ErasureStatus is the per-module completion of one erasure.
type ErasureStatus struct {
	DeletedAt time.Time
	ErasureID string
	// Acks holds the latest ack of every module that acknowledged, sorted by
	// module id.
	Acks []ErasureAck
}

// newErasureID returns a random, opaque erasure id; it is never derived from
// the user id or username.
func newErasureID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "er_" + hex.EncodeToString(b), nil
}

func formatErasureTime(t time.Time) string { return t.UTC().Format(erasureTimeLayout) }

func parseErasureTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// migrateErasures installs the ledger tables (forward-only, idempotent).
func (s *Store) migrateErasures() error {
	for _, q := range erasureDDL {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate erasures: %w", err)
		}
	}
	return nil
}

var erasureDDL = []string{
	`CREATE TABLE IF NOT EXISTS user_erasures (
		erasure_id TEXT PRIMARY KEY,
		user_id    TEXT NOT NULL UNIQUE,
		tenant_id  TEXT NOT NULL DEFAULT '',
		deleted_at TEXT NOT NULL,
		deleted_by TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_user_erasures_order ON user_erasures(deleted_at, erasure_id)`,
	`CREATE TABLE IF NOT EXISTS erasure_acks (
		erasure_id  TEXT NOT NULL,
		module_id   TEXT NOT NULL,
		outcome     TEXT NOT NULL,
		detail_code TEXT NOT NULL DEFAULT '',
		counts_json TEXT NOT NULL DEFAULT '{}',
		acked_at    TEXT NOT NULL,
		PRIMARY KEY (erasure_id, module_id)
	)`,
}

// notErased is appended to INSERT ... SELECT statements so a tombstoned user
// id can never gain a row again, even if it races an erasure.
const notErasedClause = ` WHERE NOT EXISTS (SELECT 1 FROM user_erasures WHERE user_id = ?)`

type sqlExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// writeTx runs fn on a dedicated connection inside BEGIN IMMEDIATE, so the
// transaction holds SQLite's write lock from its first statement: reads taken
// inside fn (e.g. the last-admin count) cannot be invalidated by a concurrent
// writer in this or another process before the commit.
func (s *Store) writeTx(ctx context.Context, fn func(q sqlExecer) error) (err error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("begin write transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			// A background context: the rollback must run even if ctx ended.
			if _, rbErr := conn.ExecContext(context.Background(), `ROLLBACK`); rbErr != nil && err == nil {
				err = rbErr
			}
		}
	}()
	if err := fn(conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
	return nil
}

// eraseHookBeforeTx, when set (tests only), runs after argument checks and
// before the write transaction begins.
var eraseHookBeforeTx func()

// EraseUser erases targetID on behalf of callerID (an administrator whose
// bearer the caller has already verified) in callerTenant (empty = the single
// household). In ONE write transaction it checks the tenant, rejects erasing
// the last admin in the tenant (counted inside the transaction), deletes the
// user, all sessions (full, partial, api-token), API tokens, passkeys, passkey
// sessions and TOTP rows, revokes the user's unredeemed invites and anonymises
// their created_by, and records the tombstone.
//
// Erasing an already tombstoned id in the caller's tenant returns the same
// erasure id. An unknown id, or one in another tenant, returns
// ErrUserNotFound. Self-erasure returns ErrSelfErasure.
func (s *Store) EraseUser(ctx context.Context, callerID, callerTenant, targetID string) (string, error) {
	callerTenant = strings.TrimSpace(callerTenant)
	if targetID == "" || len(targetID) > maxErasureUserIDLen {
		return "", ErrUserNotFound
	}
	if callerID == "" {
		return "", errors.New("erasing administrator is required")
	}
	if callerID == targetID {
		return "", ErrSelfErasure
	}
	erasureID, err := newErasureID()
	if err != nil {
		return "", err
	}
	if eraseHookBeforeTx != nil {
		eraseHookBeforeTx()
	}
	var result string
	err = s.writeTx(ctx, func(q sqlExecer) error {
		var username, tenantID, rolesJSON string
		err := q.QueryRowContext(ctx, `SELECT username, COALESCE(tenant_id, ''), roles FROM users WHERE id = ?`, targetID).
			Scan(&username, &tenantID, &rolesJSON)
		if errors.Is(err, sql.ErrNoRows) {
			// Idempotent repeat: the same tombstone, if it is in this tenant.
			var existing, existingTenant string
			err := q.QueryRowContext(ctx, `SELECT erasure_id, tenant_id FROM user_erasures WHERE user_id = ?`, targetID).
				Scan(&existing, &existingTenant)
			if errors.Is(err, sql.ErrNoRows) || (err == nil && existingTenant != callerTenant) {
				return ErrUserNotFound
			}
			if err != nil {
				return err
			}
			result = existing
			return nil
		}
		if err != nil {
			return err
		}
		if strings.TrimSpace(tenantID) != callerTenant {
			return ErrUserNotFound
		}
		if rolesHaveAdmin(rolesJSON) {
			admins, err := countTenantAdmins(ctx, q, callerTenant)
			if err != nil {
				return err
			}
			if admins <= 1 {
				return ErrLastAdmin
			}
		}
		if _, err := purgeUserRows(ctx, q, targetID, username); err != nil {
			return err
		}
		if _, err := q.ExecContext(ctx,
			`INSERT INTO user_erasures (erasure_id, user_id, tenant_id, deleted_at, deleted_by) VALUES (?, ?, ?, ?, ?)`,
			erasureID, targetID, callerTenant, formatErasureTime(time.Now()), callerID); err != nil {
			return fmt.Errorf("record tombstone: %w", err)
		}
		result = erasureID
		return nil
	})
	if err != nil {
		return "", err
	}
	return result, nil
}

func rolesHaveAdmin(rolesJSON string) bool {
	var roles []string
	if err := json.Unmarshal([]byte(rolesJSON), &roles); err != nil {
		return false
	}
	for _, r := range roles {
		if r == "admin" {
			return true
		}
	}
	return false
}

// countTenantAdmins counts users holding the exact "admin" role (the role every
// authorization check uses) in tenantID.
func countTenantAdmins(ctx context.Context, q sqlExecer, tenantID string) (int, error) {
	rows, err := q.QueryContext(ctx, `SELECT roles FROM users WHERE COALESCE(tenant_id, '') = ?`, tenantID)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var roles string
		if err := rows.Scan(&roles); err != nil {
			return 0, err
		}
		if rolesHaveAdmin(roles) {
			n++
		}
	}
	return n, rows.Err()
}

// purgeUserRows deletes every credential, session and identity row of userID
// and anonymises the invites created under username. It returns the number of
// rows changed. It runs inside the caller's write transaction.
func purgeUserRows(ctx context.Context, q sqlExecer, userID, username string) (int64, error) {
	var total int64
	exec := func(query string, args ...any) error {
		res, err := q.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		total += n
		return nil
	}
	for _, query := range []string{
		`DELETE FROM sessions WHERE user_id = ?`, // full, partial and api-token
		`DELETE FROM api_tokens WHERE user_id = ?`,
		`DELETE FROM webauthn_credentials WHERE user_id = ?`,
		`DELETE FROM webauthn_sessions WHERE user_id = ?`,
		`DELETE FROM totp WHERE user_id = ?`,
	} {
		if err := exec(query, userID); err != nil {
			return 0, fmt.Errorf("erase user rows: %w", err)
		}
	}
	if username != "" && username != DeletedUserMarker {
		now := time.Now().UTC().Format(time.RFC3339)
		if err := exec(`UPDATE invites SET revoked_at = ?
			WHERE created_by = ? AND revoked_at = '' AND (max_uses = 0 OR use_count < max_uses)`, now, username); err != nil {
			return 0, fmt.Errorf("revoke invites: %w", err)
		}
		if err := exec(`UPDATE invites SET created_by = ? WHERE created_by = ?`, DeletedUserMarker, username); err != nil {
			return 0, fmt.Errorf("anonymise invites: %w", err)
		}
	}
	if err := exec(`DELETE FROM users WHERE id = ?`, userID); err != nil {
		return 0, fmt.Errorf("erase user: %w", err)
	}
	return total, nil
}

// SweepTombstoned enforces "the tombstone wins" (ADR-0035 §4): it deletes every
// user, credential, session and token row whose user id is tombstoned, e.g.
// after a restore of an archive taken before the erasure. It returns the number
// of rows changed. It runs at every open and after an authctl import.
func (s *Store) SweepTombstoned(ctx context.Context) (int64, error) {
	var total int64
	err := s.writeTx(ctx, func(q sqlExecer) error {
		n, err := sweepTombstoned(ctx, q)
		total = n
		return err
	})
	return total, err
}

func sweepTombstoned(ctx context.Context, q sqlExecer) (int64, error) {
	rows, err := q.QueryContext(ctx, `SELECT u.id, u.username FROM users u JOIN user_erasures e ON e.user_id = u.id`)
	if err != nil {
		return 0, err
	}
	type victim struct{ id, username string }
	var victims []victim
	for rows.Next() {
		var v victim
		if err := rows.Scan(&v.id, &v.username); err != nil {
			_ = rows.Close()
			return 0, err
		}
		victims = append(victims, v)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	_ = rows.Close()
	var total int64
	for _, v := range victims {
		n, err := purgeUserRows(ctx, q, v.id, v.username)
		if err != nil {
			return 0, err
		}
		total += n
	}
	// Stray rows whose user row is already gone.
	for _, table := range []string{"sessions", "api_tokens", "webauthn_credentials", "webauthn_sessions", "totp"} {
		res, err := q.ExecContext(ctx, `DELETE FROM `+table+` WHERE user_id IN (SELECT user_id FROM user_erasures)`)
		if err != nil {
			return 0, fmt.Errorf("sweep %s: %w", table, err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// IsErased reports whether userID is tombstoned.
func (s *Store) IsErased(ctx context.Context, userID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM user_erasures WHERE user_id = ?`, userID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// --- Ledger (consumer modules) ---

type erasureCursor struct {
	Version   int    `json:"v"`
	DeletedAt string `json:"d"`
	ErasureID string `json:"e"`
	Tenant    string `json:"t,omitempty"`
	Pending   bool   `json:"p,omitempty"`
}

func normalizeErasurePageSize(n int) (int, error) {
	switch {
	case n == 0:
		return DefaultErasurePageSize, nil
	case n < 0 || n > MaxErasurePageSize:
		return 0, ErrInvalidErasurePage
	}
	return n, nil
}

// ListErasures returns one page of the whole ledger (every tenant), ordered by
// deleted_at then erasure_id. moduleID is the verified caller; it only sets
// AcknowledgedByCaller.
func (s *Store) ListErasures(ctx context.Context, moduleID string, pageSize int, pageToken string) ([]LedgerEntry, string, error) {
	size, err := normalizeErasurePageSize(pageSize)
	if err != nil {
		return nil, "", err
	}
	var cur erasureCursor
	if pageToken != "" {
		if cur, err = s.decodeErasureCursor(pageToken, erasureListCursorAAD); err != nil {
			return nil, "", err
		}
	}
	query := `SELECT e.erasure_id, e.user_id, e.tenant_id, e.deleted_at, e.deleted_by,
		EXISTS (SELECT 1 FROM erasure_acks a WHERE a.erasure_id = e.erasure_id AND a.module_id = ? AND a.outcome = 'OK')
		FROM user_erasures e`
	args := []any{moduleID}
	if pageToken != "" {
		query += ` WHERE (e.deleted_at > ? OR (e.deleted_at = ? AND e.erasure_id > ?))`
		args = append(args, cur.DeletedAt, cur.DeletedAt, cur.ErasureID)
	}
	query += ` ORDER BY e.deleted_at, e.erasure_id LIMIT ?`
	args = append(args, size+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()
	out := make([]LedgerEntry, 0, size+1)
	for rows.Next() {
		var e LedgerEntry
		var at string
		if err := rows.Scan(&e.ErasureID, &e.UserID, &e.TenantID, &at, &e.DeletedBy, &e.AcknowledgedByCaller); err != nil {
			return nil, "", err
		}
		if e.DeletedAt, err = parseErasureTime(at); err != nil {
			return nil, "", fmt.Errorf("invalid stored erasure time: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(out) <= size {
		return out, "", nil
	}
	out = out[:size]
	last := out[len(out)-1]
	next, err := s.encodeErasureCursor(erasureCursor{Version: 1, DeletedAt: formatErasureTime(last.DeletedAt), ErasureID: last.ErasureID}, erasureListCursorAAD)
	if err != nil {
		return nil, "", err
	}
	return out, next, nil
}

// AckErasure records moduleID's acknowledgement of erasureID. The most recent
// acknowledgement per (erasure, module) replaces the previous one; repeating
// it is idempotent. An unknown erasure id returns ErrErasureNotFound. Callers
// validate outcome, detail code and counts.
func (s *Store) AckErasure(ctx context.Context, erasureID, moduleID, outcome, detailCode string, counts map[string]int64) error {
	switch outcome {
	case ErasureOutcomeOK, ErasureOutcomeFailed, ErasureOutcomeUnsupported:
	default:
		return fmt.Errorf("invalid erasure outcome %q", outcome)
	}
	if moduleID == "" {
		return errors.New("acknowledging module is required")
	}
	if counts == nil {
		counts = map[string]int64{}
	}
	countsJSON, err := json.Marshal(counts)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO erasure_acks (erasure_id, module_id, outcome, detail_code, counts_json, acked_at)
		SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM user_erasures WHERE erasure_id = ?)
		ON CONFLICT(erasure_id, module_id) DO UPDATE SET outcome = excluded.outcome, detail_code = excluded.detail_code,
			counts_json = excluded.counts_json, acked_at = excluded.acked_at`,
		erasureID, moduleID, outcome, detailCode, string(countsJSON), formatErasureTime(time.Now()), erasureID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrErasureNotFound
	}
	return nil
}

// --- Status (administrators) ---

// requiredOKSQL returns a condition true when every module in required has an
// OK acknowledgement of e.erasure_id, plus its arguments.
func requiredOKSQL(required []string) (string, []any) {
	if len(required) == 0 {
		return `1`, nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(required)), ",")
	args := make([]any, 0, len(required)+1)
	for _, m := range required {
		args = append(args, m)
	}
	args = append(args, len(required))
	return `(SELECT COUNT(DISTINCT a.module_id) FROM erasure_acks a WHERE a.erasure_id = e.erasure_id
		AND a.outcome = 'OK' AND a.module_id IN (` + ph + `)) = ?`, args
}

// dedupe returns the non-empty values in order without duplicates.
func dedupe(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// ErasureStatuses reports erasures of tenantID with their acknowledgements.
// With erasureID set it returns exactly that erasure (ErrErasureNotFound if it
// is unknown in the tenant) and ignores the other arguments. Otherwise
// pendingOnly keeps erasures that some module in required has not
// acknowledged OK, paged by deleted_at then erasure_id.
func (s *Store) ErasureStatuses(ctx context.Context, tenantID, erasureID string, pendingOnly bool, required []string, pageSize int, pageToken string) ([]ErasureStatus, string, error) {
	tenantID = strings.TrimSpace(tenantID)
	required = dedupe(required)
	query := `SELECT e.erasure_id, e.deleted_at FROM user_erasures e WHERE e.tenant_id = ?`
	args := []any{tenantID}
	size := 1
	var err error
	if erasureID != "" {
		query += ` AND e.erasure_id = ?`
		args = append(args, erasureID)
	} else {
		if size, err = normalizeErasurePageSize(pageSize); err != nil {
			return nil, "", err
		}
		if pendingOnly {
			cond, condArgs := requiredOKSQL(required)
			query += ` AND NOT (` + cond + `)`
			args = append(args, condArgs...)
		}
		if pageToken != "" {
			cur, err := s.decodeErasureCursor(pageToken, erasureStatusCursorAD)
			if err != nil {
				return nil, "", err
			}
			if cur.Tenant != tenantID || cur.Pending != pendingOnly {
				return nil, "", ErrInvalidErasurePage
			}
			query += ` AND (e.deleted_at > ? OR (e.deleted_at = ? AND e.erasure_id > ?))`
			args = append(args, cur.DeletedAt, cur.DeletedAt, cur.ErasureID)
		}
		query += ` ORDER BY e.deleted_at, e.erasure_id LIMIT ?`
		args = append(args, size+1)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	var out []ErasureStatus
	for rows.Next() {
		var st ErasureStatus
		var at string
		if err := rows.Scan(&st.ErasureID, &at); err != nil {
			_ = rows.Close()
			return nil, "", err
		}
		if st.DeletedAt, err = parseErasureTime(at); err != nil {
			_ = rows.Close()
			return nil, "", fmt.Errorf("invalid stored erasure time: %w", err)
		}
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, "", err
	}
	_ = rows.Close()
	if erasureID != "" && len(out) == 0 {
		return nil, "", ErrErasureNotFound
	}
	next := ""
	if erasureID == "" && len(out) > size {
		out = out[:size]
		last := out[len(out)-1]
		next, err = s.encodeErasureCursor(erasureCursor{
			Version: 1, DeletedAt: formatErasureTime(last.DeletedAt), ErasureID: last.ErasureID,
			Tenant: tenantID, Pending: pendingOnly,
		}, erasureStatusCursorAD)
		if err != nil {
			return nil, "", err
		}
	}
	if err := s.loadErasureAcks(ctx, out); err != nil {
		return nil, "", err
	}
	return out, next, nil
}

func (s *Store) loadErasureAcks(ctx context.Context, statuses []ErasureStatus) error {
	if len(statuses) == 0 {
		return nil
	}
	index := make(map[string]int, len(statuses))
	args := make([]any, 0, len(statuses))
	for i, st := range statuses {
		index[st.ErasureID] = i
		args = append(args, st.ErasureID)
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
	rows, err := s.db.QueryContext(ctx, `SELECT erasure_id, module_id, outcome, detail_code, acked_at
		FROM erasure_acks WHERE erasure_id IN (`+ph+`) ORDER BY erasure_id, module_id`, args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, at string
		var a ErasureAck
		if err := rows.Scan(&id, &a.ModuleID, &a.Outcome, &a.DetailCode, &at); err != nil {
			return err
		}
		if a.AckedAt, err = parseErasureTime(at); err != nil {
			return fmt.Errorf("invalid stored ack time: %w", err)
		}
		if i, ok := index[id]; ok {
			statuses[i].Acks = append(statuses[i].Acks, a)
		}
	}
	return rows.Err()
}

func (s *Store) encodeErasureCursor(c erasureCursor, aad string) (string, error) {
	plain, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.box.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := s.box.aead.Seal(nonce, nonce, plain, []byte(aad))
	return erasureCursorPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *Store) decodeErasureCursor(token, aad string) (erasureCursor, error) {
	invalid := erasureCursor{}
	if len(token) > maxErasureCursorSize || !strings.HasPrefix(token, erasureCursorPrefix) {
		return invalid, ErrInvalidErasurePage
	}
	encoded := strings.TrimPrefix(token, erasureCursorPrefix)
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	n := s.box.aead.NonceSize()
	if err != nil || len(raw) < n+s.box.aead.Overhead() {
		return invalid, ErrInvalidErasurePage
	}
	plain, err := s.box.aead.Open(nil, raw[:n], raw[n:], []byte(aad))
	if err != nil {
		return invalid, ErrInvalidErasurePage
	}
	var c erasureCursor
	if err := json.Unmarshal(plain, &c); err != nil || c.Version != 1 || !ValidErasureID(c.ErasureID) {
		return invalid, ErrInvalidErasurePage
	}
	if _, err := parseErasureTime(c.DeletedAt); err != nil {
		return invalid, ErrInvalidErasurePage
	}
	return c, nil
}

// --- Offline export / import (authctl, ADR-0035 §4) ---

// Ledger is the portable tombstone ledger written by authctl erasures export.
// It contains no secrets and no usernames.
type Ledger struct {
	Version    int         `json:"version"`
	ExportedAt time.Time   `json:"exported_at"`
	Erasures   []Tombstone `json:"erasures"`
}

// LedgerVersion is the only Ledger.Version understood by ImportLedger.
const LedgerVersion = 1

// ExportLedger reads every tombstone from the auth-local database at path
// without modifying it (read-only open, no migrations). A database that
// predates the ledger exports an empty ledger.
func ExportLedger(ctx context.Context, path string) (*Ledger, error) {
	db, err := openExisting(path, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	ledger := &Ledger{Version: LedgerVersion, ExportedAt: time.Now().UTC(), Erasures: []Tombstone{}}
	var name string
	err = db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'user_erasures'`).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return ledger, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	rows, err := db.QueryContext(ctx, `SELECT erasure_id, user_id, tenant_id, deleted_at, deleted_by FROM user_erasures ORDER BY deleted_at, erasure_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var t Tombstone
		var at string
		if err := rows.Scan(&t.ErasureID, &t.UserID, &t.TenantID, &at, &t.DeletedBy); err != nil {
			return nil, err
		}
		if t.DeletedAt, err = parseErasureTime(at); err != nil {
			return nil, fmt.Errorf("invalid stored erasure time for %s: %w", t.ErasureID, err)
		}
		ledger.Erasures = append(ledger.Erasures, t)
	}
	return ledger, rows.Err()
}

// ImportResult summarises ImportLedger.
type ImportResult struct {
	Imported int
	Present  int
	Swept    int64
}

// ValidateLedger checks a ledger before import.
func ValidateLedger(l *Ledger) error {
	if l == nil || l.Version != LedgerVersion {
		return fmt.Errorf("unsupported ledger version")
	}
	seenE, seenU := map[string]string{}, map[string]string{}
	for i, t := range l.Erasures {
		if !ValidErasureID(t.ErasureID) {
			return fmt.Errorf("erasure %d: invalid erasure_id", i)
		}
		if t.UserID == "" || len(t.UserID) > maxErasureUserIDLen || strings.TrimSpace(t.UserID) != t.UserID {
			return fmt.Errorf("erasure %s: invalid user_id", t.ErasureID)
		}
		if len(t.TenantID) > maxErasureUserIDLen || len(t.DeletedBy) > maxErasureUserIDLen {
			return fmt.Errorf("erasure %s: field too long", t.ErasureID)
		}
		if t.DeletedAt.IsZero() {
			return fmt.Errorf("erasure %s: deleted_at is required", t.ErasureID)
		}
		if u, ok := seenE[t.ErasureID]; ok && u != t.UserID {
			return fmt.Errorf("%w: erasure %s names two users", ErrErasureConflict, t.ErasureID)
		}
		if e, ok := seenU[t.UserID]; ok && e != t.ErasureID {
			return fmt.Errorf("%w: a user has two erasure ids (%s, %s)", ErrErasureConflict, e, t.ErasureID)
		}
		seenE[t.ErasureID], seenU[t.UserID] = t.UserID, t.ErasureID
	}
	return nil
}

// ImportLedger merges l into the auth-local database at path, then enforces
// the tombstone over restored rows (SweepTombstoned) in the same transaction.
// It is idempotent. A tombstone whose erasure_id or user_id already appears in
// the database paired differently is a conflict: nothing is imported.
// The database must exist; it is migrated forward first (no secret key is
// needed). Run it only while auth-local is stopped.
func ImportLedger(ctx context.Context, path string, l *Ledger) (ImportResult, error) {
	var res ImportResult
	if err := ValidateLedger(l); err != nil {
		return res, err
	}
	db, err := openExisting(path, false)
	if err != nil {
		return res, err
	}
	s := &Store{db: db}
	defer func() { _ = db.Close() }()
	if err := s.migrate(); err != nil {
		return res, fmt.Errorf("migrate: %w", err)
	}
	err = s.writeTx(ctx, func(q sqlExecer) error {
		res = ImportResult{}
		for _, t := range l.Erasures {
			var userID, erasureID string
			err := q.QueryRowContext(ctx, `SELECT user_id FROM user_erasures WHERE erasure_id = ?`, t.ErasureID).Scan(&userID)
			switch {
			case err == nil && userID == t.UserID:
				res.Present++
				continue
			case err == nil:
				return fmt.Errorf("%w: erasure %s already names another user", ErrErasureConflict, t.ErasureID)
			case !errors.Is(err, sql.ErrNoRows):
				return err
			}
			err = q.QueryRowContext(ctx, `SELECT erasure_id FROM user_erasures WHERE user_id = ?`, t.UserID).Scan(&erasureID)
			if err == nil {
				return fmt.Errorf("%w: the user of erasure %s is already erased as %s", ErrErasureConflict, t.ErasureID, erasureID)
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if _, err := q.ExecContext(ctx, `INSERT INTO user_erasures (erasure_id, user_id, tenant_id, deleted_at, deleted_by) VALUES (?, ?, ?, ?, ?)`,
				t.ErasureID, t.UserID, strings.TrimSpace(t.TenantID), formatErasureTime(t.DeletedAt), t.DeletedBy); err != nil {
				return err
			}
			res.Imported++
		}
		n, err := sweepTombstoned(ctx, q)
		res.Swept = n
		return err
	})
	if err != nil {
		return ImportResult{}, err
	}
	return res, nil
}

func openExisting(path string, readOnly bool) (*sql.DB, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("database %s: %w", path, err)
	}
	dsn := path + "?_busy_timeout=5000"
	if readOnly {
		dsn = "file:" + path + "?mode=ro&_busy_timeout=5000"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func logSweep(n int64) {
	if n > 0 {
		slog.Warn("erasure: removed rows of tombstoned users (restored data; the tombstone wins)", "rows", n)
	}
}
