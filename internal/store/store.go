package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// bcryptCost is the password hashing cost. Only test binaries may lower it
// (SetPasswordHashCostForTesting); production always uses 12.
var bcryptCost = 12

// SetPasswordHashCostForTesting lowers the bcrypt cost so tests that create
// many users finish under the race detector. It panics outside a test binary,
// so it can never weaken production hashing. Call it from TestMain only.
func SetPasswordHashCostForTesting(cost int) {
	if !testing.Testing() {
		panic("store: SetPasswordHashCostForTesting called outside a test binary")
	}
	bcryptCost = max(cost, bcrypt.MinCost)
}

const sessionTTL = 24 * time.Hour

// User represents a user in the local auth store.
type User struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Password    string    `json:"-"`
	Roles       []string  `json:"roles"`
	TenantID    string    `json:"tenant_id,omitempty"`
	TOTPSecret  string    `json:"-"`
	TOTPEnabled bool      `json:"totp_enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// Claims returns auth claim map for session/JWT-style consumers (tenant.FromClaims).
func (u *User) Claims() map[string]any {
	if u == nil {
		return map[string]any{}
	}
	m := map[string]any{
		"sub":      u.ID,
		"user_id":  u.ID,
		"username": u.Username,
		"roles":    append([]string(nil), u.Roles...),
	}
	if tid := strings.TrimSpace(u.TenantID); tid != "" {
		m["tenant_id"] = tid
	}
	return m
}

// Session represents an authenticated session.
type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	Kind      string    `json:"kind"` // "full", "partial", "api-token"
	ExpiresAt time.Time `json:"expires_at"`
}

// Store manages users, sessions, and credentials in SQLite.
type Store struct {
	db  *sql.DB
	mu  sync.Mutex
	box *secretBox
}

// New opens or creates the SQLite database and runs migrations.
//
// TOTP secrets are encrypted at rest with AES-256-GCM; the key comes from
// AUTH_SECRET_KEY / AUTH_SECRET_KEY_FILE or an auto-generated key file next to
// the database (see LoadOrCreateKey).
func New(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	key, err := LoadOrCreateKey(dir)
	if err != nil {
		return nil, fmt.Errorf("secret key: %w", err)
	}
	return NewWithKey(path, key)
}

// NewWithKey is New with an explicit 32-byte secret key.
func NewWithKey(path string, key []byte) (*Store, error) {
	box, err := newSecretBox(key)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite single-writer

	s := &Store{db: db, box: box}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := s.migrateSessionTokens(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.migrateTOTPSecrets(); err != nil {
		_ = db.Close()
		return nil, err
	}
	// ADR-0035 §4: the tombstone wins over restored rows.
	swept, err := s.SweepTombstoned(context.Background())
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("erasure sweep: %w", err)
	}
	logSweep(swept)
	if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("chmod db: %w", err)
	}
	return s, nil
}

func (s *Store) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id         TEXT PRIMARY KEY,
			username   TEXT UNIQUE NOT NULL,
			password   TEXT NOT NULL,
			roles      TEXT NOT NULL DEFAULT '[]',
			totp_secret TEXT DEFAULT '',
			totp_enabled INTEGER DEFAULT 0,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token      TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL REFERENCES users(id),
			kind       TEXT NOT NULL DEFAULT 'full',
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			expires_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`,
		`CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id              TEXT PRIMARY KEY,
			user_id         TEXT NOT NULL REFERENCES users(id),
			public_key      BLOB NOT NULL,
			credential_type TEXT NOT NULL DEFAULT 'public-key',
			transports      TEXT DEFAULT '[]',
			aaguid          TEXT DEFAULT '',
			sign_count      INTEGER DEFAULT 0,
			created_at      TEXT NOT NULL DEFAULT (datetime('now')),
			last_used_at    TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id)`,
		`CREATE TABLE IF NOT EXISTS api_tokens (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL REFERENCES users(id),
			name       TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			prefix     TEXT NOT NULL,
			scopes     TEXT NOT NULL DEFAULT '[]',
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			expires_at TEXT DEFAULT '',
			last_used  TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id)`,
		`CREATE TABLE IF NOT EXISTS totp (
			user_id     TEXT PRIMARY KEY REFERENCES users(id),
			secret      TEXT NOT NULL,
			enabled     INTEGER NOT NULL DEFAULT 1,
			verified_at TEXT DEFAULT '',
			created_at  TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS webauthn_sessions (
			challenge   TEXT PRIMARY KEY,
			user_id     TEXT NOT NULL,
			data        BLOB NOT NULL,
			expires_at  TEXT NOT NULL
		)`,
	}
	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate query: %w", err)
		}
	}
	if err := s.migrateInvites(); err != nil {
		return err
	}
	if err := s.migrateTenantColumns(); err != nil {
		return err
	}
	if err := s.migrateErasures(); err != nil {
		return err
	}
	return s.migrateSessionIDs()
}

func (s *Store) migrateTenantColumns() error {
	for _, q := range []string{
		`ALTER TABLE users ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE invites ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, "duplicate column") || strings.Contains(msg, "already exists") {
				continue
			}
			return fmt.Errorf("migrate tenant columns: %w", err)
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// --- User CRUD ---

func (s *Store) CreateUser(username, password string) (*User, error) {
	return s.CreateUserTenant(username, password, "")
}

// CreateUserTenant creates a user bound to tenantID (empty = single-household / unset).
func (s *Store) CreateUserTenant(username, password, tenantID string) (*User, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if password == "" {
		return nil, fmt.Errorf("password is required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	id := newID()
	tenantID = strings.TrimSpace(tenantID)
	user := &User{
		ID:       id,
		Username: username,
		Password: string(hash),
		Roles:    []string{"user"},
		TenantID: tenantID,
	}
	rolesJSON, _ := json.Marshal(user.Roles)
	res, err := s.db.Exec(
		`INSERT INTO users (id, username, password, roles, tenant_id) SELECT ?, ?, ?, ?, ?`+notErasedClause,
		id, username, string(hash), string(rolesJSON), tenantID, id,
	)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrUserIDErased
	}
	return user, nil
}

func (s *Store) GetUserByUsername(username string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password, roles, COALESCE(tenant_id,''), totp_secret, totp_enabled, created_at FROM users WHERE username = ?`,
		username,
	)
	return s.scanUser(row)
}

func (s *Store) GetUser(id string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password, roles, COALESCE(tenant_id,''), totp_secret, totp_enabled, created_at FROM users WHERE id = ?`,
		id,
	)
	return s.scanUser(row)
}

func (s *Store) scanUser(row *sql.Row) (*User, error) {
	var u User
	var rolesJSON, totpSecret, createdAtStr string
	var totpEnabled int
	if err := row.Scan(&u.ID, &u.Username, &u.Password, &rolesJSON, &u.TenantID, &totpSecret, &totpEnabled, &createdAtStr); err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	if err := json.Unmarshal([]byte(rolesJSON), &u.Roles); err != nil {
		slog.Warn("corrupt roles data for user", "user_id", u.ID, "error", err)
	}
	plainSecret, err := s.box.decrypt(totpSecret)
	if err != nil {
		return nil, err
	}
	u.TOTPSecret = plainSecret
	u.TOTPEnabled = totpEnabled == 1
	u.CreatedAt = parseTime(createdAtStr)
	return &u, nil
}

func (s *Store) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(`SELECT id, username, roles, COALESCE(tenant_id,''), created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var users []*User
	for rows.Next() {
		var u User
		var rolesJSON, createdAtStr string
		if err := rows.Scan(&u.ID, &u.Username, &rolesJSON, &u.TenantID, &createdAtStr); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(rolesJSON), &u.Roles); err != nil {
			slog.Warn("corrupt roles data for user", "user_id", u.ID, "error", err)
		}
		u.CreatedAt = parseTime(createdAtStr)
		users = append(users, &u)
	}
	return users, nil
}

// SetTenantID updates a user's tenant binding.
func (s *Store) SetTenantID(id, tenantID string) error {
	_, err := s.db.Exec(`UPDATE users SET tenant_id = ? WHERE id = ?`, strings.TrimSpace(tenantID), id)
	return err
}

func (s *Store) SetPassword(id, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE users SET password = ? WHERE id = ?`, string(hash), id)
	return err
}

func (s *Store) SetRoles(id string, roles []string) error {
	rolesJSON, _ := json.Marshal(roles)
	_, err := s.db.Exec(`UPDATE users SET roles = ? WHERE id = ?`, string(rolesJSON), id)
	return err
}

// --- API Tokens ---

type APITokenInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Prefix    string    `json:"prefix"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
}

func (s *Store) CreateAPIToken(userID, name string, scopes []string) (string, *APITokenInfo, error) {
	if name == "" {
		return "", nil, fmt.Errorf("token name is required")
	}
	raw := "mct_" + newSessionToken()[:32]
	hash := sha256Hex(raw)
	prefix := raw[:12]
	id := newID()
	scopesJSON, _ := json.Marshal(scopes)

	res, err := s.db.Exec(
		`INSERT INTO api_tokens (id, user_id, name, token_hash, prefix, scopes) SELECT ?, ?, ?, ?, ?, ?`+notErasedClause,
		id, userID, name, hash, prefix, string(scopesJSON), userID,
	)
	if err != nil {
		return "", nil, fmt.Errorf("create token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", nil, ErrUserIDErased
	}

	return raw, &APITokenInfo{
		ID:        id,
		Name:      name,
		Prefix:    prefix,
		Scopes:    scopes,
		CreatedAt: time.Now(),
	}, nil
}

func (s *Store) ValidateAPIToken(rawToken string) (*Session, error) {
	hash := sha256Hex(rawToken)
	row := s.db.QueryRow(
		`SELECT id, user_id, name FROM api_tokens WHERE token_hash = ?`,
		hash,
	)
	var tokenID, userID, name string
	if err := row.Scan(&tokenID, &userID, &name); err != nil {
		return nil, fmt.Errorf("invalid API token")
	}

	// Create a transient session for the token.
	sess, err := s.CreateSession(userID, "api-token", 60*time.Second)
	if err != nil {
		return nil, err
	}

	// Update last_used.
	_, _ = s.db.Exec(`UPDATE api_tokens SET last_used = datetime('now') WHERE id = ?`, tokenID)
	return sess, nil
}

func (s *Store) ListAPITokens(userID string) ([]*APITokenInfo, error) {
	rows, err := s.db.Query(
		`SELECT id, name, prefix, scopes, created_at, COALESCE(last_used, '') FROM api_tokens WHERE user_id = ? ORDER BY created_at`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var tokens []*APITokenInfo
	for rows.Next() {
		t := &APITokenInfo{}
		var scopesJSON, createdAtStr, lastUsedStr string
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &scopesJSON, &createdAtStr, &lastUsedStr); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(scopesJSON), &t.Scopes); err != nil {
			slog.Warn("corrupt scopes data for API token", "token_id", t.ID, "error", err)
		}
		t.CreatedAt = parseTime(createdAtStr)
		t.LastUsed = parseTime(lastUsedStr)
		tokens = append(tokens, t)
	}
	return tokens, nil
}

func (s *Store) DeleteAPIToken(id string) error {
	_, err := s.db.Exec(`DELETE FROM api_tokens WHERE id = ?`, id)
	return err
}

// APITokenUserID returns the owning user ID for an API token.
func (s *Store) APITokenUserID(id string) (string, error) {
	var userID string
	err := s.db.QueryRow(`SELECT user_id FROM api_tokens WHERE id = ?`, id).Scan(&userID)
	if err != nil {
		return "", err
	}
	return userID, nil
}

// --- Password Authentication ---

func (s *Store) VerifyPassword(username, password string) (*User, error) {
	user, err := s.GetUserByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("invalid username or password")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid username or password")
	}
	return user, nil
}

// --- Sessions ---

func (s *Store) CreateSession(userID, kind string, ttl time.Duration) (*Session, error) {
	token := newSessionToken()
	sessionID, err := newManagementSessionID()
	if err != nil {
		return nil, fmt.Errorf("create session ID: %w", err)
	}
	expiresAt := time.Now().Add(ttl)
	res, err := s.db.Exec(
		`INSERT INTO sessions (token, session_id, user_id, kind, expires_at) SELECT ?, ?, ?, ?, ?`+notErasedClause,
		hashSessionToken(token), sessionID, userID, kind, expiresAt.Format(time.RFC3339), userID,
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrUserIDErased
	}
	return &Session{Token: token, UserID: userID, Kind: kind, ExpiresAt: expiresAt}, nil
}

func (s *Store) CreateFullSession(userID string) (*Session, error) {
	return s.CreateSession(userID, "full", sessionTTL)
}

func (s *Store) CreatePartialSession(userID string) (*Session, error) {
	return s.CreateSession(userID, "partial", 5*time.Minute)
}

func (s *Store) GetSession(token string) (*Session, error) {
	row := s.db.QueryRow(
		`SELECT user_id, kind, expires_at FROM sessions WHERE token = ?`,
		hashSessionToken(token),
	)
	var sess Session
	sess.Token = token // the caller's own raw token; only its hash is stored
	var expiresAt string
	if err := row.Scan(&sess.UserID, &sess.Kind, &expiresAt); err != nil {
		return nil, fmt.Errorf("session not found")
	}
	sess.ExpiresAt = parseTime(expiresAt)
	if sess.ExpiresAt.IsZero() {
		slog.Warn("session has unparseable expiration, treating as expired", "user_id", sess.UserID)
		_ = s.DeleteSession(token)
		return nil, fmt.Errorf("session expired")
	}
	if time.Now().After(sess.ExpiresAt) {
		_ = s.DeleteSession(token)
		return nil, fmt.Errorf("session expired")
	}
	return &sess, nil
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token = ?`, hashSessionToken(token))
	return err
}

func (s *Store) DeleteUserSessions(userID string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

func (s *Store) UpgradeSession(partialToken string) (*Session, error) {
	sess, err := s.GetSession(partialToken)
	if err != nil {
		return nil, err
	}
	if sess.Kind != "partial" {
		return nil, fmt.Errorf("session is not a partial token")
	}
	// Delete the partial session, create a full one.
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE token = ?`, hashSessionToken(partialToken))
	return s.CreateFullSession(sess.UserID)
}

// --- TOTP ---

func (s *Store) SetTOTPSecret(userID, secret string) error {
	enc, err := s.box.encrypt(secret)
	if err != nil {
		return fmt.Errorf("encrypt totp secret: %w", err)
	}
	res, err := s.db.Exec(
		`INSERT OR REPLACE INTO totp (user_id, secret, enabled, created_at) SELECT ?, ?, 1, datetime('now')`+notErasedClause,
		userID, enc, userID,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserIDErased
	}
	return nil
}

func (s *Store) GetTOTPSecret(userID string) (string, bool, error) {
	row := s.db.QueryRow(`SELECT secret, enabled FROM totp WHERE user_id = ?`, userID)
	var secret string
	var enabled int
	if err := row.Scan(&secret, &enabled); err != nil {
		return "", false, nil // not found = not enabled
	}
	plain, err := s.box.decrypt(secret)
	if err != nil {
		return "", false, err
	}
	return plain, enabled == 1, nil
}

func (s *Store) VerifyTOTPSetup(userID string) error {
	_, err := s.db.Exec(`UPDATE totp SET verified_at = datetime('now') WHERE user_id = ?`, userID)
	return err
}

func (s *Store) DisableTOTP(userID string) error {
	_, err := s.db.Exec(`DELETE FROM totp WHERE user_id = ?`, userID)
	if err != nil {
		return err
	}
	// Also update the users table flag for quick checks.
	_, err = s.db.Exec(`UPDATE users SET totp_secret = '', totp_enabled = 0 WHERE id = ?`, userID)
	return err
}

// --- WebAuthn ---

type WebAuthnSessionData struct {
	Challenge        string    `json:"challenge"`
	UserID           string    `json:"user_id"`
	AllowedCreds     [][]byte  `json:"allowed_creds"`
	ExpiresAt        time.Time `json:"expires_at"`
	RelyingPartyID   string    `json:"rp_id"`
	UserVerification string    `json:"user_verification"`
}

func (s *Store) SaveWebAuthnSession(userID, challenge string, data []byte) error {
	res, err := s.db.Exec(
		`INSERT INTO webauthn_sessions (challenge, user_id, data, expires_at) SELECT ?, ?, ?, datetime('now', '+5 minutes')`+notErasedClause+`
		 ON CONFLICT(challenge) DO UPDATE SET data = excluded.data`,
		challenge, userID, data, userID,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserIDErased
	}
	return nil
}

func (s *Store) GetWebAuthnSession(challenge string) ([]byte, error) {
	row := s.db.QueryRow(
		`SELECT data FROM webauthn_sessions WHERE challenge = ? AND expires_at > datetime('now')`,
		challenge,
	)
	var data []byte
	if err := row.Scan(&data); err != nil {
		return nil, fmt.Errorf("webauthn session not found or expired")
	}
	return data, nil
}

func (s *Store) DeleteWebAuthnSession(challenge string) error {
	_, err := s.db.Exec(`DELETE FROM webauthn_sessions WHERE challenge = ?`, challenge)
	return err
}

func (s *Store) AddWebAuthnCredential(userID string, data []byte) error {
	// Generate a unique ID for the credential row using SHA-256 of the data.
	id := sha256.Sum256(data)
	if erased, err := s.IsErased(context.Background(), userID); err != nil {
		return err
	} else if erased {
		return ErrUserIDErased
	}
	_, err := s.db.Exec(
		`INSERT INTO webauthn_credentials (id, user_id, public_key, created_at) SELECT ?, ?, ?, datetime('now')`+notErasedClause+`
		 ON CONFLICT(id) DO NOTHING`,
		hex.EncodeToString(id[:]), userID, data, userID,
	)
	return err
}

func (s *Store) ListWebAuthnCredentials(userID string) ([][]byte, error) {
	rows, err := s.db.Query(`SELECT public_key FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var creds [][]byte
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		creds = append(creds, data)
	}
	return creds, nil
}

type WebAuthnCredentialInfo struct {
	ID             string    `json:"id"`
	CredentialType string    `json:"credential_type"`
	Transports     string    `json:"transports"`
	AAGUID         string    `json:"aaguid"`
	CreatedAt      time.Time `json:"created_at"`
	LastUsedAt     time.Time `json:"last_used_at"`
}

func (s *Store) ListWebAuthnCredentialMeta(userID string) ([]WebAuthnCredentialInfo, error) {
	rows, err := s.db.Query(
		`SELECT id, credential_type, transports, aaguid, created_at, COALESCE(last_used_at, '') FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var infos []WebAuthnCredentialInfo
	for rows.Next() {
		var info WebAuthnCredentialInfo
		var createdStr, lastUsedStr string
		if err := rows.Scan(&info.ID, &info.CredentialType, &info.Transports, &info.AAGUID, &createdStr, &lastUsedStr); err != nil {
			return nil, err
		}
		info.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
		info.LastUsedAt, _ = time.Parse("2006-01-02 15:04:05", lastUsedStr)
		infos = append(infos, info)
	}
	return infos, nil
}

func (s *Store) WebAuthnCredentialCount(userID string) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, userID).Scan(&count)
	return count, err
}

func (s *Store) DeleteWebAuthnCredential(userID, credentialID string) error {
	_, err := s.db.Exec(`DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`, credentialID, userID)
	return err
}

func (s *Store) DeleteAllWebAuthnCredentials(userID string) error {
	_, err := s.db.Exec(`DELETE FROM webauthn_credentials WHERE user_id = ?`, userID)
	return err
}

// Ping checks database connectivity.
func (s *Store) Ping() error {
	return s.db.Ping()
}

// SessionCount returns the number of active (non-expired) sessions.
func (s *Store) SessionCount() int {
	var count int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now')`).Scan(&count)
	return count
}

// --- Cleanup ---

func (s *Store) CleanupExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < datetime('now')`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM webauthn_sessions WHERE expires_at < datetime('now')`)
	return err
}

// --- Helpers ---

func newSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// newID returns a random 128-bit hex id. It is a variable only so tests can
// force a collision with a tombstoned id.
var newID = func() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// sessionHashPrefix marks a stored session token as sha256(raw) hex; anything
// else in sessions.token is a legacy plaintext token migrated on open.
const sessionHashPrefix = "h1:"

func hashSessionToken(raw string) string { return sessionHashPrefix + sha256Hex(raw) }

// migrateSessionTokens hashes legacy plaintext session tokens in place
// (idempotent) so existing sessions stay valid.
func (s *Store) migrateSessionTokens() error {
	rows, err := s.db.Query(`SELECT token FROM sessions WHERE token NOT LIKE 'h1:%'`)
	if err != nil {
		return fmt.Errorf("scan sessions: %w", err)
	}
	var plain []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			_ = rows.Close()
			return err
		}
		plain = append(plain, t)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	for _, t := range plain {
		if _, err := s.db.Exec(`UPDATE sessions SET token = ? WHERE token = ?`, hashSessionToken(t), t); err != nil {
			return fmt.Errorf("hash session token: %w", err)
		}
	}
	return nil
}

// sha256Hex returns the hex-encoded SHA-256 hash of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// parseTime parses a SQLite datetime string with the format used by
// datetime('now') and RFC3339. Returns zero time on parse failure.
func parseTime(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
		if err != nil {
			slog.Warn("failed to parse timestamp", "value", s, "error", err)
			return time.Time{}
		}
	}
	return t
}
