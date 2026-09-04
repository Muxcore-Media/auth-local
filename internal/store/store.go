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
	"strings"
	"sync"
	"time"

	"github.com/Muxcore-Media/auth-local/internal/revocation"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const bcryptCost = 12
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
	Token          string    `json:"token"`
	UserID         string    `json:"user_id"`
	Kind           string    `json:"kind"` // "full", "partial", "api-token"
	ExpiresAt      time.Time `json:"expires_at"`
	LastActivityAt time.Time `json:"last_activity_at,omitempty"`
	BoundIP        string    `json:"bound_ip,omitempty"`
	BoundUA        string    `json:"bound_ua,omitempty"`
	Device         string    `json:"device,omitempty"`
	Browser        string    `json:"browser,omitempty"`
	Location       string    `json:"location,omitempty"`
}

// Store manages users, sessions, and credentials in SQLite.
type Store struct {
	db            *sql.DB
	mu            sync.Mutex
	sessionConfig SessionConfig
	revocations   *revocation.List
}

// New opens or creates the SQLite database and runs migrations.
func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite single-writer

	s := &Store{
		db:            db,
		sessionConfig: DefaultSessionConfig(),
	}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
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
	if err := s.migrateSessionColumns(); err != nil {
		return err
	}
	if err := s.migrateSessionFingerprintColumns(); err != nil {
		return err
	}
	return nil
}

func (s *Store) migrateSessionColumns() error {
	for _, q := range []string{
		`ALTER TABLE sessions ADD COLUMN last_activity_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sessions ADD COLUMN bound_ip TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sessions ADD COLUMN bound_ua TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, "duplicate column") || strings.Contains(msg, "already exists") {
				continue
			}
			return fmt.Errorf("migrate session columns: %w", err)
		}
	}
	return nil
}

func (s *Store) migrateSessionFingerprintColumns() error {
	for _, q := range []string{
		`ALTER TABLE sessions ADD COLUMN device TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sessions ADD COLUMN browser TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sessions ADD COLUMN location TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, "duplicate column") || strings.Contains(msg, "already exists") {
				continue
			}
			return fmt.Errorf("migrate session fingerprint columns: %w", err)
		}
	}
	return nil
}

// SetRevocationList attaches a token revocation list checked on every session lookup.
func (s *Store) SetRevocationList(list *revocation.List) {
	s.revocations = list
}

// RevocationCount returns active entries in the revocation list.
func (s *Store) RevocationCount() int {
	if s.revocations == nil {
		return 0
	}
	return s.revocations.Count()
}

// SetSessionConfig replaces session TTL, idle timeout, and binding options.
func (s *Store) SetSessionConfig(cfg SessionConfig) {
	if cfg.TTL <= 0 {
		cfg.TTL = sessionTTL
	}
	s.sessionConfig = cfg
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

// Ping verifies the SQLite connection is alive.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

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
	_, err = s.db.Exec(
		`INSERT INTO users (id, username, password, roles, tenant_id) VALUES (?, ?, ?, ?, ?)`,
		id, username, string(hash), string(rolesJSON), tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func (s *Store) GetUserByUsername(username string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password, roles, COALESCE(tenant_id,''), totp_secret, totp_enabled, created_at FROM users WHERE username = ?`,
		username,
	)
	return scanUser(row)
}

func (s *Store) GetUser(id string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password, roles, COALESCE(tenant_id,''), totp_secret, totp_enabled, created_at FROM users WHERE id = ?`,
		id,
	)
	return scanUser(row)
}

func scanUser(row *sql.Row) (*User, error) {
	var u User
	var rolesJSON, totpSecret, createdAtStr string
	var totpEnabled int
	if err := row.Scan(&u.ID, &u.Username, &u.Password, &rolesJSON, &u.TenantID, &totpSecret, &totpEnabled, &createdAtStr); err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	if err := json.Unmarshal([]byte(rolesJSON), &u.Roles); err != nil {
		slog.Warn("corrupt roles data for user", "user_id", u.ID, "error", err)
	}
	u.TOTPSecret = totpSecret
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

func (s *Store) DeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM webauthn_credentials WHERE user_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM api_tokens WHERE user_id = ?`, id); err != nil {
		return err
	}
	result, err := tx.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return tx.Commit()
}

func (s *Store) SetPassword(id, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE users SET password = ? WHERE id = ?`, string(hash), id)
	if err != nil {
		return err
	}
	return s.DeleteUserSessions(id)
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

	_, err := s.db.Exec(
		`INSERT INTO api_tokens (id, user_id, name, token_hash, prefix, scopes) VALUES (?, ?, ?, ?, ?, ?)`,
		id, userID, name, hash, prefix, string(scopesJSON),
	)
	if err != nil {
		return "", nil, fmt.Errorf("create token: %w", err)
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
	sess, err := s.CreateSession(userID, "api-token", 60*time.Second, SessionMeta{})
	if err != nil {
		return nil, err
	}

	// Update last_used.
	_, _ = s.db.Exec(`UPDATE api_tokens SET last_used = datetime('now') WHERE id = ?`, tokenID)
	return sess, nil
}

func (s *Store) ListAPITokens(userID string) ([]*APITokenInfo, error) {
	rows, err := s.db.Query(
		`SELECT id, name, prefix, scopes, created_at FROM api_tokens WHERE user_id = ? ORDER BY created_at`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var tokens []*APITokenInfo
	for rows.Next() {
		t := &APITokenInfo{}
		var scopesJSON, createdAtStr string
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &scopesJSON, &createdAtStr); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(scopesJSON), &t.Scopes); err != nil {
			slog.Warn("corrupt scopes data for API token", "token_id", t.ID, "error", err)
		}
		t.CreatedAt = parseTime(createdAtStr)
		tokens = append(tokens, t)
	}
	return tokens, nil
}

func (s *Store) DeleteAPIToken(id string) error {
	_, err := s.db.Exec(`DELETE FROM api_tokens WHERE id = ?`, id)
	return err
}

func (s *Store) APITokenUserID(id string) (string, error) {
	var userID string
	err := s.db.QueryRow(`SELECT user_id FROM api_tokens WHERE id = ?`, id).Scan(&userID)
	if err != nil {
		return "", fmt.Errorf("token not found")
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

func (s *Store) CreateSession(userID, kind string, ttl time.Duration, meta SessionMeta) (*Session, error) {
	token := newSessionToken()
	hash := sha256Hex(token)
	now := time.Now()
	expiresAt := now.Add(ttl)
	boundIP, boundUA := "", ""
	device, browser, location := "", "", ""
	if s.sessionConfig.BindIP && strings.TrimSpace(meta.IP) != "" {
		boundIP = strings.TrimSpace(meta.IP)
	}
	if s.sessionConfig.BindUA && strings.TrimSpace(meta.UserAgent) != "" {
		boundUA = strings.TrimSpace(meta.UserAgent)
	}
	device = strings.TrimSpace(meta.Device)
	browser = strings.TrimSpace(meta.Browser)
	location = strings.TrimSpace(meta.Location)
	_, err := s.db.Exec(
		`INSERT INTO sessions (token, user_id, kind, expires_at, last_activity_at, bound_ip, bound_ua, device, browser, location) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		hash, userID, kind, expiresAt.Format(time.RFC3339), now.Format(time.RFC3339), boundIP, boundUA, device, browser, location,
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return &Session{
		Token:          token,
		UserID:         userID,
		Kind:           kind,
		ExpiresAt:      expiresAt,
		LastActivityAt: now,
		BoundIP:        boundIP,
		BoundUA:        boundUA,
		Device:         device,
		Browser:        browser,
		Location:       location,
	}, nil
}

func (s *Store) CreateFullSession(userID string, meta ...SessionMeta) (*Session, error) {
	m := SessionMeta{}
	if len(meta) > 0 {
		m = meta[0]
	}
	ttl := s.sessionConfig.TTL
	if ttl <= 0 {
		ttl = sessionTTL
	}
	return s.CreateSession(userID, "full", ttl, m)
}

func (s *Store) CreatePartialSession(userID string, meta ...SessionMeta) (*Session, error) {
	m := SessionMeta{}
	if len(meta) > 0 {
		m = meta[0]
	}
	return s.CreateSession(userID, "partial", 5*time.Minute, m)
}

func (s *Store) GetSession(token string, check ...SessionCheck) (*Session, error) {
	hash := sha256Hex(token)
	if s.revocations != nil && s.revocations.Contains(hash) {
		return nil, fmt.Errorf("session revoked")
	}
	row := s.db.QueryRow(
		`SELECT token, user_id, kind, expires_at, COALESCE(last_activity_at,''), COALESCE(bound_ip,''), COALESCE(bound_ua,''), COALESCE(device,''), COALESCE(browser,''), COALESCE(location,'') FROM sessions WHERE token = ?`,
		hash,
	)
	var sess Session
	var storedToken, expiresAt, lastActivityAt, boundIP, boundUA, device, browser, location string
	if err := row.Scan(&storedToken, &sess.UserID, &sess.Kind, &expiresAt, &lastActivityAt, &boundIP, &boundUA, &device, &browser, &location); err != nil {
		return nil, fmt.Errorf("session not found")
	}
	sess.Token = token
	sess.ExpiresAt = parseTime(expiresAt)
	sess.LastActivityAt = parseTime(lastActivityAt)
	sess.BoundIP = boundIP
	sess.BoundUA = boundUA
	sess.Device = device
	sess.Browser = browser
	sess.Location = location
	if sess.ExpiresAt.IsZero() {
		slog.Warn("session has unparseable expiration, treating as expired", "token", token[:8])
		_ = s.DeleteSession(token)
		return nil, fmt.Errorf("session expired")
	}
	if time.Now().After(sess.ExpiresAt) {
		_ = s.DeleteSession(token)
		return nil, fmt.Errorf("session expired")
	}
	if s.sessionConfig.IdleTimeout > 0 {
		last := sess.LastActivityAt
		if last.IsZero() {
			last = sess.ExpiresAt.Add(-s.sessionConfig.TTL)
		}
		if time.Since(last) > s.sessionConfig.IdleTimeout {
			_ = s.DeleteSession(token)
			return nil, fmt.Errorf("session idle timeout")
		}
	}
	var chk SessionCheck
	if len(check) > 0 {
		chk = check[0]
	}
	if sess.BoundIP != "" && chk.IP != "" && sess.BoundIP != strings.TrimSpace(chk.IP) {
		return nil, fmt.Errorf("session ip binding mismatch")
	}
	if sess.BoundUA != "" && chk.UserAgent != "" && sess.BoundUA != strings.TrimSpace(chk.UserAgent) {
		return nil, fmt.Errorf("session user-agent binding mismatch")
	}
	if chk.TouchIdle {
		now := time.Now()
		_, _ = s.db.Exec(`UPDATE sessions SET last_activity_at = ? WHERE token = ?`, now.Format(time.RFC3339), hash)
		sess.LastActivityAt = now
	}
	return &sess, nil
}

func (s *Store) DeleteSession(token string) error {
	hash := sha256Hex(token)
	retain := s.sessionConfig.TTL
	if retain <= 0 {
		retain = sessionTTL
	}
	if s.revocations != nil {
		s.revocations.Add(hash, retain)
	}
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token = ?`, hash)
	return err
}

func (s *Store) DeleteUserSessions(userID string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

func (s *Store) UpgradeSession(partialToken string, meta ...SessionMeta) (*Session, error) {
	sess, err := s.GetSession(partialToken)
	if err != nil {
		return nil, err
	}
	if sess.Kind != "partial" {
		return nil, fmt.Errorf("session is not a partial token")
	}
	m := SessionMeta{IP: sess.BoundIP, UserAgent: sess.BoundUA, Device: sess.Device, Browser: sess.Browser, Location: sess.Location}
	if len(meta) > 0 {
		if meta[0].IP != "" {
			m.IP = meta[0].IP
		}
		if meta[0].UserAgent != "" {
			m.UserAgent = meta[0].UserAgent
		}
		if meta[0].Device != "" {
			m.Device = meta[0].Device
		}
		if meta[0].Browser != "" {
			m.Browser = meta[0].Browser
		}
		if meta[0].Location != "" {
			m.Location = meta[0].Location
		}
	}
	// Delete the partial session, create a full one.
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE token = ?`, sha256Hex(partialToken))
	return s.CreateFullSession(sess.UserID, m)
}

// --- TOTP ---

func (s *Store) SetTOTPSecret(userID, secret string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO totp (user_id, secret, enabled, verified_at, created_at) VALUES (?, ?, 0, '', datetime('now'))`,
		userID, secret,
	)
	return err
}

func (s *Store) GetTOTPSecret(userID string) (string, bool, error) {
	row := s.db.QueryRow(`SELECT secret, enabled, COALESCE(verified_at, '') FROM totp WHERE user_id = ?`, userID)
	var secret, verifiedAt string
	var enabled int
	if err := row.Scan(&secret, &enabled, &verifiedAt); err != nil {
		return "", false, nil // not found = not enabled
	}
	loginRequired := enabled == 1 && strings.TrimSpace(verifiedAt) != ""
	return secret, loginRequired, nil
}

func (s *Store) VerifyTOTPSetup(userID string) error {
	_, err := s.db.Exec(`UPDATE totp SET enabled = 1, verified_at = datetime('now') WHERE user_id = ?`, userID)
	return err
}

func (s *Store) DisableTOTP(userID string) error {
	if err := s.DeleteUserSessions(userID); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM totp WHERE user_id = ?`, userID)
	if err != nil {
		return err
	}
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
	_, err := s.db.Exec(
		`INSERT INTO webauthn_sessions (challenge, user_id, data, expires_at) VALUES (?, ?, ?, datetime('now', '+5 minutes'))
		 ON CONFLICT(challenge) DO UPDATE SET data = excluded.data`,
		challenge, userID, data,
	)
	return err
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
	_, err := s.db.Exec(
		`INSERT INTO webauthn_credentials (id, user_id, public_key, created_at) VALUES (?, ?, ?, datetime('now'))
		 ON CONFLICT(id) DO NOTHING`,
		hex.EncodeToString(id[:]), userID, data,
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

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
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
