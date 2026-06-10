package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite" // sqlite driver registration
)

const bcryptCost = 12
const sessionTTL = 24 * time.Hour

// User represents a user in the local auth store.
type User struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Password    string    `json:"-"`
	Roles       []string  `json:"roles"`
	TOTPSecret  string    `json:"-"`
	TOTPEnabled bool      `json:"totp_enabled"`
	CreatedAt   time.Time `json:"created_at"`
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
	db       *sql.DB
	mu       sync.Mutex
}

// New opens or creates the SQLite database and runs migrations.
func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite single-writer

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
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
	}
	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate query: %w", err)
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// --- User CRUD ---

func (s *Store) CreateUser(username, password string) (*User, error) {
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
	user := &User{
		ID:       id,
		Username: username,
		Password: string(hash),
		Roles:    []string{"user"},
	}
	rolesJSON, _ := json.Marshal(user.Roles)
	_, err = s.db.Exec(
		`INSERT INTO users (id, username, password, roles) VALUES (?, ?, ?, ?)`,
		id, username, string(hash), string(rolesJSON),
	)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func (s *Store) GetUserByUsername(username string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password, roles, totp_secret, totp_enabled, created_at FROM users WHERE username = ?`,
		username,
	)
	var u User
	var rolesJSON, totpSecret, createdAtStr string
	var totpEnabled int
	if err := row.Scan(&u.ID, &u.Username, &u.Password, &rolesJSON, &totpSecret, &totpEnabled, &createdAtStr); err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	json.Unmarshal([]byte(rolesJSON), &u.Roles)
	u.TOTPSecret = totpSecret
	u.TOTPEnabled = totpEnabled == 1
	u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
	return &u, nil
}

func (s *Store) GetUser(id string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password, roles, totp_secret, totp_enabled, created_at FROM users WHERE id = ?`,
		id,
	)
	var u User
	var rolesJSON, totpSecret, createdAtStr string
	var totpEnabled int
	if err := row.Scan(&u.ID, &u.Username, &u.Password, &rolesJSON, &totpSecret, &totpEnabled, &createdAtStr); err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	json.Unmarshal([]byte(rolesJSON), &u.Roles)
	u.TOTPSecret = totpSecret
	u.TOTPEnabled = totpEnabled == 1
	u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
	return &u, nil
}

func (s *Store) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(`SELECT id, username, roles, created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var u User
		var rolesJSON, createdAtStr string
		if err := rows.Scan(&u.ID, &u.Username, &rolesJSON, &createdAtStr); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(rolesJSON), &u.Roles)
		u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
		users = append(users, &u)
	}
	return users, nil
}

func (s *Store) DeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, id)
	tx.Exec(`DELETE FROM webauthn_credentials WHERE user_id = ?`, id)
	tx.Exec(`DELETE FROM api_tokens WHERE user_id = ?`, id)
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
	return err
}

func (s *Store) SetRoles(id string, roles []string) error {
	rolesJSON, _ := json.Marshal(roles)
	_, err := s.db.Exec(`UPDATE users SET roles = ? WHERE id = ?`, string(rolesJSON), id)
	return err
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
	expiresAt := time.Now().Add(ttl)
	_, err := s.db.Exec(
		`INSERT INTO sessions (token, user_id, kind, expires_at) VALUES (?, ?, ?, ?)`,
		token, userID, kind, expiresAt.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
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
		`SELECT token, user_id, kind, expires_at FROM sessions WHERE token = ?`,
		token,
	)
	var sess Session
	var expiresAt string
	if err := row.Scan(&sess.Token, &sess.UserID, &sess.Kind, &expiresAt); err != nil {
		return nil, fmt.Errorf("session not found")
	}
	sess.ExpiresAt, _ = time.Parse("2006-01-02 15:04:05", expiresAt)
	// Also try RFC3339 for legacy entries.
	if sess.ExpiresAt.IsZero() {
		sess.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	}
	if time.Now().After(sess.ExpiresAt) {
		s.DeleteSession(token)
		return nil, fmt.Errorf("session expired")
	}
	return &sess, nil
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
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
	s.db.Exec(`DELETE FROM sessions WHERE token = ?`, partialToken)
	return s.CreateFullSession(sess.UserID)
}

// --- Cleanup ---

func (s *Store) CleanupExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < datetime('now')`)
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
