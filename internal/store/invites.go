package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Invite is a time-limited signup token (Wizarr-style).
type Invite struct {
	ID        string    `json:"id"`
	Token     string    `json:"token,omitempty"` // raw token — only set on create
	Prefix    string    `json:"prefix"`
	CreatedBy string    `json:"created_by"`
	Role      string    `json:"role"`
	TenantID  string    `json:"tenant_id,omitempty"`
	MaxUses   int       `json:"max_uses"` // 0 = unlimited
	UseCount  int       `json:"use_count"`
	ExpiresAt time.Time `json:"expires_at"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// MarshalJSON omits zero revoked_at.
func (inv Invite) MarshalJSON() ([]byte, error) {
	type alias struct {
		ID        string `json:"id"`
		Token     string `json:"token,omitempty"`
		Prefix    string `json:"prefix"`
		CreatedBy string `json:"created_by"`
		Role      string `json:"role"`
		TenantID  string `json:"tenant_id,omitempty"`
		MaxUses   int    `json:"max_uses"`
		UseCount  int    `json:"use_count"`
		ExpiresAt string `json:"expires_at"`
		RevokedAt string `json:"revoked_at,omitempty"`
		CreatedAt string `json:"created_at"`
	}
	a := alias{
		ID: inv.ID, Token: inv.Token, Prefix: inv.Prefix, CreatedBy: inv.CreatedBy,
		Role: inv.Role, TenantID: inv.TenantID, MaxUses: inv.MaxUses, UseCount: inv.UseCount,
		ExpiresAt: inv.ExpiresAt.UTC().Format(time.RFC3339),
		CreatedAt: inv.CreatedAt.UTC().Format(time.RFC3339),
	}
	if !inv.RevokedAt.IsZero() {
		a.RevokedAt = inv.RevokedAt.UTC().Format(time.RFC3339)
	}
	return json.Marshal(a)
}

func (s *Store) migrateInvites() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS invites (
			id          TEXT PRIMARY KEY,
			token_hash  TEXT UNIQUE NOT NULL,
			prefix      TEXT NOT NULL,
			created_by  TEXT NOT NULL DEFAULT '',
			role        TEXT NOT NULL DEFAULT 'user',
			max_uses    INTEGER NOT NULL DEFAULT 1,
			use_count   INTEGER NOT NULL DEFAULT 0,
			expires_at  TEXT NOT NULL,
			revoked_at  TEXT NOT NULL DEFAULT '',
			created_at  TEXT NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate invites: %w", err)
	}
	_, err = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_invites_hash ON invites(token_hash)`)
	return err
}

// CreateInvite creates a new invite. maxUses <= 0 means unlimited. ttl must be > 0.
// tenantID is copied onto users created via RedeemInvite (household tenancy).
func (s *Store) CreateInvite(createdBy, role, tenantID string, maxUses int, ttl time.Duration) (*Invite, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("ttl must be positive")
	}
	if role == "" {
		role = "user"
	}
	if maxUses < 0 {
		maxUses = 0
	}
	tenantID = strings.TrimSpace(tenantID)
	raw := "mci_" + newSessionToken()
	hash := sha256Hex(raw)
	prefix := raw
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	id := newID()
	now := time.Now().UTC()
	expires := now.Add(ttl)
	_, err := s.db.Exec(`
		INSERT INTO invites (id, token_hash, prefix, created_by, role, tenant_id, max_uses, use_count, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
	`, id, hash, prefix, createdBy, role, tenantID, maxUses,
		expires.Format(time.RFC3339), now.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("create invite: %w", err)
	}
	return &Invite{
		ID: id, Token: raw, Prefix: prefix, CreatedBy: createdBy, Role: role,
		TenantID: tenantID, MaxUses: maxUses, ExpiresAt: expires, CreatedAt: now,
	}, nil
}

// ListInvites returns all invites newest first (no raw tokens).
func (s *Store) ListInvites() ([]*Invite, error) {
	rows, err := s.db.Query(`
		SELECT id, prefix, created_by, role, COALESCE(tenant_id,''), max_uses, use_count, expires_at, revoked_at, created_at
		FROM invites ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Invite
	for rows.Next() {
		inv, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// RevokeInvite marks an invite revoked.
func (s *Store) RevokeInvite(id string) error {
	if id == "" {
		return fmt.Errorf("id is required")
	}
	res, err := s.db.Exec(`
		UPDATE invites SET revoked_at = ? WHERE id = ? AND revoked_at = ''
	`, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("invite not found or already revoked")
	}
	return nil
}

// RedeemInvite validates the token and creates a user with the invite role.
func (s *Store) RedeemInvite(rawToken, username, password string) (*User, *Invite, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, nil, fmt.Errorf("invite token is required")
	}
	if username == "" || password == "" {
		return nil, nil, fmt.Errorf("username and password are required")
	}
	hash := sha256Hex(rawToken)

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRow(`
		SELECT id, prefix, created_by, role, COALESCE(tenant_id,''), max_uses, use_count, expires_at, revoked_at, created_at
		FROM invites WHERE token_hash = ?
	`, hash)
	inv, err := scanInvite(row)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid invite token")
	}
	if !inv.RevokedAt.IsZero() {
		return nil, nil, fmt.Errorf("invite has been revoked")
	}
	if time.Now().After(inv.ExpiresAt) {
		return nil, nil, fmt.Errorf("invite has expired")
	}
	if inv.MaxUses > 0 && inv.UseCount >= inv.MaxUses {
		return nil, nil, fmt.Errorf("invite has no remaining uses")
	}

	pwHash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return nil, nil, fmt.Errorf("hash password: %w", err)
	}
	userID := newID()
	roles := []string{inv.Role}
	rolesJSON, _ := json.Marshal(roles)
	_, err = tx.Exec(
		`INSERT INTO users (id, username, password, roles, tenant_id) VALUES (?, ?, ?, ?, ?)`,
		userID, username, string(pwHash), string(rolesJSON), inv.TenantID,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create user: %w", err)
	}
	_, err = tx.Exec(`UPDATE invites SET use_count = use_count + 1 WHERE id = ?`, inv.ID)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	inv.UseCount++
	return &User{
		ID: userID, Username: username, Roles: roles, TenantID: inv.TenantID, CreatedAt: time.Now().UTC(),
	}, inv, nil
}

// PeekInvite returns invite metadata for a raw token without consuming it.
func (s *Store) PeekInvite(rawToken string) (*Invite, error) {
	hash := sha256Hex(strings.TrimSpace(rawToken))
	row := s.db.QueryRow(`
		SELECT id, prefix, created_by, role, COALESCE(tenant_id,''), max_uses, use_count, expires_at, revoked_at, created_at
		FROM invites WHERE token_hash = ?
	`, hash)
	inv, err := scanInvite(row)
	if err != nil {
		return nil, fmt.Errorf("invalid invite token")
	}
	if !inv.RevokedAt.IsZero() {
		return nil, fmt.Errorf("invite has been revoked")
	}
	if time.Now().After(inv.ExpiresAt) {
		return nil, fmt.Errorf("invite has expired")
	}
	if inv.MaxUses > 0 && inv.UseCount >= inv.MaxUses {
		return nil, fmt.Errorf("invite has no remaining uses")
	}
	return inv, nil
}

type inviteRowScanner interface {
	Scan(dest ...any) error
}

func scanInvite(row inviteRowScanner) (*Invite, error) {
	var inv Invite
	var expires, revoked, created string
	if err := row.Scan(
		&inv.ID, &inv.Prefix, &inv.CreatedBy, &inv.Role, &inv.TenantID, &inv.MaxUses, &inv.UseCount,
		&expires, &revoked, &created,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invite not found")
		}
		return nil, err
	}
	inv.ExpiresAt = parseTime(expires)
	if strings.TrimSpace(revoked) != "" {
		inv.RevokedAt = parseTime(revoked)
	}
	inv.CreatedAt = parseTime(created)
	return &inv, nil
}
