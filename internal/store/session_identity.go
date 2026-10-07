package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrInvalidSession means the bearer definitively cannot authenticate. Storage
// and decoding failures must not be classified as invalid credentials: callers
// may need to retain their local cookie while the provider recovers.
var ErrInvalidSession = errors.New("invalid or expired session")

// SessionIdentity contains only the current public claims needed to validate a
// bearer. Validation never reads password hashes or decrypts TOTP secrets.
type SessionIdentity struct {
	UserID   string
	Username string
	Roles    []string
	TenantID string
}

// ValidateSession distinguishes a definitively invalid bearer from an inability
// to validate it. The joined read observes current user claims and session state.
func (s *Store) ValidateSession(ctx context.Context, token string) (*SessionIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if token == "" {
		return nil, ErrInvalidSession
	}
	var identity SessionIdentity
	var rolesJSON, expiresAt string
	hash := hashSessionToken(token)
	err := s.db.QueryRowContext(ctx, `SELECT u.id, u.username, u.roles, COALESCE(u.tenant_id, ''), s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token = ? AND s.kind IN ('full', 'api-token')`, hash).
		Scan(&identity.UserID, &identity.Username, &rolesJSON, &identity.TenantID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidSession
	}
	if err != nil {
		return nil, fmt.Errorf("read session identity: %w", err)
	}
	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		expiry, err = time.Parse("2006-01-02 15:04:05", expiresAt)
	}
	if err != nil {
		return nil, errors.New("invalid stored session expiry")
	}
	if !expiry.After(time.Now()) {
		// Preserve lazy expiry cleanup, but never remove an unparseable row or a
		// session whose expiry changed since the read. Cleanup is best effort;
		// a failed write cannot make this known-expired bearer valid again.
		_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token = ? AND expires_at = ?`, hash, expiresAt)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, ErrInvalidSession
	}
	if err := json.Unmarshal([]byte(rolesJSON), &identity.Roles); err != nil {
		return nil, fmt.Errorf("decode session roles: %w", err)
	}
	if identity.UserID == "" {
		return nil, errors.New("invalid stored session user ID")
	}
	return &identity, nil
}
