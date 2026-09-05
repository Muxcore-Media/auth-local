package store

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// BootstrapAdminFromEnv creates the initial admin user when the database is empty
// and AUTH_BOOTSTRAP_USER plus AUTH_BOOTSTRAP_PASSWORD are both set. It is a
// no-op when users already exist or when neither env var is set. When only one
// of the pair is set, bootstrap is skipped with a warning.
func BootstrapAdminFromEnv(s *Store) error {
	username := strings.TrimSpace(os.Getenv("AUTH_BOOTSTRAP_USER"))
	password := os.Getenv("AUTH_BOOTSTRAP_PASSWORD")
	if username == "" && password == "" {
		return nil
	}
	if username == "" || password == "" {
		slog.Warn("AUTH_BOOTSTRAP_USER and AUTH_BOOTSTRAP_PASSWORD must both be set; skipping bootstrap")
		return nil
	}

	users, err := s.ListUsers()
	if err != nil {
		return fmt.Errorf("bootstrap admin: list users: %w", err)
	}
	if len(users) > 0 {
		return nil
	}

	user, err := s.CreateUser(username, password)
	if err != nil {
		return fmt.Errorf("bootstrap admin: create user: %w", err)
	}
	if err := s.SetRoles(user.ID, []string{"admin"}); err != nil {
		return fmt.Errorf("bootstrap admin: set roles: %w", err)
	}
	slog.Info("bootstrap admin user created", "username", username)
	return nil
}
