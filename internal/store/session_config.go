package store

import "time"

// SessionConfig controls absolute TTL, idle timeout, and optional binding.
type SessionConfig struct {
	// Absolute maximum session lifetime.
	TTL time.Duration
	// IdleTimeout ends sessions with no activity. Zero disables idle expiry.
	IdleTimeout time.Duration
	// BindIP stores client IP at session creation and validates on use.
	BindIP bool
	// BindUA stores User-Agent at session creation and validates on use.
	BindUA bool
}

// DefaultSessionConfig returns production-oriented session defaults.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		TTL:         sessionTTL,
		IdleTimeout: 30 * time.Minute,
	}
}

// SessionMeta captures optional client metadata stored with a session.
type SessionMeta struct {
	IP        string
	UserAgent string
	Device    string
	Browser   string
	Location  string
}

// SessionCheck supplies client metadata for binding validation and idle refresh.
type SessionCheck struct {
	IP        string
	UserAgent string
	TouchIdle bool
}
