package internal

import (
	"os"
	"strings"
	"time"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

func parseSessionConfig() authStore.SessionConfig {
	cfg := authStore.DefaultSessionConfig()
	if v := strings.TrimSpace(os.Getenv("AUTH_SESSION_IDLE_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.IdleTimeout = d
		}
	}
	if v := strings.TrimSpace(os.Getenv("AUTH_SESSION_TTL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.TTL = d
		}
	}
	cfg.BindIP = envBool("AUTH_SESSION_BIND_IP")
	cfg.BindUA = envBool("AUTH_SESSION_BIND_UA")
	return cfg
}

func envBool(key string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes"
}
