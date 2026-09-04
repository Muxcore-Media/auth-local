package security

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// Collector tracks security-relevant counters for Prometheus and dashboards.
type Collector struct {
	LoginFailed      atomic.Int64
	RateLimited      atomic.Int64
	Revoked          atomic.Int64
	WebAuthnCeremony atomic.Int64
}

// RecordLoginFailed increments failed login attempts.
func (c *Collector) RecordLoginFailed() {
	if c != nil {
		c.LoginFailed.Add(1)
	}
}

// RecordRateLimited increments rate-limit denials.
func (c *Collector) RecordRateLimited() {
	if c != nil {
		c.RateLimited.Add(1)
	}
}

// RecordRevoked increments token revocations.
func (c *Collector) RecordRevoked() {
	if c != nil {
		c.Revoked.Add(1)
	}
}

// RecordWebAuthnCeremony increments WebAuthn ceremony events.
func (c *Collector) RecordWebAuthnCeremony() {
	if c != nil {
		c.WebAuthnCeremony.Add(1)
	}
}

// Prometheus renders security counters in Prometheus text format.
func (c *Collector) Prometheus() string {
	if c == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("# HELP auth_security_login_failed_total Failed login attempts\n")
	b.WriteString("# TYPE auth_security_login_failed_total counter\n")
	fmt.Fprintf(&b, "auth_security_login_failed_total %d\n", c.LoginFailed.Load())

	b.WriteString("# HELP auth_security_rate_limited_total Rate-limited requests\n")
	b.WriteString("# TYPE auth_security_rate_limited_total counter\n")
	fmt.Fprintf(&b, "auth_security_rate_limited_total %d\n", c.RateLimited.Load())

	b.WriteString("# HELP auth_security_revoked_total Revoked session tokens\n")
	b.WriteString("# TYPE auth_security_revoked_total counter\n")
	fmt.Fprintf(&b, "auth_security_revoked_total %d\n", c.Revoked.Load())

	b.WriteString("# HELP auth_security_webauthn_ceremony_total WebAuthn ceremony events\n")
	b.WriteString("# TYPE auth_security_webauthn_ceremony_total counter\n")
	fmt.Fprintf(&b, "auth_security_webauthn_ceremony_total %d\n", c.WebAuthnCeremony.Load())
	return b.String()
}

// Dashboard returns a JSON-serializable security summary.
func (c *Collector) Dashboard(revocationCount int) map[string]any {
	if c == nil {
		return map[string]any{}
	}
	return map[string]any{
		"failed_logins":       c.LoginFailed.Load(),
		"rate_limited":        c.RateLimited.Load(),
		"revocations":         c.Revoked.Load(),
		"webauthn_ceremonies": c.WebAuthnCeremony.Load(),
		"revocation_list":     revocationCount,
	}
}
