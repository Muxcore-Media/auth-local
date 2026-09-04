package ratelimit

import "time"

// CheckLoginBackoff reports whether login may proceed for IP and optional username.
func CheckLoginBackoff(b *LoginBackoff, ip, username string) (allowed bool, retryAfter time.Duration, blockedKey string) {
	if b == nil {
		return true, 0, ""
	}
	if ip != "" {
		if ok, wait := b.Check(ip); !ok {
			return false, wait, ip
		}
	}
	if key := UsernameKey(username); key != "" {
		if ok, wait := b.Check(key); !ok {
			return false, wait, key
		}
	}
	return true, 0, ""
}

// RecordLoginFailure increments backoff for IP and username when present.
func RecordLoginFailure(b *LoginBackoff, ip, username string) {
	if b == nil {
		return
	}
	if ip != "" {
		b.RecordFailure(ip)
	}
	if key := UsernameKey(username); key != "" {
		b.RecordFailure(key)
	}
}

// ResetLoginBackoff clears backoff state after successful login.
func ResetLoginBackoff(b *LoginBackoff, ip, username string) {
	if b == nil {
		return
	}
	if ip != "" {
		b.Reset(ip)
	}
	if key := UsernameKey(username); key != "" {
		b.Reset(key)
	}
}
