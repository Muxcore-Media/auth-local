package ratelimit

import (
	"testing"
	"time"
)

func TestLoginBackoffExponential(t *testing.T) {
	b := NewLoginBackoff()
	t.Cleanup(b.Stop)

	key := "203.0.113.50"
	if !b.Allow(key) {
		t.Fatal("expected initial allow")
	}
	d1 := b.RecordFailure(key)
	if d1 != loginBaseBackoff {
		t.Fatalf("first backoff %v want %v", d1, loginBaseBackoff)
	}
	if b.Allow(key) {
		t.Fatal("expected block after first failure")
	}
	// Simulate expiry and stack failures.
	b.mu.Lock()
	b.failures[key].blockedUntil = time.Now().Add(-time.Second)
	b.mu.Unlock()

	d2 := b.RecordFailure(key)
	if d2 != 2*loginBaseBackoff {
		t.Fatalf("second backoff %v want %v", d2, 2*loginBaseBackoff)
	}
	b.Reset(key)
	if !b.Allow(key) {
		t.Fatal("expected allow after reset")
	}
}

func TestLimiterOnDeniedCallback(t *testing.T) {
	l := New()
	t.Cleanup(l.Stop)

	key := "203.0.113.99"
	var denied bool
	l.SetOnDenied(func(k string, _ time.Duration) {
		if k == key {
			denied = true
		}
	})
	for i := 0; i < maxAttempts; i++ {
		_ = l.Allow(key)
	}
	_ = l.Allow(key)
	if !denied {
		t.Fatal("expected onDenied callback")
	}
}
