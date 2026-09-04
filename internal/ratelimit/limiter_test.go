package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLimiterBlocksAfterMaxAttempts(t *testing.T) {
	l := New()
	t.Cleanup(l.Stop)

	key := "203.0.113.1"
	for i := 0; i < maxAttempts; i++ {
		if !l.Allow(key) {
			t.Fatalf("attempt %d: expected allow", i+1)
		}
	}
	if l.Allow(key) {
		t.Fatal("expected block after max attempts")
	}
}

func TestLimiterSeparateKeys(t *testing.T) {
	l := New()
	t.Cleanup(l.Stop)

	for i := 0; i < maxAttempts; i++ {
		if !l.Allow("203.0.113.1") {
			t.Fatalf("ip1 attempt %d: expected allow", i+1)
		}
	}
	if l.Allow("203.0.113.1") {
		t.Fatal("ip1 should be blocked")
	}
	if !l.Allow("203.0.113.2") {
		t.Fatal("ip2 should remain allowed")
	}
}

func TestWriteHTTP(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteHTTP(rec, "Too many login attempts")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") != retryAfterSecond {
		t.Fatalf("Retry-After %q want %q", rec.Header().Get("Retry-After"), retryAfterSecond)
	}
}
