package revocation

import (
	"testing"
	"time"
)

func TestListAddContains(t *testing.T) {
	l := New()
	t.Cleanup(l.Stop)

	hash := "abc123"
	if l.Contains(hash) {
		t.Fatal("expected empty list")
	}
	l.Add(hash, time.Minute)
	if !l.Contains(hash) {
		t.Fatal("expected revoked token")
	}
	if l.Count() != 1 {
		t.Fatalf("count = %d want 1", l.Count())
	}
}

func TestListExpiry(t *testing.T) {
	l := New()
	t.Cleanup(l.Stop)

	hash := "expired"
	l.Add(hash, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if l.Contains(hash) {
		t.Fatal("expected expired revocation to clear")
	}
}
