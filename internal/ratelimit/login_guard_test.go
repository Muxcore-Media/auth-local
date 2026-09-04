package ratelimit

import "testing"

func TestUsernameKey(t *testing.T) {
	if got := UsernameKey(" Alice "); got != "user:alice" {
		t.Fatalf("UsernameKey = %q", got)
	}
}

func TestLoginGuardUsernameBackoff(t *testing.T) {
	b := NewLoginBackoff()
	t.Cleanup(b.Stop)

	ip := "203.0.113.10"
	user := "alice"
	if ok, _, _ := CheckLoginBackoff(b, ip, user); !ok {
		t.Fatal("expected initial allow")
	}
	RecordLoginFailure(b, "", user)
	if ok, _, blocked := CheckLoginBackoff(b, ip, user); ok || blocked != "user:alice" {
		t.Fatalf("expected username block, ok=%v blocked=%q", ok, blocked)
	}
	ResetLoginBackoff(b, ip, user)
	if ok, _, _ := CheckLoginBackoff(b, ip, user); !ok {
		t.Fatal("expected allow after reset")
	}
}
