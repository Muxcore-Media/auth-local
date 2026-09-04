package store

import (
	"testing"

	"github.com/Muxcore-Media/auth-local/internal/revocation"
)

func TestRevocationListBlocksSession(t *testing.T) {
	s := newTestStore(t)
	rev := revocation.New()
	t.Cleanup(rev.Stop)
	s.SetRevocationList(rev)

	user, _ := s.CreateUser("alice", "pw")
	sess, err := s.CreateFullSession(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(sess.Token); err != nil {
		t.Fatalf("session should be valid: %v", err)
	}
	if err := s.DeleteSession(sess.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(sess.Token); err == nil {
		t.Fatal("expected revoked session to be rejected")
	}
}

func TestSessionFingerprintStored(t *testing.T) {
	s := newTestStore(t)
	user, _ := s.CreateUser("alice", "pw")
	sess, err := s.CreateFullSession(user.ID, SessionMeta{
		IP:        "203.0.113.1",
		UserAgent: "Mozilla/5.0 Chrome/120",
		Device:    "desktop",
		Browser:   "chrome",
		Location:  "US",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSession(sess.Token)
	if err != nil {
		t.Fatal(err)
	}
	if got.Device != "desktop" || got.Browser != "chrome" || got.Location != "US" {
		t.Fatalf("fingerprint = %+v", got)
	}
}
