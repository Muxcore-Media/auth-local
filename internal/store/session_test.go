package store

import (
	"testing"
	"time"
)

func TestSessionIdleTimeout(t *testing.T) {
	s := newTestStore(t)
	s.SetSessionConfig(SessionConfig{
		TTL:         time.Hour,
		IdleTimeout: 50 * time.Millisecond,
	})
	user, _ := s.CreateUser("alice", "pw")
	sess, err := s.CreateFullSession(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	_, err = s.GetSession(sess.Token)
	if err == nil {
		t.Fatal("expected idle timeout")
	}
}

func TestSessionIPBinding(t *testing.T) {
	s := newTestStore(t)
	s.SetSessionConfig(SessionConfig{
		TTL:      time.Hour,
		BindIP:   true,
		BindUA:   true,
	})
	user, _ := s.CreateUser("alice", "pw")
	sess, err := s.CreateFullSession(user.ID, SessionMeta{IP: "203.0.113.1", UserAgent: "test-agent"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(sess.Token, SessionCheck{IP: "203.0.113.1", UserAgent: "test-agent", TouchIdle: true}); err != nil {
		t.Fatalf("matching binding: %v", err)
	}
	if _, err := s.GetSession(sess.Token, SessionCheck{IP: "203.0.113.2", UserAgent: "test-agent"}); err == nil {
		t.Fatal("expected ip binding mismatch")
	}
}
