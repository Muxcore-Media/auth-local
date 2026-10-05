package webapp_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
	"github.com/Muxcore-Media/auth-local/internal/webapp"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newLimiterEnv(t *testing.T) (http.Handler, *fakeClock) {
	t.Helper()
	store, err := authStore.New(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateUser("alice", "right-password"); err != nil {
		t.Fatal(err)
	}
	h := webapp.New(store, "http://127.0.0.1:9401", nil)
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	h.SetLimiterClock(clk.now)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux, clk
}

func deviceLogin(mux http.Handler, user, pass, addr string) (int, string) {
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	req := httptest.NewRequest(http.MethodPost, "/login/device", bytes.NewReader(body))
	req.RemoteAddr = addr
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestLoginManySuccessesNeverThrottled(t *testing.T) {
	mux, _ := newLimiterEnv(t)
	for i := 0; i < 20; i++ {
		if code, body := deviceLogin(mux, "alice", "right-password", "10.0.0.1:1"); code != http.StatusOK {
			t.Fatalf("login %d: %d %s", i, code, body)
		}
	}
}

func TestLoginFailuresBlockThenSuccessBlockedToo(t *testing.T) {
	mux, _ := newLimiterEnv(t)
	for i := 0; i < 10; i++ {
		if code, _ := deviceLogin(mux, "alice", "wrong", "10.0.0.1:1"); code != http.StatusUnauthorized {
			t.Fatalf("failure %d: want 401 got %d", i, code)
		}
	}
	if code, _ := deviceLogin(mux, "alice", "wrong", "10.0.0.1:1"); code != http.StatusTooManyRequests {
		t.Fatalf("want 429 after 10 failures, got %d", code)
	}
	// Per-username: a different IP is blocked for that username.
	if code, _ := deviceLogin(mux, "alice", "right-password", "10.0.0.2:1"); code != http.StatusTooManyRequests {
		t.Fatalf("username lockout: got %d", code)
	}
	// Per-IP: same IP, other username also blocked.
	if code, _ := deviceLogin(mux, "bob", "x", "10.0.0.1:1"); code != http.StatusTooManyRequests {
		t.Fatalf("ip lockout: got %d", code)
	}
	// Unrelated IP and username unaffected.
	if code, _ := deviceLogin(mux, "bob", "x", "10.0.0.3:1"); code != http.StatusUnauthorized {
		t.Fatalf("unrelated: got %d", code)
	}
}

func TestLoginUnknownUserLockedLikeKnown(t *testing.T) {
	mux, _ := newLimiterEnv(t)
	for i := 0; i < 10; i++ {
		deviceLogin(mux, "ghost", "x", "10.0.0.1:1")
	}
	code, body := deviceLogin(mux, "ghost", "x", "10.0.0.9:1")
	code2, body2 := func() (int, string) {
		for i := 0; i < 10; i++ {
			deviceLogin(mux, "alice", "x", "10.0.0.5:1")
		}
		return deviceLogin(mux, "alice", "x", "10.0.0.8:1")
	}()
	if code != code2 || body != body2 {
		t.Fatalf("responses differ: %d %q vs %d %q", code, body, code2, body2)
	}
}

func TestLoginSuccessDoesNotResetIPFailures(t *testing.T) {
	mux, _ := newLimiterEnv(t)
	// Attacker with a valid account interleaves successes with guesses at another user.
	for i := 0; i < 10; i++ {
		if code, _ := deviceLogin(mux, "bob", "x", "10.0.0.1:1"); code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, code)
		}
		if i < 9 {
			if code, _ := deviceLogin(mux, "alice", "right-password", "10.0.0.1:1"); code != http.StatusOK {
				t.Fatalf("own login %d: %d", i, code)
			}
		}
	}
	if code, _ := deviceLogin(mux, "alice", "right-password", "10.0.0.1:1"); code != http.StatusTooManyRequests {
		t.Fatalf("IP failures were cleared by successes: got %d", code)
	}
}

func TestLoginSuccessResetsUsernameFailures(t *testing.T) {
	mux, _ := newLimiterEnv(t)
	// Each round uses a fresh IP (the IP counter is deliberately not reset by success);
	// the username counter must be cleared by each success.
	for round := 0; round < 3; round++ {
		ip := fmt.Sprintf("10.0.1.%d:1", round+1)
		for i := 0; i < 9; i++ {
			if code, _ := deviceLogin(mux, "alice", "wrong", ip); code != http.StatusUnauthorized {
				t.Fatalf("round %d failure %d: %d", round, i, code)
			}
		}
		if code, _ := deviceLogin(mux, "alice", "right-password", ip); code != http.StatusOK {
			t.Fatalf("round %d success: %d", round, code)
		}
	}
}

func TestLoginFailureWindowExpires(t *testing.T) {
	mux, clk := newLimiterEnv(t)
	for i := 0; i < 10; i++ {
		deviceLogin(mux, "alice", "wrong", "10.0.0.1:1")
	}
	if code, _ := deviceLogin(mux, "alice", "right-password", "10.0.0.1:1"); code != http.StatusTooManyRequests {
		t.Fatalf("want blocked, got %d", code)
	}
	clk.advance(14 * time.Minute)
	if code, _ := deviceLogin(mux, "alice", "right-password", "10.0.0.1:1"); code != http.StatusTooManyRequests {
		t.Fatalf("still within window, got %d", code)
	}
	clk.advance(2 * time.Minute)
	if code, body := deviceLogin(mux, "alice", "right-password", "10.0.0.1:1"); code != http.StatusOK {
		t.Fatalf("window expired, want 200 got %d %s", code, body)
	}
}
