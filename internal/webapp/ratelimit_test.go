package webapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Muxcore-Media/auth-local/internal/ratelimit"
	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

func TestExchangeRateLimit(t *testing.T) {
	st, err := authStore.New(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	limiter := ratelimit.New()
	t.Cleanup(limiter.Stop)
	h := New(st, "http://127.0.0.1:9401", nil, limiter, nil, nil)

	ip := "203.0.113.77:12345"
	body := `{"code":"missing"}`
	for i := 0; i < 7; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login/exchange", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip
		rec := httptest.NewRecorder()
		h.exchangeHandler(rec, req)
		if i < 6 && rec.Code == http.StatusTooManyRequests {
			t.Fatalf("unexpected rate limit on attempt %d", i+1)
		}
		if i == 6 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("attempt 7: status %d want 429", rec.Code)
		}
	}
}

func TestAPIInviteRedeemRateLimit(t *testing.T) {
	st, err := authStore.New(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	inv, err := st.CreateInvite("admin", "viewer", "", 1, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	limiter := ratelimit.New()
	t.Cleanup(limiter.Stop)
	h := New(st, "http://127.0.0.1:9401", nil, limiter, nil, nil)

	ip := "203.0.113.88:12345"
	body, _ := json.Marshal(map[string]string{
		"token":    inv.Token,
		"username": "newbie",
		"password": "password123",
	})
	for i := 0; i < 7; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/invite/redeem", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip
		rec := httptest.NewRecorder()
		h.apiInviteRedeem(rec, req)
		if i < 6 && rec.Code == http.StatusTooManyRequests {
			t.Fatalf("unexpected rate limit on attempt %d", i+1)
		}
		if i == 6 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("attempt 7: status %d want 429", rec.Code)
		}
	}
}
