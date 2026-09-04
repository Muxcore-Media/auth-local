package webapp_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
	"github.com/Muxcore-Media/auth-local/internal/webapp"
)

func loginCSRFCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "muxcore-auth-csrf" {
			return c
		}
	}
	t.Fatal("missing muxcore-auth-csrf cookie")
	return nil
}

func TestLoginCSRFCookieFlags(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "auth.db")
	store, err := authStore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	tests := []struct {
		name       string
		publicURL  string
		req        func() *http.Request
		wantSecure bool
	}{
		{
			name:      "public https url",
			publicURL: "https://auth.zem.systems",
			req: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/login", nil)
			},
			wantSecure: true,
		},
		{
			name:      "local http",
			publicURL: "http://127.0.0.1:9401",
			req: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/login", nil)
			},
			wantSecure: false,
		},
		{
			name:      "trusted proxy x-forwarded-proto",
			publicURL: "",
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/login", nil)
				req.RemoteAddr = "127.0.0.1:12345"
				req.Header.Set("X-Forwarded-Proto", "https")
				return req
			},
			wantSecure: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := webapp.New(store, tc.publicURL, nil, nil, nil, nil)
			mux := http.NewServeMux()
			h.RegisterRoutes(mux)

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, tc.req())
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /login status %d", rec.Code)
			}

			cookie := loginCSRFCookie(t, rec)
			if !cookie.HttpOnly {
				t.Fatal("expected HttpOnly")
			}
			if cookie.SameSite != http.SameSiteLaxMode {
				t.Fatalf("SameSite=%v want Lax", cookie.SameSite)
			}
			if cookie.Path != "/" {
				t.Fatalf("Path=%q want /", cookie.Path)
			}
			if cookie.Secure != tc.wantSecure {
				t.Fatalf("Secure=%v want %v", cookie.Secure, tc.wantSecure)
			}
		})
	}
}

func TestLoginPageSecurityHeaders(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "auth.db")
	store, err := authStore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	h := webapp.New(store, "http://127.0.0.1:9401", nil, nil, nil, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login status %d", rec.Code)
	}

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("missing Content-Security-Policy")
	}
	for _, want := range []string{
		"default-src 'self'",
		"frame-ancestors 'none'",
		"connect-src 'self'",
		"form-action 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP missing %q: %s", want, csp)
		}
	}

	for _, hdr := range []struct {
		name, want string
		exact      bool
	}{
		{"X-Content-Type-Options", "nosniff", true},
		{"X-Frame-Options", "DENY", true},
		{"Referrer-Policy", "strict-origin-when-cross-origin", true},
		{"Permissions-Policy", "camera=()", false},
	} {
		got := rec.Header().Get(hdr.name)
		if hdr.exact {
			if got != hdr.want {
				t.Fatalf("%s: got %q want %q", hdr.name, got, hdr.want)
			}
			continue
		}
		if !strings.Contains(got, hdr.want) {
			t.Fatalf("%s: got %q want substring %q", hdr.name, got, hdr.want)
		}
	}
}

func TestLoginRateLimitSecurityHeaders(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "auth.db")
	store, err := authStore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	h := webapp.New(store, "http://127.0.0.1:9401", nil, nil, nil, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	ip := "203.0.113.50:12345"
	for i := 0; i < 7; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = ip
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if i < 6 && rec.Code == http.StatusTooManyRequests {
			t.Fatalf("unexpected rate limit on attempt %d", i+1)
		}
		if i == 6 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("attempt 7: status %d want 429", rec.Code)
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatalf("attempt %d: missing X-Frame-Options", i+1)
		}
	}
}
