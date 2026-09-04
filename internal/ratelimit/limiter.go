package ratelimit

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxAttempts      = 6
	blockDuration    = time.Minute
	recordTTL        = 10 * time.Minute
	cleanupInterval  = 5 * time.Minute
	retryAfterSecond = "60"

	loginBaseBackoff = time.Minute
	loginMaxBackoff  = 30 * time.Minute
)

type record struct {
	count        int
	blockedUntil time.Time
	lastSeen     time.Time
}

type failureRecord struct {
	count        int
	blockedUntil time.Time
	lastSeen     time.Time
}

// Limiter provides in-memory per-key rate limiting with automatic cleanup.
type Limiter struct {
	mu       sync.Mutex
	records  map[string]*record
	stopCh   chan struct{}
	onDenied func(key string, retryAfter time.Duration)
}

// New creates a Limiter and starts a background cleanup goroutine.
func New() *Limiter {
	l := &Limiter{
		records: make(map[string]*record),
		stopCh:  make(chan struct{}),
	}
	go l.cleanup()
	return l
}

// SetOnDenied registers a callback invoked when Allow rejects a key.
func (l *Limiter) SetOnDenied(fn func(key string, retryAfter time.Duration)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onDenied = fn
}

// Allow reports whether key is within the rate limit. When false, the caller
// should reject the request until the block window expires.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	rec, exists := l.records[key]
	if !exists {
		rec = &record{}
		l.records[key] = rec
	}
	rec.lastSeen = time.Now()
	if time.Now().Before(rec.blockedUntil) {
		retryAfter := time.Until(rec.blockedUntil)
		if l.onDenied != nil {
			l.onDenied(key, retryAfter)
		}
		return false
	}
	rec.count++
	if rec.count >= maxAttempts {
		rec.blockedUntil = time.Now().Add(blockDuration)
		rec.count = 0
	}
	return true
}

// RetryAfter returns how long key must wait before Allow may succeed again.
func (l *Limiter) RetryAfter(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.records[key]
	if !ok || time.Now().After(rec.blockedUntil) {
		return 0
	}
	return time.Until(rec.blockedUntil)
}

// Stop signals the cleanup goroutine to exit.
func (l *Limiter) Stop() {
	select {
	case <-l.stopCh:
	default:
		close(l.stopCh)
	}
}

func (l *Limiter) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-l.stopCh:
			return
		case <-ticker.C:
			l.mu.Lock()
			cutoff := time.Now().Add(-recordTTL)
			for key, rec := range l.records {
				if rec.lastSeen.Before(cutoff) {
					delete(l.records, key)
				}
			}
			l.mu.Unlock()
		}
	}
}

// LoginBackoff tracks failed login attempts per key with exponential lockout.
type LoginBackoff struct {
	mu       sync.Mutex
	failures map[string]*failureRecord
	stopCh   chan struct{}
}

// NewLoginBackoff creates a LoginBackoff with background cleanup.
func NewLoginBackoff() *LoginBackoff {
	b := &LoginBackoff{
		failures: make(map[string]*failureRecord),
		stopCh:   make(chan struct{}),
	}
	go b.cleanup()
	return b
}

// Allow reports whether key may attempt login (not in exponential lockout).
func (b *LoginBackoff) Allow(key string) bool {
	allowed, _ := b.check(key)
	return allowed
}

// Check returns whether login is allowed and remaining lockout duration.
func (b *LoginBackoff) Check(key string) (allowed bool, retryAfter time.Duration) {
	return b.check(key)
}

func (b *LoginBackoff) check(key string) (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	rec, ok := b.failures[key]
	if !ok || time.Now().After(rec.blockedUntil) {
		return true, 0
	}
	return false, time.Until(rec.blockedUntil)
}

// RecordFailure increments consecutive failures and applies exponential backoff.
func (b *LoginBackoff) RecordFailure(key string) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	rec, ok := b.failures[key]
	if !ok {
		rec = &failureRecord{}
		b.failures[key] = rec
	}
	rec.count++
	rec.lastSeen = time.Now()
	backoff := loginBaseBackoff << (rec.count - 1)
	if backoff > loginMaxBackoff {
		backoff = loginMaxBackoff
	}
	rec.blockedUntil = time.Now().Add(backoff)
	return backoff
}

// Reset clears failure state after a successful login.
func (b *LoginBackoff) Reset(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.failures, key)
}

// Stop signals the cleanup goroutine to exit.
func (b *LoginBackoff) Stop() {
	select {
	case <-b.stopCh:
	default:
		close(b.stopCh)
	}
}

func (b *LoginBackoff) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.mu.Lock()
			cutoff := time.Now().Add(-recordTTL)
			for key, rec := range b.failures {
				if rec.lastSeen.Before(cutoff) {
					delete(b.failures, key)
				}
			}
			b.mu.Unlock()
		}
	}
}

// UsernameKey returns a stable backoff key for per-username brute-force tracking.
func UsernameKey(username string) string {
	username = strings.TrimSpace(strings.ToLower(username))
	if username == "" {
		return ""
	}
	return "user:" + username
}

// LogDenied is the default rate-limit denial logger for security monitoring.
func LogDenied(scope, key string, retryAfter time.Duration) {
	slog.Warn("rate limit exceeded",
		"scope", scope,
		"key", key,
		"retry_after_seconds", int(retryAfter.Seconds()),
	)
}

// WriteHTTP responds with 429 Too Many Requests and a Retry-After header.
func WriteHTTP(w http.ResponseWriter, message string) {
	if message == "" {
		message = "Too many requests"
	}
	w.Header().Set("Retry-After", retryAfterSecond)
	http.Error(w, message, http.StatusTooManyRequests)
}

// WriteHTTPRetryAfter responds with 429 and a caller-supplied Retry-After (seconds).
func WriteHTTPRetryAfter(w http.ResponseWriter, message string, retryAfter time.Duration) {
	if message == "" {
		message = "Too many requests"
	}
	secs := int(retryAfter.Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	http.Error(w, message, http.StatusTooManyRequests)
}
