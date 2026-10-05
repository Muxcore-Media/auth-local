package webapp

import (
	"sync"
	"time"
)

// Login throttling: only FAILED authentication attempts count. A key (client
// IP, normalised username, or user ID for the TOTP step) is blocked once it
// accumulates loginMaxFailures failures inside a fixed window that starts at
// its first failure; the count expires with the window and is cleared by a
// successful login. Successful logins are never throttled by this limiter.
const (
	loginMaxFailures = 10
	loginFailWindow  = 15 * time.Minute
)

type failRecord struct {
	count       int
	windowStart time.Time
}

type failLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	max     int
	window  time.Duration
	records map[string]*failRecord
}

func newFailLimiter(max int, window time.Duration) *failLimiter {
	return &failLimiter{now: time.Now, max: max, window: window, records: make(map[string]*failRecord)}
}

// live returns the record for key if its window is still open (caller holds mu).
func (l *failLimiter) live(key string) *failRecord {
	rec := l.records[key]
	if rec == nil {
		return nil
	}
	if !l.now().Before(rec.windowStart.Add(l.window)) {
		delete(l.records, key)
		return nil
	}
	return rec
}

// blocked reports whether key has reached the failure threshold in the current window.
func (l *failLimiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := l.live(key)
	return rec != nil && rec.count >= l.max
}

// retryAfter returns the seconds until key's window closes (at least 1).
func (l *failLimiter) retryAfter(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := l.live(key)
	if rec == nil {
		return 1
	}
	d := int(rec.windowStart.Add(l.window).Sub(l.now()).Seconds()) + 1
	if d < 1 {
		d = 1
	}
	return d
}

func (l *failLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := l.live(key)
	if rec == nil {
		rec = &failRecord{windowStart: l.now()}
		l.records[key] = rec
	}
	rec.count++
}

func (l *failLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.records, key)
}

// sweep drops expired records.
func (l *failLimiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, rec := range l.records {
		if !now.Before(rec.windowStart.Add(l.window)) {
			delete(l.records, k)
		}
	}
}
