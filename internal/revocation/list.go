package revocation

import (
	"sync"
	"time"
)

const (
	defaultRetention = 48 * time.Hour
	cleanupInterval  = 10 * time.Minute
)

// List tracks revoked token hashes until they expire from the list.
type List struct {
	mu      sync.RWMutex
	entries map[string]time.Time
	stopCh  chan struct{}
}

// New creates a revocation list with background cleanup.
func New() *List {
	l := &List{
		entries: make(map[string]time.Time),
		stopCh:  make(chan struct{}),
	}
	go l.cleanup()
	return l
}

// Add records a revoked token hash. retain controls how long the hash stays blocked.
func (l *List) Add(tokenHash string, retain time.Duration) {
	if l == nil || tokenHash == "" {
		return
	}
	if retain <= 0 {
		retain = defaultRetention
	}
	expires := time.Now().Add(retain)
	l.mu.Lock()
	l.entries[tokenHash] = expires
	l.mu.Unlock()
}

// Contains reports whether tokenHash is on the revocation list.
func (l *List) Contains(tokenHash string) bool {
	if l == nil || tokenHash == "" {
		return false
	}
	l.mu.RLock()
	expires, ok := l.entries[tokenHash]
	l.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(expires) {
		l.mu.Lock()
		delete(l.entries, tokenHash)
		l.mu.Unlock()
		return false
	}
	return true
}

// Count returns active revoked token hashes.
func (l *List) Count() int {
	if l == nil {
		return 0
	}
	now := time.Now()
	l.mu.RLock()
	defer l.mu.RUnlock()
	n := 0
	for _, expires := range l.entries {
		if now.Before(expires) {
			n++
		}
	}
	return n
}

// Stop signals the cleanup goroutine to exit.
func (l *List) Stop() {
	if l == nil {
		return
	}
	select {
	case <-l.stopCh:
	default:
		close(l.stopCh)
	}
}

func (l *List) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-l.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			l.mu.Lock()
			for hash, expires := range l.entries {
				if now.After(expires) {
					delete(l.entries, hash)
				}
			}
			l.mu.Unlock()
		}
	}
}
