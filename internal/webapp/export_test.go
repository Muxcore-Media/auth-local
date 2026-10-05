package webapp

import "time"

// SetLimiterClock replaces the login limiter clock (tests only).
func (h *Handler) SetLimiterClock(now func() time.Time) { h.limiter.now = now }
