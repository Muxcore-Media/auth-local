package webapp

import (
	"encoding/json"
	"net/http"

	"github.com/Muxcore-Media/auth-local/internal/security"
)

// SecurityDashboardHandler serves a JSON security summary on loopback only.
func SecurityDashboardHandler(collector *security.Collector, revocationCount func() int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isDirectLoopback(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		count := 0
		if revocationCount != nil {
			count = revocationCount()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(collector.Dashboard(count))
	}
}
