package webapp

import (
	"net"
	"net/http"
)

// MetricsHandler serves Prometheus metrics for auth-local. Access is restricted
// to clients on a direct loopback TCP connection (127.0.0.0/8, ::1). X-Forwarded-For
// is intentionally ignored so /metrics cannot be scraped through a reverse proxy on
// the public HTTP listener.
func MetricsHandler(body func() string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isDirectLoopback(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(body()))
	}
}

func isDirectLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
