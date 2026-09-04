package clientip

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// ExtractIP returns the client IP, honoring X-Forwarded-For only from trusted proxies.
func ExtractIP(r *http.Request, trustedProxies []net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if IsTrustedProxy(host, trustedProxies) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if ip := parseRightmostXFF(fwd); ip != "" {
				return ip
			}
		}
	}
	return host
}

func DefaultTrustedProxies() []net.IPNet {
	return []net.IPNet{
		{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
	}
}

func ParseTrustedProxies(cidrs []string) []net.IPNet {
	if len(cidrs) == 0 {
		return DefaultTrustedProxies()
	}
	parsed := make([]net.IPNet, 0, len(cidrs)+1)
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			slog.Warn("ignoring invalid trusted proxy CIDR", "cidr", c, "error", err)
			continue
		}
		parsed = append(parsed, *n)
	}
	if len(parsed) == 0 {
		return DefaultTrustedProxies()
	}
	parsed = append(parsed, net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)})
	return parsed
}

func IsTrustedProxy(addr string, trustedProxies []net.IPNet) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func parseRightmostXFF(xff string) string {
	parts := strings.Split(xff, ",")
	if len(parts) == 0 {
		return ""
	}
	rightmost := strings.TrimSpace(parts[len(parts)-1])
	if rightmost == "" {
		return ""
	}
	if ip := net.ParseIP(rightmost); ip != nil {
		return ip.String()
	}
	return ""
}
