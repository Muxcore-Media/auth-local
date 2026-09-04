package fingerprint

import (
	"net"
	"net/http"
	"strings"

	"github.com/Muxcore-Media/auth-local/internal/clientip"
)

// Meta captures session client metadata for binding and audit.
type Meta struct {
	Device   string
	Browser  string
	Location string
}

// FromRequest derives device, browser, and coarse location from an HTTP request.
func FromRequest(r *http.Request, trustedProxies []net.IPNet) Meta {
	if r == nil {
		return Meta{}
	}
	ua := r.UserAgent()
	return Meta{
		Device:   parseDevice(ua),
		Browser:  parseBrowser(ua),
		Location: parseLocation(r, trustedProxies),
	}
}

func parseDevice(ua string) string {
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "iphone"), strings.Contains(lower, "ipad"):
		return "ios"
	case strings.Contains(lower, "android"):
		return "android"
	case strings.Contains(lower, "tvos"), strings.Contains(lower, "appletv"):
		return "tv"
	case strings.Contains(lower, "smart-tv"), strings.Contains(lower, "hbbtv"):
		return "tv"
	case strings.Contains(lower, "mobile"):
		return "mobile"
	case strings.Contains(lower, "tablet"):
		return "tablet"
	case ua == "":
		return "unknown"
	default:
		return "desktop"
	}
}

func parseBrowser(ua string) string {
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "edg/"):
		return "edge"
	case strings.Contains(lower, "chrome/") && !strings.Contains(lower, "chromium"):
		return "chrome"
	case strings.Contains(lower, "firefox/"):
		return "firefox"
	case strings.Contains(lower, "safari/") && !strings.Contains(lower, "chrome/"):
		return "safari"
	case strings.Contains(lower, "opr/"), strings.Contains(lower, "opera"):
		return "opera"
	case strings.Contains(lower, "curl/"):
		return "curl"
	case strings.Contains(lower, "go-http-client"):
		return "go"
	case ua == "":
		return "unknown"
	default:
		return "other"
	}
}

func parseLocation(r *http.Request, trustedProxies []net.IPNet) string {
	for _, hdr := range []string{"CF-IPCountry", "X-Country-Code", "X-Appengine-Country"} {
		if v := strings.TrimSpace(r.Header.Get(hdr)); v != "" && v != "XX" && v != "T1" {
			return strings.ToUpper(v)
		}
	}
	_ = clientip.ExtractIP(r, trustedProxies)
	return ""
}
