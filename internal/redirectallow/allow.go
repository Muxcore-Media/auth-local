package redirectallow

import (
	"net/url"
	"os"
	"strings"
)

// HostAllowed reports whether an absolute redirect host may be used after login.
// Relative redirects are not handled here.
func HostAllowed(requestHost, redirectHost string) bool {
	if redirectHost == "" {
		return false
	}
	if redirectHost == requestHost {
		return true
	}
	return knownHosts()[redirectHost]
}

func knownHosts() map[string]bool {
	hosts := map[string]bool{
		"localhost:8082":  true,
		"127.0.0.1:8082":  true,
		"localhost:5173":  true, // media-ui-app / mediauiprox MVP
		"127.0.0.1:5173":  true,
		"localhost:3000":  true,
		"127.0.0.1:3000":  true,
		"localhost:18180": true,
		"127.0.0.1:18180": true,
	}
	add := func(raw string) {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if strings.Contains(part, "://") {
				u, err := url.Parse(part)
				if err == nil && u.Host != "" {
					hosts[u.Host] = true
				}
				continue
			}
			hosts[part] = true
		}
	}
	add(os.Getenv("AUTH_ALLOWED_REDIRECT_HOSTS"))
	add(os.Getenv("ADMIN_UI_PUBLIC_URL"))
	add(os.Getenv("MEDIA_UI_PUBLIC_URL"))
	return hosts
}
