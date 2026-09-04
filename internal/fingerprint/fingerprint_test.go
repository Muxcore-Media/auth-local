package fingerprint

import (
	"net/http/httptest"
	"testing"
)

func TestFromRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")
	req.Header.Set("CF-IPCountry", "us")

	meta := FromRequest(req, nil)
	if meta.Device != "ios" {
		t.Fatalf("device = %q want ios", meta.Device)
	}
	if meta.Browser != "safari" {
		t.Fatalf("browser = %q want safari", meta.Browser)
	}
	if meta.Location != "US" {
		t.Fatalf("location = %q want US", meta.Location)
	}
}
