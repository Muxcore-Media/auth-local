package server

import (
	"net/http"
	"strings"
)

func bearerTokenFromRequest(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if token := strings.TrimSpace(r.Header.Get(authTokenMetadataKey)); token != "" {
		return token
	}
	return ""
}

// AuthenticateHTTPRequest returns true when the request carries a valid full session.
func (s *AuthServer) AuthenticateHTTPRequest(r *http.Request) bool {
	if s.store == nil {
		return false
	}
	token := bearerTokenFromRequest(r)
	if token == "" {
		return false
	}
	sess, err := s.store.GetSession(token)
	if err != nil {
		return false
	}
	if sess.Kind != "full" && sess.Kind != "api-token" {
		return false
	}
	_, err = s.store.GetUser(sess.UserID)
	return err == nil
}
