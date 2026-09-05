package server

import (
	"net/http"
	"strings"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
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

func hasRoleHTTP(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// HTTPUser returns the authenticated user for a valid full session, if any.
func (s *AuthServer) HTTPUser(r *http.Request) (*authStore.User, error) {
	if s.store == nil {
		return nil, errHTTPUnauthorized
	}
	token := bearerTokenFromRequest(r)
	if token == "" {
		return nil, errHTTPUnauthorized
	}
	sess, err := s.store.GetSession(token)
	if err != nil {
		return nil, errHTTPUnauthorized
	}
	if sess.Kind != "full" && sess.Kind != "api-token" {
		return nil, errHTTPUnauthorized
	}
	return s.store.GetUser(sess.UserID)
}

var errHTTPUnauthorized = &httpAuthError{msg: "unauthorized"}

type httpAuthError struct{ msg string }

func (e *httpAuthError) Error() string { return e.msg }

// AuthenticateHTTPRequest returns true when the request carries a valid full session.
func (s *AuthServer) AuthenticateHTTPRequest(r *http.Request) bool {
	_, err := s.HTTPUser(r)
	return err == nil
}

// RequireAdminHTTP writes 401/403 and returns false when the caller is not an admin.
func (s *AuthServer) RequireAdminHTTP(w http.ResponseWriter, r *http.Request) bool {
	user, err := s.HTTPUser(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	if !hasRoleHTTP(user.Roles, "admin") {
		http.Error(w, "admin role required", http.StatusForbidden)
		return false
	}
	return true
}
