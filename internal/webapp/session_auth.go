package webapp

import (
	"net/http"
	"strings"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

func extractBearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
		return ""
	}
	return auth[len(prefix):]
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

func mustFullSession(w http.ResponseWriter, r *http.Request, store *authStore.Store) *authStore.Session {
	token := extractBearerToken(r)
	if token == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil
	}
	sess, err := store.GetSession(token)
	if err != nil || sess.Kind != "full" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil
	}
	return sess
}

func mustAdminSession(w http.ResponseWriter, r *http.Request, store *authStore.Store) *authStore.Session {
	sess := mustFullSession(w, r, store)
	if sess == nil {
		return nil
	}
	user, err := store.GetUser(sess.UserID)
	if err != nil || !hasRole(user.Roles, "admin") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil
	}
	return sess
}

func selfOrAdminSession(w http.ResponseWriter, r *http.Request, store *authStore.Store, targetUserID string) *authStore.Session {
	sess := mustFullSession(w, r, store)
	if sess == nil {
		return nil
	}
	if strings.TrimSpace(targetUserID) == "" {
		http.Error(w, "user_id required", http.StatusBadRequest)
		return nil
	}
	if sess.UserID == targetUserID {
		return sess
	}
	user, err := store.GetUser(sess.UserID)
	if err != nil || !hasRole(user.Roles, "admin") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil
	}
	return sess
}
