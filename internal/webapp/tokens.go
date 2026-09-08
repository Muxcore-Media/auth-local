package webapp

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

func (h *Handler) RegisterTokenRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/tokens", h.apiTokens)
	mux.HandleFunc("/api/tokens/", h.apiTokenAction)
}

func publicAPIToken(t *authStore.APITokenInfo, userID, username string) map[string]any {
	if t == nil {
		return map[string]any{}
	}
	scopes := t.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	created := ""
	if !t.CreatedAt.IsZero() {
		created = t.CreatedAt.UTC().Format(time.RFC3339)
	}
	lastUsed := ""
	if !t.LastUsed.IsZero() {
		lastUsed = t.LastUsed.UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"id":         t.ID,
		"name":       t.Name,
		"prefix":     t.Prefix,
		"user_id":    userID,
		"username":   username,
		"scopes":     scopes,
		"created_at": created,
		"last_used":  lastUsed,
	}
}

func (h *Handler) apiTokens(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.auth == nil || !h.auth.RequireAdminHTTP(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		users, err := h.store.ListUsers()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]map[string]any, 0)
		for _, u := range users {
			if u == nil {
				continue
			}
			tokens, listErr := h.store.ListAPITokens(u.ID)
			if listErr != nil {
				http.Error(w, listErr.Error(), http.StatusInternalServerError)
				return
			}
			for _, tok := range tokens {
				out = append(out, publicAPIToken(tok, u.ID, u.Username))
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tokens": out})
	case http.MethodPost:
		caller, err := h.auth.HTTPUser(r)
		if err != nil || caller == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			Name   string   `json:"name"`
			UserID string   `json:"user_id"`
			Scopes []string `json:"scopes"`
		}
		if decErr := json.NewDecoder(r.Body).Decode(&body); decErr != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(body.Name)
		if name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		userID := strings.TrimSpace(body.UserID)
		username := caller.Username
		if userID == "" {
			userID = caller.ID
		} else if userID != caller.ID {
			target, getErr := h.store.GetUser(userID)
			if getErr != nil || target == nil {
				http.Error(w, "user not found", http.StatusNotFound)
				return
			}
			username = target.Username
		}
		secret, info, createErr := h.store.CreateAPIToken(userID, name, body.Scopes)
		if createErr != nil {
			http.Error(w, createErr.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":  publicAPIToken(info, userID, username),
			"secret": secret,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) apiTokenAction(w http.ResponseWriter, r *http.Request) {
	if h.auth == nil || !h.auth.RequireAdminHTTP(w, r) {
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/tokens/"), "/")
	if rest == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(rest, "/rotate") {
		id := strings.Trim(strings.TrimSuffix(rest, "/rotate"), "/")
		if id == "" || strings.Contains(id, "/") || r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.rotateAPIToken(w, r, id)
		return
	}
	if strings.Contains(rest, "/") {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, err := h.store.APITokenUserID(rest); err != nil {
		http.Error(w, "token not found", http.StatusNotFound)
		return
	}
	if err := h.store.DeleteAPIToken(rest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"removed": true, "id": rest})
}

func (h *Handler) rotateAPIToken(w http.ResponseWriter, r *http.Request, id string) {
	userID, err := h.store.APITokenUserID(id)
	if err != nil {
		http.Error(w, "token not found", http.StatusNotFound)
		return
	}
	target, getErr := h.store.GetUser(userID)
	if getErr != nil || target == nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	tokens, listErr := h.store.ListAPITokens(userID)
	if listErr != nil {
		http.Error(w, listErr.Error(), http.StatusInternalServerError)
		return
	}
	var current *authStore.APITokenInfo
	for _, tok := range tokens {
		if tok != nil && tok.ID == id {
			current = tok
			break
		}
	}
	if current == nil {
		http.Error(w, "token not found", http.StatusNotFound)
		return
	}
	secret, info, createErr := h.store.CreateAPIToken(userID, current.Name, current.Scopes)
	if createErr != nil {
		http.Error(w, createErr.Error(), http.StatusBadRequest)
		return
	}
	if delErr := h.store.DeleteAPIToken(id); delErr != nil {
		_ = h.store.DeleteAPIToken(info.ID)
		http.Error(w, delErr.Error(), http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":  publicAPIToken(info, userID, target.Username),
		"secret": secret,
	})
}
