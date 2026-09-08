package webapp

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

func (h *Handler) RegisterUserRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/users", h.apiUsers)
	mux.HandleFunc("/api/users/", h.apiUserAction)
}

func publicAuthUser(st *authStore.Store, u *authStore.User) map[string]any {
	if u == nil {
		return map[string]any{}
	}
	totp := u.TOTPEnabled
	if st != nil {
		if _, enabled, err := st.GetTOTPSecret(u.ID); err == nil {
			totp = enabled
		}
	}
	roles := u.Roles
	if roles == nil {
		roles = []string{}
	}
	created := ""
	if !u.CreatedAt.IsZero() {
		created = u.CreatedAt.UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"id":           u.ID,
		"username":     u.Username,
		"roles":        roles,
		"totp_enabled": totp,
		"created_at":   created,
		"tenant_id":    u.TenantID,
	}
}

func countAdmins(users []*authStore.User) int {
	n := 0
	for _, u := range users {
		if u == nil {
			continue
		}
		for _, role := range u.Roles {
			if strings.EqualFold(strings.TrimSpace(role), "admin") {
				n++
				break
			}
		}
	}
	return n
}

func userHasAdmin(u *authStore.User) bool {
	if u == nil {
		return false
	}
	for _, role := range u.Roles {
		if strings.EqualFold(strings.TrimSpace(role), "admin") {
			return true
		}
	}
	return false
}

func (h *Handler) apiUsers(w http.ResponseWriter, r *http.Request) {
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
		out := make([]map[string]any, 0, len(users))
		for _, u := range users {
			out = append(out, publicAuthUser(h.store, u))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"users": out})
	case http.MethodPost:
		h.apiCreateUser(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) apiCreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		TenantID string `json:"tenantId"`
		Tenant   string `json:"tenant"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(body.Username)
	password := strings.TrimSpace(body.Password)
	if username == "" || password == "" {
		http.Error(w, "username and password are required", http.StatusBadRequest)
		return
	}
	if len(password) < 8 {
		http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	tenantID := strings.TrimSpace(body.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(body.Tenant)
	}
	if tenantID == "" {
		if caller, err := h.auth.HTTPUser(r); err == nil && caller != nil {
			tenantID = strings.TrimSpace(caller.TenantID)
		}
	}
	user, err := h.store.CreateUserTenant(username, password, tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	role := strings.TrimSpace(body.Role)
	if role != "" && !strings.EqualFold(role, "user") {
		if setErr := h.store.SetRoles(user.ID, []string{role}); setErr != nil {
			http.Error(w, setErr.Error(), http.StatusBadRequest)
			return
		}
	}
	updated, _ := h.store.GetUser(user.ID)
	if updated == nil {
		updated = user
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"user": publicAuthUser(h.store, updated)})
}

func (h *Handler) apiUserAction(w http.ResponseWriter, r *http.Request) {
	if h.auth == nil || !h.auth.RequireAdminHTTP(w, r) {
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/")
	if strings.HasSuffix(rest, "/password") {
		h.apiSetUserPassword(w, r, strings.TrimSuffix(rest, "/password"))
		return
	}
	id := rest
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	caller, err := h.auth.HTTPUser(r)
	if err != nil || caller == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodDelete:
		if caller.ID == id {
			http.Error(w, "cannot delete your own account", http.StatusBadRequest)
			return
		}
		target, getErr := h.store.GetUser(id)
		if getErr != nil {
			http.Error(w, getErr.Error(), http.StatusNotFound)
			return
		}
		users, listErr := h.store.ListUsers()
		if listErr != nil {
			http.Error(w, listErr.Error(), http.StatusInternalServerError)
			return
		}
		if userHasAdmin(target) && countAdmins(users) <= 1 {
			http.Error(w, "cannot delete the last admin", http.StatusBadRequest)
			return
		}
		if delErr := h.store.DeleteUser(id); delErr != nil {
			http.Error(w, delErr.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"removed": true, "id": id})
	case http.MethodPatch, http.MethodPost:
		var body struct {
			Role  string   `json:"role"`
			Roles []string `json:"roles"`
		}
		if decErr := json.NewDecoder(r.Body).Decode(&body); decErr != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		roles := body.Roles
		if len(roles) == 0 && strings.TrimSpace(body.Role) != "" {
			roles = []string{strings.TrimSpace(body.Role)}
		}
		if len(roles) == 0 {
			http.Error(w, "roles required", http.StatusBadRequest)
			return
		}
		target, getErr := h.store.GetUser(id)
		if getErr != nil {
			http.Error(w, getErr.Error(), http.StatusNotFound)
			return
		}
		nextHasAdmin := false
		for _, role := range roles {
			if strings.EqualFold(strings.TrimSpace(role), "admin") {
				nextHasAdmin = true
				break
			}
		}
		if userHasAdmin(target) && !nextHasAdmin {
			users, listErr := h.store.ListUsers()
			if listErr != nil {
				http.Error(w, listErr.Error(), http.StatusInternalServerError)
				return
			}
			if countAdmins(users) <= 1 {
				http.Error(w, "cannot demote the last admin", http.StatusBadRequest)
				return
			}
		}
		if setErr := h.store.SetRoles(id, roles); setErr != nil {
			http.Error(w, setErr.Error(), http.StatusBadRequest)
			return
		}
		updated, _ := h.store.GetUser(id)
		_ = json.NewEncoder(w).Encode(map[string]any{"user": publicAuthUser(h.store, updated)})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) apiSetUserPassword(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id = strings.Trim(id, "/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	password := strings.TrimSpace(body.Password)
	if len(password) < 8 {
		http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	if _, err := h.store.GetUser(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := h.store.SetPassword(id, password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": id})
}
