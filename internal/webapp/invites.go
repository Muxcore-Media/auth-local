package webapp

import (
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

const inviteHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Join MuxCore</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Inter","IBM Plex Sans","Segoe UI",system-ui,sans-serif;color:#f5f5f7;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:
  radial-gradient(1200px 600px at 8% -10%, rgba(61,184,168,.12) 0%, transparent 55%),
  radial-gradient(900px 500px at 100% 0%, rgba(245,166,35,.08) 0%, transparent 50%),
  #0b0c0f;
}
.card{background:#15161b;border-radius:16px;padding:32px;width:100%;max-width:400px;border:1px solid #23252b;box-shadow:0 20px 25px -5px rgba(0,0,0,.4)}
.brand{width:40px;height:40px;border-radius:10px;background:#3db8a8;color:#0b0c0f;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:18px;margin-bottom:16px}
h1{font-size:22px;margin-bottom:8px;font-weight:700}
p{color:#a1a1aa;font-size:14px;margin-bottom:20px}
label{display:block;font-size:12px;color:#a1a1aa;margin-bottom:4px}
input{width:100%;padding:10px 12px;border:1px solid #23252b;border-radius:10px;background:#1c1e26;color:#f5f5f7;margin-bottom:14px;font:inherit}
input:focus{outline:2px solid #3db8a8;outline-offset:1px}
button{width:100%;padding:12px;background:#3db8a8;color:#0b0c0f;border:none;border-radius:10px;font-weight:600;font-size:14px;cursor:pointer;transition:background-color .15s}
button:hover{background:#56d0c0}
.error{color:#f87171;font-size:13px;margin-bottom:12px}
.ok{color:#3ddc84;font-size:14px}
a{color:#3db8a8}
</style>
</head>
<body>
<div class="card">
<div class="brand">M</div>
<h1>Join MuxCore</h1>
{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
{{if .Success}}
<p class="ok">Account created. You can sign in now.</p>
<p><a href="/login">Go to login</a></p>
{{else if .Invalid}}
<p>{{.Error}}</p>
{{else}}
<p>Create your account with invite role <strong>{{.Role}}</strong>.</p>
<form method="post" action="/invite/redeem">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}"/>
<input type="hidden" name="token" value="{{.Token}}"/>
<label>Username</label>
<input name="username" required autocomplete="username"/>
<label>Password</label>
<input type="password" name="password" required minlength="8" autocomplete="new-password"/>
<button type="submit">Create account</button>
</form>
{{end}}
</div>
</body>
</html>`

var inviteTmpl = template.Must(template.New("invite").Parse(inviteHTML))

type invitePageData struct {
	Token     string
	Role      string
	CSRFToken string
	Error     string
	Success   bool
	Invalid   bool
}

func (h *Handler) RegisterInviteRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/invite/redeem", h.inviteRedeem)
	mux.HandleFunc("/api/invite/peek", h.apiInvitePeek)
	mux.HandleFunc("/api/invite/redeem", h.apiInviteRedeem)
	mux.HandleFunc("/api/invites", h.apiInvites)
	mux.HandleFunc("/api/invites/", h.apiInviteAction)
	mux.HandleFunc("/invite", h.invitePage)
	mux.HandleFunc("/invite/", h.invitePage) // /invite/{token}
}

func (h *Handler) apiInvitePeek(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		http.Error(w, `{"error":"token required"}`, http.StatusBadRequest)
		return
	}
	inv, err := h.store.PeekInvite(token)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"valid":      true,
		"role":       inv.Role,
		"expires_at": inv.ExpiresAt.UTC().Format(time.RFC3339),
		"max_uses":   inv.MaxUses,
		"use_count":  inv.UseCount,
	})
}

func (h *Handler) apiInviteRedeem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(body.Token)
	username := strings.TrimSpace(body.Username)
	password := body.Password
	user, _, err := h.store.RedeemInvite(token, username, password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	slog.Info("invite redeemed", "user", user.Username, "user_id", user.ID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"username": user.Username,
		"user_id":  user.ID,
	})
}

func (h *Handler) invitePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		token = strings.TrimPrefix(r.URL.Path, "/invite/")
		token = strings.Trim(token, "/")
		if token == "" || token == "redeem" {
			token = ""
		}
	}
	data := invitePageData{Token: token}
	if token == "" {
		data.Invalid = true
		data.Error = "Missing invite token"
		w.WriteHeader(http.StatusBadRequest)
		_ = inviteTmpl.Execute(w, data)
		return
	}
	inv, err := h.store.PeekInvite(token)
	if err != nil {
		data.Invalid = true
		data.Error = err.Error()
		w.WriteHeader(http.StatusBadRequest)
		_ = inviteTmpl.Execute(w, data)
		return
	}
	csrfToken := generateCSRFToken()
	h.setCSRFCookie(w, r, csrfToken)
	data.Role = inv.Role
	data.CSRFToken = csrfToken
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = inviteTmpl.Execute(w, data)
}

func (h *Handler) inviteRedeem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	if !h.validateCSRF(r) {
		data := invitePageData{
			Error: "Invalid form token — please reload and try again",
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = inviteTmpl.Execute(w, data)
		return
	}
	token := strings.TrimSpace(r.FormValue("token"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	data := invitePageData{Token: token}
	user, _, err := h.store.RedeemInvite(token, username, password)
	if err != nil {
		data.Error = err.Error()
		if inv, peekErr := h.store.PeekInvite(token); peekErr == nil {
			data.Role = inv.Role
			csrfToken := generateCSRFToken()
			h.setCSRFCookie(w, r, csrfToken)
			data.CSRFToken = csrfToken
		} else {
			data.Invalid = true
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = inviteTmpl.Execute(w, data)
		return
	}
	slog.Info("invite redeemed", "user", user.Username, "user_id", user.ID)
	data.Success = true
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = inviteTmpl.Execute(w, data)
}

func (h *Handler) apiInvites(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		list, err := h.store.ListInvites()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if list == nil {
			list = make([]*authStore.Invite, 0)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"invites": list})
	case http.MethodPost:
		var body struct {
			CreatedBy string `json:"createdBy"`
			Role      string `json:"role"`
			TenantID  string `json:"tenantId"`
			Tenant    string `json:"tenant"`
			MaxUses   *int   `json:"maxUses"`
			TTLHours  int    `json:"ttlHours"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if body.TTLHours <= 0 {
			body.TTLHours = 168 // 7 days
		}
		maxUses := 1
		if body.MaxUses != nil {
			maxUses = *body.MaxUses
			if maxUses < 0 {
				maxUses = 0 // unlimited
			}
		}
		tenantID := strings.TrimSpace(body.TenantID)
		if tenantID == "" {
			tenantID = strings.TrimSpace(body.Tenant)
		}
		inv, err := h.store.CreateInvite(body.CreatedBy, body.Role, tenantID, maxUses, time.Duration(body.TTLHours)*time.Hour)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(inv)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) apiInviteAction(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/invites/")
	path = strings.Trim(path, "/")
	if path == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(path, "/")
	id := parts[0]
	if r.Method == http.MethodDelete || (r.Method == http.MethodPost && len(parts) > 1 && parts[1] == "revoke") {
		if err := h.store.RevokeInvite(id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "revoked", "id": id})
		return
	}
	http.NotFound(w, r)
}
