package webapp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pquerna/otp/totp"
)

const householdTOTPIssuer = "MuxCore"

func (h *Handler) RegisterTOTPRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/totp", h.apiTOTP)
	mux.HandleFunc("/api/totp/verify", h.apiTOTPVerify)
}

func (h *Handler) totpCaller(w http.ResponseWriter, r *http.Request) bool {
	if h.auth == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	if _, err := h.auth.HTTPUser(r); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (h *Handler) apiTOTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !h.totpCaller(w, r) {
		return
	}
	user, err := h.auth.HTTPUser(r)
	if err != nil || user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		_, enabled, _ := h.store.GetTOTPSecret(user.ID)
		_ = json.NewEncoder(w).Encode(map[string]any{"enabled": enabled})
	case http.MethodPost:
		h.apiEnableTOTP(w, user.ID, user.Username)
	case http.MethodDelete:
		if disErr := h.store.DisableTOTP(user.ID); disErr != nil {
			http.Error(w, disErr.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"enabled": false})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) apiEnableTOTP(w http.ResponseWriter, userID, username string) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      householdTOTPIssuer,
		AccountName: username,
	})
	if err != nil {
		http.Error(w, "generate totp secret", http.StatusInternalServerError)
		return
	}
	if err := h.store.SetTOTPSecret(userID, key.Secret()); err != nil {
		http.Error(w, "save totp secret", http.StatusInternalServerError)
		return
	}
	q := url.Values{}
	q.Set("secret", key.Secret())
	q.Set("issuer", householdTOTPIssuer)
	qrURL := fmt.Sprintf("otpauth://totp/%s:%s?%s", householdTOTPIssuer, username, q.Encode())
	_ = json.NewEncoder(w).Encode(map[string]any{
		"enabled":     true,
		"secret":      key.Secret(),
		"qr_code_url": qrURL,
	})
}

func (h *Handler) apiTOTPVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.totpCaller(w, r) {
		return
	}
	user, err := h.auth.HTTPUser(r)
	if err != nil || user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		Code     string `json:"code"`
		TOTPCode string `json:"totp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(body.Code)
	if code == "" {
		code = strings.TrimSpace(body.TOTPCode)
	}
	secret, enabled, err := h.store.GetTOTPSecret(user.ID)
	if err != nil || !enabled {
		http.Error(w, "TOTP not enabled for this user", http.StatusBadRequest)
		return
	}
	if !totp.Validate(code, secret) {
		http.Error(w, "invalid TOTP code", http.StatusBadRequest)
		return
	}
	if err := h.store.VerifyTOTPSetup(user.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"verified": true, "enabled": true})
}
