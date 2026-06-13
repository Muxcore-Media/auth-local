package webapp

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

//go:embed login.html totp.html
var pageHTML embed.FS

func generateCSRFToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type LoginPageData struct {
	Error        string
	Redirect     string
	HasPasskeys  bool
	CSRFToken    string
	PartialToken string
}

type loginRateRecord struct {
	count        int
	blockedUntil time.Time
	lastSeen     time.Time
}

type codeEntry struct {
	sessToken string
	expiresAt time.Time
}

type Handler struct {
	store       *authStore.Store
	authAddr    string
	rateMu      sync.Mutex
	rateRecords map[string]*loginRateRecord
	codesMu     sync.Mutex
	codes       map[string]*codeEntry
	stopCh      chan struct{}
}

func New(store *authStore.Store, authAddr string) *Handler {
	h := &Handler{
		store:       store,
		authAddr:    authAddr,
		rateRecords: make(map[string]*loginRateRecord),
		codes:       make(map[string]*codeEntry),
		stopCh:      make(chan struct{}),
	}
	go h.rateLimitCleanup()
	go h.codeCleanup()
	return h
}

// Stop signals the cleanup goroutines to shut down.
func (h *Handler) Stop() {
	close(h.stopCh)
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/login", h.loginHandler)
	mux.HandleFunc("/login/password", h.passwordLogin)
	mux.HandleFunc("/login/totp", h.totpLogin)
	mux.HandleFunc("/login/exchange", h.exchangeHandler)
}

// --- One-time code exchange (replaces token in URL) ---

func (h *Handler) generateCode(sessToken string) string {
	b := make([]byte, 16)
	rand.Read(b)
	code := hex.EncodeToString(b)
	h.codesMu.Lock()
	h.codes[code] = &codeEntry{
		sessToken: sessToken,
		expiresAt: time.Now().Add(30 * time.Second),
	}
	h.codesMu.Unlock()
	return code
}

func (h *Handler) consumeCode(code string) (string, bool) {
	h.codesMu.Lock()
	defer h.codesMu.Unlock()
	entry, ok := h.codes[code]
	if !ok {
		return "", false
	}
	delete(h.codes, code)
	if time.Now().After(entry.expiresAt) {
		return "", false
	}
	return entry.sessToken, true
}

func (h *Handler) codeCleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.codesMu.Lock()
			now := time.Now()
			for k, v := range h.codes {
				if now.After(v.expiresAt) {
					delete(h.codes, k)
				}
			}
			h.codesMu.Unlock()
		}
	}
}

func (h *Handler) exchangeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		http.Error(w, "code required", http.StatusBadRequest)
		return
	}

	sessToken, ok := h.consumeCode(req.Code)
	if !ok {
		http.Error(w, "invalid or expired code", http.StatusUnauthorized)
		return
	}

	sess, err := h.store.GetSession(sessToken)
	if err != nil {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}

	user, err := h.store.GetUser(sess.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"token":    sessToken,
		"user_id":  user.ID,
		"username": user.Username,
		"roles":    user.Roles,
	})
}

// --- Admin key check ---

func (h *Handler) rateLimitCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.rateMu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for ip, rec := range h.rateRecords {
				if rec.lastSeen.Before(cutoff) {
					delete(h.rateRecords, ip)
				}
			}
			h.rateMu.Unlock()
		}
	}
}

func (h *Handler) checkRateLimit(ip string) bool {
	h.rateMu.Lock()
	defer h.rateMu.Unlock()
	rec, exists := h.rateRecords[ip]
	if !exists {
		rec = &loginRateRecord{}
		h.rateRecords[ip] = rec
	}
	rec.lastSeen = time.Now()
	if time.Now().Before(rec.blockedUntil) {
		return false
	}
	rec.count++
	if rec.count >= 6 {
		rec.blockedUntil = time.Now().Add(1 * time.Minute)
		rec.count = 0
	}
	return true
}

// --- Redirect with one-time code ---

func (h *Handler) redirectWithCode(w http.ResponseWriter, r *http.Request, sessToken, redirect string) {
	code := h.generateCode(sessToken)
	sep := "?"
	if strings.Contains(redirect, "?") {
		sep = "&"
	}
	target := redirect + sep + "code=" + code
	slog.Info("login: redirecting with code", "target", target, "host", r.Host)
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// --- Login page ---

func (h *Handler) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		h.renderLogin(w, r, "")
		return
	}
	h.passwordLogin(w, r)
}

func (h *Handler) renderLogin(w http.ResponseWriter, r *http.Request, errMsg string) {
	redirect := safeRedirect(r.URL, r.URL.Query().Get("redirect"))
	slog.Info("login: render page", "method", r.Method, "host", r.Host, "path", r.URL.Path, "query_redirect", r.URL.Query().Get("redirect"), "safe_redirect", redirect, "error", errMsg)

	hasPasskeys := false
	users, err := h.store.ListUsers()
	if err == nil {
		for _, u := range users {
			count, _ := h.store.WebAuthnCredentialCount(u.ID)
			if count > 0 {
				hasPasskeys = true
				break
			}
		}
	}

	csrfToken := generateCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf-token",
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	tmpl, err := template.ParseFS(pageHTML, "login.html")
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, LoginPageData{
		Error:       errMsg,
		Redirect:    redirect,
		HasPasskeys: hasPasskeys,
		CSRFToken:   csrfToken,
	}); err != nil {
		slog.Error("login template execute", "error", err)
	}
}

func (h *Handler) renderTOTP(w http.ResponseWriter, r *http.Request, partialToken, redirect, errMsg string) {
	csrfToken := generateCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf-token",
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	tmpl, err := template.ParseFS(pageHTML, "totp.html")
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, map[string]string{
		"Error":        errMsg,
		"PartialToken": partialToken,
		"Redirect":     redirect,
		"CSRFToken":    csrfToken,
	}); err != nil {
		slog.Error("totp template execute", "error", err)
	}
}

// --- Password login ---

func (h *Handler) passwordLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	ip := extractIP(r)
	slog.Info("login: POST received", "ip", ip, "host", r.Host, "path", r.URL.Path)

	if !h.checkRateLimit(ip) {
		slog.Warn("login: rate limited", "ip", ip)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too many login attempts", http.StatusTooManyRequests)
		return
	}

	if err := r.ParseForm(); err != nil {
		slog.Warn("login: parse form failed", "ip", ip, "error", err)
		h.renderLogin(w, r, "Invalid form data")
		return
	}

	cookieCSRF, _ := r.Cookie("csrf-token")
	formCSRF := r.FormValue("csrf_token")
	cookieVal := ""
	if cookieCSRF != nil {
		cookieVal = cookieCSRF.Value
	}
	slog.Info("login: CSRF check", "ip", ip, "cookie_present", cookieCSRF != nil, "cookie_val_len", len(cookieVal), "form_val_len", len(formCSRF), "match", cookieVal == formCSRF)
	if cookieCSRF == nil || cookieCSRF.Value == "" || formCSRF != cookieCSRF.Value {
		slog.Warn("login: CSRF mismatch", "ip", ip)
		h.renderLogin(w, r, "Invalid form token — please reload and try again")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	formRedirect := r.FormValue("redirect")
	redirect := safeRedirect(r.URL, formRedirect)
	slog.Info("login: form values", "ip", ip, "username", username, "form_redirect", formRedirect, "safe_redirect", redirect, "query_redirect", r.URL.Query().Get("redirect"))
	if redirect == "/" {
		redirect = safeRedirect(r.URL, r.URL.Query().Get("redirect"))
		slog.Info("login: fallback redirect", "ip", ip, "fallback", redirect)
	}

	if username == "" || password == "" {
		slog.Warn("login: empty credentials", "ip", ip)
		h.renderLogin(w, r, "Username and password are required")
		return
	}

	user, err := h.store.VerifyPassword(username, password)
	if err != nil {
		slog.Warn("login: password verification failed", "username", username, "ip", ip, "error", err)
		h.renderLogin(w, r, "Invalid username or password")
		return
	}
	slog.Info("login: password verified", "username", username, "user_id", user.ID, "ip", ip)

	// Check if TOTP is required.
	secret, totpEnabled, err := h.store.GetTOTPSecret(user.ID)
	if err == nil && totpEnabled && secret != "" {
		slog.Info("login: TOTP required", "username", username, "ip", ip)
		partialSess, err := h.store.CreatePartialSession(user.ID)
		if err != nil {
			slog.Error("login: create partial session failed", "error", err)
			h.renderLogin(w, r, "Internal error")
			return
		}
		h.renderTOTP(w, r, partialSess.Token, redirect, "")
		return
	}

	sess, err := h.store.CreateFullSession(user.ID)
	if err != nil {
		slog.Error("login: create session failed", "error", err)
		h.renderLogin(w, r, "Internal error")
		return
	}
	slog.Info("login: session created", "username", username, "ip", ip, "session_token", sess.Token[:8]+"...")

	h.redirectWithCode(w, r, sess.Token, redirect)
}

// --- TOTP login ---

func (h *Handler) totpLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	ip := extractIP(r)
	if !h.checkRateLimit(ip) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too many login attempts", http.StatusTooManyRequests)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	cookieCSRF, _ := r.Cookie("csrf-token")
	formCSRF := r.FormValue("csrf_token")
	if cookieCSRF == nil || cookieCSRF.Value == "" || formCSRF != cookieCSRF.Value {
		h.renderTOTP(w, r, "", "", "Invalid form token — please reload and try again")
		return
	}

	partialToken := r.FormValue("partial_token")
	totpCode := r.FormValue("totp_code")
	redirect := safeRedirect(r.URL, r.FormValue("redirect"))

	if partialToken == "" || totpCode == "" {
		h.renderTOTP(w, r, partialToken, redirect, "Code is required")
		return
	}

	partialSess, err := h.store.GetSession(partialToken)
	if err != nil {
		h.renderLogin(w, r, "Session expired — please log in again")
		return
	}
	if partialSess.Kind != "partial" {
		h.renderLogin(w, r, "Invalid session")
		return
	}

	secret, enabled, err := h.store.GetTOTPSecret(partialSess.UserID)
	if err != nil || !enabled || secret == "" {
		h.renderLogin(w, r, "TOTP is not enabled")
		return
	}

	if !totp.Validate(totpCode, secret) {
		h.renderTOTP(w, r, partialToken, redirect, "Invalid code — try again")
		return
	}

	fullSess, err := h.store.UpgradeSession(partialToken)
	if err != nil {
		slog.Error("login: upgrade session failed", "error", err)
		h.renderLogin(w, r, "Internal error")
		return
	}

	h.redirectWithCode(w, r, fullSess.Token, redirect)
}

func safeRedirect(r *url.URL, redirect string) string {
	if redirect == "" {
		return "/"
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		return "/"
	}
	if !parsed.IsAbs() {
		return redirect
	}
	if parsed.Host == r.Host {
		return redirect
	}
	knownHosts := map[string]bool{
		"localhost:8082":          true,
		"localhost:3000":          true,
		"admin-ui.digifender.com": true,
	}
	if knownHosts[parsed.Host] {
		return redirect
	}
	return "/"
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

func extractIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if idx := strings.Index(fwd, ","); idx > 0 {
			return strings.TrimSpace(fwd[:idx])
		}
		return strings.TrimSpace(fwd)
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		return host[:idx]
	}
	return host
}
