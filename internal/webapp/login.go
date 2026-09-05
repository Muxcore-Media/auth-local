package webapp

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/Muxcore-Media/auth-local/internal/redirectallow"
	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

//go:embed login.html totp.html
var pageHTML embed.FS

// authCSRFCookie must not share a name with admin-ui's csrf-token: browsers do not
// isolate cookies by port, so admin GETs would overwrite the login double-submit token.
const authCSRFCookie = "muxcore-auth-csrf"

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
	store          *authStore.Store
	publicURL      string
	trustedProxies []net.IPNet
	rateMu         sync.Mutex
	rateRecords    map[string]*loginRateRecord
	codesMu        sync.Mutex
	codes          map[string]*codeEntry
	stopCh         chan struct{}
}

func New(store *authStore.Store, publicURL string, trustedProxies []net.IPNet) *Handler {
	if len(trustedProxies) == 0 {
		trustedProxies = defaultTrustedProxies()
	}
	h := &Handler{
		store:          store,
		publicURL:      strings.TrimRight(strings.TrimSpace(publicURL), "/"),
		trustedProxies: trustedProxies,
		rateRecords:    make(map[string]*loginRateRecord),
		codes:          make(map[string]*codeEntry),
		stopCh:         make(chan struct{}),
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
	secure := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			setSecurityHeaders(w)
			fn(w, r)
		}
	}
	mux.HandleFunc("/login", secure(h.loginHandler))
	mux.HandleFunc("/login/password", secure(h.passwordLogin))
	mux.HandleFunc("/login/totp", secure(h.totpLogin))
	mux.HandleFunc("/login/exchange", secure(h.exchangeHandler))
	mux.HandleFunc("/login/device", secure(h.deviceLogin))
	mux.HandleFunc("/login/device/totp", secure(h.deviceTOTPLogin))
	mux.HandleFunc("/", secure(h.rootHandler))
	h.RegisterInviteRoutes(mux)
}

func (h *Handler) rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if strings.TrimSpace(r.URL.Query().Get("code")) != "" {
		h.renderRootMisredirect(w, r)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

const rootMisredirectHTML = `<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>MuxCore Auth</title>
<style>
*,:after,:before{box-sizing:border-box;border:0 solid #23252b}
html{font-family:"Inter","IBM Plex Sans","Segoe UI",system-ui,sans-serif;font-size:14px;color-scheme:dark}
body{margin:0;min-height:100vh;color:#f5f5f7;display:flex;align-items:center;justify-content:center;padding:1rem;
background:
  radial-gradient(1200px 600px at 8% -10%, rgba(61,184,168,.12) 0%, transparent 55%),
  radial-gradient(900px 500px at 100% 0%, rgba(245,166,35,.08) 0%, transparent 50%),
  #0b0c0f;
}
.card{max-width:28rem;width:100%;padding:2rem;text-align:center}
.text-2xl{font-size:1.5rem;font-weight:700}
.text-sm{font-size:.875rem}
.text-gray-400{color:#a1a1aa}
.text-gray-500{color:#6b6b73}
.mb-4{margin-bottom:1rem}.mb-8{margin-bottom:2rem}.mt-4{margin-top:1rem}
a{color:#3db8a8}
code{color:#c7c8cc}
</style>
</head>
<body>
<div class="card">
<div class="text-2xl mb-4">Return to the app</div>
<p class="text-sm text-gray-400 mb-4">Sign-in succeeded, but this auth host cannot send you back to the mobile app.</p>
<p class="text-sm text-gray-400 mb-8">In MuxCore iOS, set the server URL to <code>{{.MediaURL}}</code> (not this auth page), then sign in again.</p>
<p class="text-sm text-gray-500 mt-4"><a href="/login">Back to login</a></p>
</div>
</body>
</html>`

func (h *Handler) renderRootMisredirect(w http.ResponseWriter, r *http.Request) {
	mediaURL := strings.TrimSpace(os.Getenv("MEDIA_UI_PUBLIC_URL"))
	if mediaURL == "" {
		mediaURL = "https://mux.zem.systems"
	}
	tmpl, err := template.New("root").Parse(rootMisredirectHTML)
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, map[string]string{"MediaURL": mediaURL}); err != nil {
		slog.Error("root misredirect template execute", "error", err)
	}
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":     sessToken,
		"user_id":   user.ID,
		"username":  user.Username,
		"roles":     user.Roles,
		"tenant_id": user.TenantID,
		"claims":    user.Claims(),
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
	http.Redirect(w, r, redirect+sep+"code="+code, http.StatusSeeOther)
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
	h.setCSRFCookie(w, r, csrfToken)

	tmpl, err := template.ParseFS(pageHTML, "login.html")
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
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
	h.setCSRFCookie(w, r, csrfToken)

	tmpl, err := template.ParseFS(pageHTML, "totp.html")
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
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

	ip := h.extractIP(r)
	if !h.checkRateLimit(ip) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too many login attempts", http.StatusTooManyRequests)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderLogin(w, r, "Invalid form data")
		return
	}

	if !h.validateCSRF(r) {
		h.renderLogin(w, r, "Invalid form token — please reload and try again")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	redirect := safeRedirect(r.URL, r.FormValue("redirect"))
	if redirect == "/" {
		redirect = safeRedirect(r.URL, r.URL.Query().Get("redirect"))
	}

	if username == "" || password == "" {
		h.renderLogin(w, r, "Username and password are required")
		return
	}

	user, err := h.store.VerifyPassword(username, password)
	if err != nil {
		slog.Warn("login: password verification failed", "username", username)
		h.renderLogin(w, r, "Invalid username or password")
		return
	}

	// Check if TOTP is required.
	secret, totpEnabled, err := h.store.GetTOTPSecret(user.ID)
	if err == nil && totpEnabled && secret != "" {
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

	h.redirectWithCode(w, r, sess.Token, redirect)
}

// --- TOTP login ---

func (h *Handler) totpLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	ip := h.extractIP(r)
	if !h.checkRateLimit(ip) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too many login attempts", http.StatusTooManyRequests)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	if !h.validateCSRF(r) {
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

// deviceLogin accepts JSON credentials for native clients (TV, mobile) without CSRF cookies.
func (h *Handler) deviceLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	ip := h.extractIP(r)
	if !h.checkRateLimit(ip) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too many login attempts", http.StatusTooManyRequests)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(creds.Username)
	password := creds.Password
	if username == "" || password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}

	user, err := h.store.VerifyPassword(username, password)
	if err != nil {
		slog.Warn("device login: password verification failed", "username", username)
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	secret, totpEnabled, err := h.store.GetTOTPSecret(user.ID)
	if err == nil && totpEnabled && secret != "" {
		partialSess, err := h.store.CreatePartialSession(user.ID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"requires_2fa":  true,
			"partial_token": partialSess.Token,
			"user_id":       user.ID,
			"username":      user.Username,
		})
		return
	}

	sess, err := h.store.CreateFullSession(user.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":     sess.Token,
		"user_id":   user.ID,
		"username":  user.Username,
		"tenant_id": user.TenantID,
		"claims":    user.Claims(),
	})
}

// deviceTOTPLogin completes native device login after password step when TOTP is enabled.
func (h *Handler) deviceTOTPLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	ip := h.extractIP(r)
	if !h.checkRateLimit(ip) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too many login attempts", http.StatusTooManyRequests)
		return
	}

	var body struct {
		PartialToken string `json:"partial_token"`
		TOTPCode     string `json:"totp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	partialToken := strings.TrimSpace(body.PartialToken)
	totpCode := strings.TrimSpace(body.TOTPCode)
	if partialToken == "" || totpCode == "" {
		http.Error(w, "partial_token and totp_code required", http.StatusBadRequest)
		return
	}

	partialSess, err := h.store.GetSession(partialToken)
	if err != nil {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}
	if partialSess.Kind != "partial" {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}

	secret, enabled, err := h.store.GetTOTPSecret(partialSess.UserID)
	if err != nil || !enabled || secret == "" {
		http.Error(w, "TOTP is not enabled", http.StatusBadRequest)
		return
	}
	if !totp.Validate(totpCode, secret) {
		http.Error(w, "invalid TOTP code", http.StatusUnauthorized)
		return
	}

	fullSess, err := h.store.UpgradeSession(partialToken)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	user, err := h.store.GetUser(fullSess.UserID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":     fullSess.Token,
		"user_id":   user.ID,
		"username":  user.Username,
		"tenant_id": user.TenantID,
		"claims":    user.Claims(),
	})
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
	if redirectallow.HostAllowed(r.Host, parsed.Host) {
		return redirect
	}
	return "/"
}

func (h *Handler) validateCSRF(r *http.Request) bool {
	cookieCSRF, _ := r.Cookie(authCSRFCookie)
	formCSRF := r.FormValue("csrf_token")
	return cookieCSRF != nil && cookieCSRF.Value != "" && formCSRF == cookieCSRF.Value
}

func (h *Handler) setCSRFCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCSRFCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
}

func (h *Handler) cookieSecure(r *http.Request) bool {
	if strings.HasPrefix(h.publicURL, "https://") {
		return true
	}
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if isTrustedProxy(host, h.trustedProxies) &&
		strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; font-src 'self'; connect-src 'self'; "+
			"frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func (h *Handler) extractIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if isTrustedProxy(host, h.trustedProxies) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if ip := parseRightmostXFF(fwd); ip != "" {
				return ip
			}
		}
	}
	return host
}

func defaultTrustedProxies() []net.IPNet {
	return []net.IPNet{
		{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
	}
}

func isTrustedProxy(addr string, trustedProxies []net.IPNet) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func parseRightmostXFF(xff string) string {
	parts := strings.Split(xff, ",")
	if len(parts) == 0 {
		return ""
	}
	rightmost := strings.TrimSpace(parts[len(parts)-1])
	if rightmost == "" {
		return ""
	}
	if ip := net.ParseIP(rightmost); ip != nil {
		return ip.String()
	}
	return ""
}

func ParseTrustedProxies(cidrs []string) []net.IPNet {
	if len(cidrs) == 0 {
		return defaultTrustedProxies()
	}
	parsed := make([]net.IPNet, 0, len(cidrs)+1)
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			slog.Warn("ignoring invalid trusted proxy CIDR", "cidr", c, "error", err)
			continue
		}
		parsed = append(parsed, *n)
	}
	if len(parsed) == 0 {
		return defaultTrustedProxies()
	}
	parsed = append(parsed, net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)})
	return parsed
}
