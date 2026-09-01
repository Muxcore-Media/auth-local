package webauthn

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Muxcore-Media/auth-local/internal/redirectallow"
	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

// Handler provides HTTP endpoints for WebAuthn registration and authentication.
type Handler struct {
	webPtr atomic.Pointer[webauthn.WebAuthn]
	store  *authStore.Store
}

// webUser wraps store.User to implement webauthn.User.
type webUser struct {
	store *authStore.User
	creds []webauthn.Credential
}

func (u *webUser) WebAuthnID() []byte                         { return []byte(u.store.ID) }
func (u *webUser) WebAuthnName() string                       { return u.store.Username }
func (u *webUser) WebAuthnDisplayName() string                { return u.store.Username }
func (u *webUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func New(rpID string, rpOrigins []string, rpName string, store *authStore.Store) (*Handler, error) {
	h := &Handler{store: store}
	if err := h.Reconfigure(rpID, rpOrigins, rpName); err != nil {
		return nil, err
	}
	return h, nil
}

// Reconfigure rebuilds the WebAuthn RP config for live settings updates.
func (h *Handler) Reconfigure(rpID string, rpOrigins []string, rpName string) error {
	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: rpName,
		RPID:          rpID,
		RPOrigins:     rpOrigins,
	})
	if err != nil {
		return err
	}
	h.webPtr.Store(web)
	return nil
}

func (h *Handler) web() *webauthn.WebAuthn {
	return h.webPtr.Load()
}

// RegisterRoutes mounts WebAuthn API routes on mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/webauthn/register/begin", h.beginRegistration)
	mux.HandleFunc("/api/webauthn/register/complete", h.completeRegistration)
	mux.HandleFunc("/api/webauthn/login/begin", h.beginLogin)
	mux.HandleFunc("/api/webauthn/login/complete", h.completeLogin)
	mux.HandleFunc("/api/webauthn/credentials", h.listCredentials)
	mux.HandleFunc("/api/webauthn/credentials/", h.deleteCredential)
	mux.HandleFunc("/api/webauthn/admin/register/begin", h.beginAdminRegistration)
	mux.HandleFunc("/api/webauthn/admin/register/complete", h.completeAdminRegistration)
}

func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

func (h *Handler) loadUser(id string) (*webUser, error) {
	su, err := h.store.GetUser(id)
	if err != nil {
		return nil, err
	}
	return h.loadUserFromStore(su)
}

func (h *Handler) loadUserByUsername(username string) (*webUser, error) {
	su, err := h.store.GetUserByUsername(username)
	if err != nil {
		return nil, err
	}
	return h.loadUserFromStore(su)
}

func (h *Handler) loadUserFromStore(su *authStore.User) (*webUser, error) {
	u := &webUser{store: su}
	creds, err := h.store.ListWebAuthnCredentials(su.ID)
	if err != nil {
		return nil, err
	}
	for _, data := range creds {
		var c webauthn.Credential
		if err := json.Unmarshal(data, &c); err != nil {
			slog.Warn("webauthn: unmarshal credential", "error", err)
			continue
		}
		u.creds = append(u.creds, c)
	}
	return u, nil
}

func (h *Handler) saveCredential(userID string, cred *webauthn.Credential) {
	data, err := json.Marshal(cred)
	if err != nil {
		slog.Error("webauthn: marshal credential", "error", err)
		return
	}
	if err := h.store.AddWebAuthnCredential(userID, data); err != nil {
		slog.Error("webauthn: save credential", "error", err)
	}
}

func (h *Handler) beginRegistration(w http.ResponseWriter, r *http.Request) {
	sess := mustAuth(w, r, h.store)
	if sess == nil {
		return
	}

	user, err := h.loadUser(sess.UserID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	options, sessionData, err := h.web().BeginRegistration(user)
	if err != nil {
		slog.Error("webauthn: begin registration", "error", err)
		writeError(w, http.StatusInternalServerError, "registration failed")
		return
	}

	sd, _ := json.Marshal(sessionData)
	if err := h.store.SaveWebAuthnSession(user.store.ID, sessionData.Challenge, sd); err != nil {
		slog.Error("webauthn: save session", "error", err)
		writeError(w, http.StatusInternalServerError, "save failed")
		return
	}

	writeJSON(w, http.StatusOK, options)
}

func (h *Handler) completeRegistration(w http.ResponseWriter, r *http.Request) {
	sess := mustAuth(w, r, h.store)
	if sess == nil {
		return
	}

	user, err := h.loadUser(sess.UserID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	sd, err := h.store.GetWebAuthnSession(r.URL.Query().Get("challenge"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "challenge not found — complete later")
		return
	}
	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sd, &sessionData); err != nil {
		slog.Error("webauthn: unmarshal session data", "error", err)
		writeError(w, http.StatusBadRequest, "invalid session data")
		return
	}
	_ = h.store.DeleteWebAuthnSession(sessionData.Challenge)

	credential, err := h.web().FinishRegistration(user, sessionData, r)
	if err != nil {
		slog.Error("webauthn: finish registration", "error", err)
		writeError(w, http.StatusBadRequest, "registration verification failed")
		return
	}

	h.saveCredential(user.store.ID, credential)
	slog.Info("webauthn: credential registered", "user", user.store.Username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
}

func (h *Handler) beginLogin(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}

	user, err := h.loadUserByUsername(username)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	options, sessionData, err := h.web().BeginLogin(user)
	if err != nil {
		slog.Error("webauthn: begin login", "error", err)
		writeError(w, http.StatusInternalServerError, "login initiation failed")
		return
	}

	sd, _ := json.Marshal(sessionData)
	if err := h.store.SaveWebAuthnSession(user.store.ID, sessionData.Challenge, sd); err != nil {
		slog.Error("webauthn: save session", "error", err)
		writeError(w, http.StatusInternalServerError, "save failed")
		return
	}

	writeJSON(w, http.StatusOK, options)
}

func (h *Handler) completeLogin(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Parse the body to extract the challenge for session lookup.
	parsed, err := protocol.ParseCredentialRequestResponseBytes(bodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid assertion")
		return
	}

	challenge := parsed.Response.CollectedClientData.Challenge
	sd, err := h.store.GetWebAuthnSession(challenge)
	if err != nil {
		writeError(w, http.StatusBadRequest, "challenge not found or expired")
		return
	}
	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sd, &sessionData); err != nil {
		slog.Error("webauthn: unmarshal session data", "error", err)
		writeError(w, http.StatusBadRequest, "invalid session data")
		return
	}
	_ = h.store.DeleteWebAuthnSession(challenge)

	user, err := h.loadUser(string(sessionData.UserID))
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	credential, err := h.web().FinishLogin(user, sessionData, r)
	if err != nil {
		slog.Error("webauthn: finish login", "error", err)
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return
	}

	h.saveCredential(user.store.ID, credential)

	sess, err := h.store.CreateFullSession(user.store.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session creation failed")
		return
	}

	slog.Info("webauthn: login successful", "user", user.store.Username)

	redirect := safeRedirectURL(r, r.URL.Query().Get("redirect"))
	writeJSON(w, http.StatusOK, map[string]string{
		"session_token": sess.Token,
		"redirect":      redirect,
	})
}

// Helpers

func mustAuth(w http.ResponseWriter, r *http.Request, store *authStore.Store) *authStore.Session {
	token := extractBearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization")
		return nil
	}
	sess, err := store.GetSession(token)
	if err != nil || sess.Kind != "full" {
		writeError(w, http.StatusUnauthorized, "invalid or unauthorized session")
		return nil
	}
	return sess
}

func mustAdminAuth(w http.ResponseWriter, r *http.Request, store *authStore.Store) *authStore.Session {
	sess := mustAuth(w, r, store)
	if sess == nil {
		return nil
	}
	user, err := store.GetUser(sess.UserID)
	if err != nil || !hasRole(user.Roles, "admin") {
		writeError(w, http.StatusForbidden, "admin role required")
		return nil
	}
	return sess
}

func (h *Handler) authSelfOrAdmin(w http.ResponseWriter, r *http.Request, targetUserID string) bool {
	sess := mustAuth(w, r, h.store)
	if sess == nil {
		return false
	}
	if sess.UserID == targetUserID {
		return true
	}
	user, err := h.store.GetUser(sess.UserID)
	if err != nil || !hasRole(user.Roles, "admin") {
		writeError(w, http.StatusForbidden, "forbidden")
		return false
	}
	return true
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

func (h *Handler) listCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "user_id required")
		return
	}
	if !h.authSelfOrAdmin(w, r, userID) {
		return
	}

	infos, err := h.store.ListWebAuthnCredentialMeta(userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	if infos == nil {
		infos = []authStore.WebAuthnCredentialInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"credentials": infos,
		"count":       len(infos),
	})
}

func (h *Handler) deleteCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "DELETE required")
		return
	}

	// Path: /api/webauthn/credentials/{credentialID}
	credID := strings.TrimPrefix(r.URL.Path, "/api/webauthn/credentials/")
	if credID == "" {
		writeError(w, http.StatusBadRequest, "credential ID required")
		return
	}

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "user_id required")
		return
	}
	if !h.authSelfOrAdmin(w, r, userID) {
		return
	}

	if err := h.store.DeleteWebAuthnCredential(userID, credID); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *Handler) beginAdminRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	if mustAdminAuth(w, r, h.store) == nil {
		return
	}
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "user_id required")
		return
	}

	user, err := h.loadUser(userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	options, sessionData, err := h.web().BeginRegistration(user)
	if err != nil {
		slog.Error("webauthn: begin admin registration", "error", err)
		writeError(w, http.StatusInternalServerError, "registration failed")
		return
	}

	sd, _ := json.Marshal(sessionData)
	if err := h.store.SaveWebAuthnSession(user.store.ID, sessionData.Challenge, sd); err != nil {
		slog.Error("webauthn: save session", "error", err)
		writeError(w, http.StatusInternalServerError, "save failed")
		return
	}

	writeJSON(w, http.StatusOK, options)
}

func (h *Handler) completeAdminRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if mustAdminAuth(w, r, h.store) == nil {
		return
	}
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "user_id required")
		return
	}

	user, err := h.loadUser(userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	challenge := r.URL.Query().Get("challenge")
	sd, err := h.store.GetWebAuthnSession(challenge)
	if err != nil {
		writeError(w, http.StatusBadRequest, "challenge not found — complete later")
		return
	}
	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sd, &sessionData); err != nil {
		slog.Error("webauthn: unmarshal session data", "error", err)
		writeError(w, http.StatusBadRequest, "invalid session data")
		return
	}
	_ = h.store.DeleteWebAuthnSession(sessionData.Challenge)

	credential, err := h.web().FinishRegistration(user, sessionData, r)
	if err != nil {
		slog.Error("webauthn: finish admin registration", "error", err)
		writeError(w, http.StatusBadRequest, "registration verification failed")
		return
	}

	h.saveCredential(user.store.ID, credential)
	slog.Info("webauthn: credential registered via admin", "user", user.store.Username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
}

// safeRedirectURL validates the redirect param to prevent open redirect attacks.
func safeRedirectURL(r *http.Request, redirect string) string {
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

func extractBearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
		return ""
	}
	return auth[len(prefix):]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("webauthn: json encode", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
