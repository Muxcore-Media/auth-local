package webauthn

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

// Handler provides HTTP endpoints for WebAuthn registration and authentication.
type Handler struct {
	web   *webauthn.WebAuthn
	store *authStore.Store
}

// webUser wraps store.User to implement webauthn.User.
type webUser struct {
	store  *authStore.User
	creds  []webauthn.Credential
}

func (u *webUser) WebAuthnID() []byte                { return []byte(u.store.ID) }
func (u *webUser) WebAuthnName() string               { return u.store.Username }
func (u *webUser) WebAuthnDisplayName() string         { return u.store.Username }
func (u *webUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func New(rpID, rpOrigin, rpName string, store *authStore.Store) (*Handler, error) {
	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: rpName,
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	})
	if err != nil {
		return nil, err
	}
	return &Handler{web: web, store: store}, nil
}

func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/webauthn/register/begin", h.beginRegistration)
	mux.HandleFunc("/api/webauthn/register/complete", h.completeRegistration)
	mux.HandleFunc("/api/webauthn/login/begin", h.beginLogin)
	mux.HandleFunc("/api/webauthn/login/complete", h.completeLogin)
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

	options, sessionData, err := h.web.BeginRegistration(user)
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
	json.Unmarshal(sd, &sessionData)
	h.store.DeleteWebAuthnSession(sessionData.Challenge)

	credential, err := h.web.FinishRegistration(user, sessionData, r)
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

	options, sessionData, err := h.web.BeginLogin(user)
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
	json.Unmarshal(sd, &sessionData)
	h.store.DeleteWebAuthnSession(challenge)

	user, err := h.loadUser(string(sessionData.UserID))
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	credential, err := h.web.FinishLogin(user, sessionData, r)
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
	writeJSON(w, http.StatusOK, map[string]string{"session_token": sess.Token})
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
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
