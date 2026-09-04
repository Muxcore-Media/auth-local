package audit

import "log/slog"

const eventKey = "auth_audit"

// LoginSuccess records a successful authentication.
func LoginSuccess(userID, username, method, ip, userAgent string) {
	slog.Info("auth state change",
		"event", eventKey,
		"action", "login",
		"outcome", "success",
		"user_id", userID,
		"username", username,
		"method", method,
		"ip", ip,
		"user_agent", userAgent,
	)
}

// LoginFailure records a failed authentication attempt.
func LoginFailure(username, method, reason, ip, userAgent string) {
	slog.Warn("auth state change",
		"event", eventKey,
		"action", "login",
		"outcome", "failure",
		"username", username,
		"method", method,
		"reason", reason,
		"ip", ip,
		"user_agent", userAgent,
	)
}

// Logout records session revocation initiated by the session owner.
func Logout(actorUserID, sessionUserID, ip string) {
	slog.Info("auth state change",
		"event", eventKey,
		"action", "logout",
		"actor_user_id", actorUserID,
		"session_user_id", sessionUserID,
		"ip", ip,
	)
}

// Revoke records administrative or self revocation of a session.
func Revoke(actorUserID, sessionUserID, ip string) {
	slog.Info("auth state change",
		"event", eventKey,
		"action", "revoke",
		"actor_user_id", actorUserID,
		"session_user_id", sessionUserID,
		"ip", ip,
	)
}

// TOTPEnabled records TOTP enrollment for a user.
func TOTPEnabled(actorUserID, targetUserID string) {
	slog.Info("auth state change",
		"event", eventKey,
		"action", "totp_enable",
		"actor_user_id", actorUserID,
		"target_user_id", targetUserID,
	)
}

// TOTPDisabled records TOTP removal for a user.
func TOTPDisabled(actorUserID, targetUserID string) {
	slog.Info("auth state change",
		"event", eventKey,
		"action", "totp_disable",
		"actor_user_id", actorUserID,
		"target_user_id", targetUserID,
	)
}

// PasswordChanged records a password reset for a user.
func PasswordChanged(actorUserID, targetUserID string) {
	slog.Info("auth state change",
		"event", eventKey,
		"action", "password_change",
		"actor_user_id", actorUserID,
		"target_user_id", targetUserID,
	)
}

// WebAuthnCeremony records a WebAuthn registration or authentication ceremony.
func WebAuthnCeremony(ceremony, outcome, userID, username, challenge, ip, userAgent string) {
	level := slog.Info
	if outcome != "success" {
		level = slog.Warn
	}
	level("auth state change",
		"event", eventKey,
		"action", "webauthn_"+ceremony,
		"outcome", outcome,
		"user_id", userID,
		"username", username,
		"challenge", challenge,
		"ip", ip,
		"user_agent", userAgent,
	)
}
