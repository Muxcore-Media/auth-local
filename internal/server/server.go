package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"

	"github.com/Muxcore-Media/auth-local/internal/policy"
	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

const issuerName = "MuxCore"

type loginRateRecord struct {
	count        int
	blockedUntil time.Time
	lastSeen     time.Time
}

// AuthServer implements the AuthService gRPC server.
type AuthServer struct {
	authv1.UnimplementedAuthServiceServer
	store        *authStore.Store
	policy       *policy.Policy
	loginSuccess atomic.Int64
	loginFailed  atomic.Int64
	rpID         string
	rpOrigins    []string
	rpName       string
	rateMu       sync.Mutex
	rateRecords  map[string]*loginRateRecord
}

// Metrics returns Prometheus-format metrics.
func (s *AuthServer) Metrics() string {
	var b strings.Builder
	b.WriteString("# HELP auth_login_success_total Successful logins\n")
	b.WriteString("# TYPE auth_login_success_total counter\n")
	fmt.Fprintf(&b, "auth_login_success_total %d\n", s.loginSuccess.Load())
	b.WriteString("# HELP auth_login_failed_total Failed login attempts\n")
	b.WriteString("# TYPE auth_login_failed_total counter\n")
	fmt.Fprintf(&b, "auth_login_failed_total %d\n", s.loginFailed.Load())
	if s.store != nil {
		b.WriteString("# HELP auth_sessions_active Current active sessions\n")
		b.WriteString("# TYPE auth_sessions_active gauge\n")
		fmt.Fprintf(&b, "auth_sessions_active %d\n", s.store.SessionCount())
	}
	return b.String()
}

func New(s *authStore.Store, p *policy.Policy, rpID string, rpOrigins []string, rpName string) *AuthServer {
	return &AuthServer{
		store:       s,
		policy:      p,
		rpID:        rpID,
		rpOrigins:   rpOrigins,
		rpName:      rpName,
		rateRecords: make(map[string]*loginRateRecord),
	}
}

func (s *AuthServer) RegisterWithGRPC(srv *grpc.Server) {
	authv1.RegisterAuthServiceServer(srv, s)
}

// SetPolicy replaces the RBAC policy at runtime. Used for SIGHUP reload.
func (s *AuthServer) SetPolicy(p *policy.Policy) {
	if p == nil {
		return
	}
	if s.policy != nil {
		s.policy.Replace(p)
	} else {
		s.policy = p
	}
	slog.Info("RBAC policy reloaded")
}

// SetRelyingParty updates WebAuthn / TOTP RP metadata used by gRPC helpers.
func (s *AuthServer) SetRelyingParty(rpID string, rpOrigins []string, rpName string) {
	s.rpID = rpID
	s.rpOrigins = rpOrigins
	s.rpName = rpName
}

func (s *AuthServer) Authenticate(ctx context.Context, req *authv1.AuthenticateRequest) (*authv1.AuthenticateResponse, error) {
	switch req.CredentialType {
	case "password":
		return s.authPassword(ctx, req)
	case "totp":
		return s.authTOTP(ctx, req)
	case "api-key":
		return s.authAPIKey(req)
	default:
		return &authv1.AuthenticateResponse{
			Authenticated: false,
			Error:         "unsupported credential type: " + req.CredentialType,
		}, nil
	}
}

func (s *AuthServer) authPassword(ctx context.Context, req *authv1.AuthenticateRequest) (*authv1.AuthenticateResponse, error) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(req.CredentialData, &creds); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid credential data")
	}

	if !s.checkRateLimit(rateLimitKey(ctx, creds.Username)) {
		s.loginFailed.Add(1)
		return &authv1.AuthenticateResponse{
			Authenticated: false,
			Error:         "too many login attempts; try again in one minute",
		}, nil
	}

	user, err := s.store.VerifyPassword(creds.Username, creds.Password)
	if err != nil {
		slog.Warn("auth: password verification failed", "username", creds.Username)
		s.loginFailed.Add(1)
		return &authv1.AuthenticateResponse{
			Authenticated: false,
			Error:         "invalid username or password",
		}, nil
	}

	// Check if TOTP is enabled.
	_, enabled, err := s.store.GetTOTPSecret(user.ID)
	if err == nil && enabled {
		sess, err := s.store.CreatePartialSession(user.ID)
		if err != nil {
			return nil, status.Error(codes.Internal, "create partial session failed")
		}
		return &authv1.AuthenticateResponse{
			Authenticated:    false,
			Requires_2Fa:     true,
			PartialToken:     sess.Token,
			AvailableMethods: []string{"totp"},
			UserId:           user.ID,
			Username:         user.Username,
		}, nil
	}

	sess, err := s.store.CreateFullSession(user.ID)
	if err != nil {
		return nil, status.Error(codes.Internal, "create session failed")
	}
	s.loginSuccess.Add(1)
	return &authv1.AuthenticateResponse{
		Authenticated: true,
		SessionToken:  sess.Token,
		UserId:        user.ID,
		Username:      user.Username,
		Roles:         user.Roles,
		TenantId:      user.TenantID,
	}, nil
}

func (s *AuthServer) authTOTP(ctx context.Context, req *authv1.AuthenticateRequest) (*authv1.AuthenticateResponse, error) {
	var creds struct {
		PartialToken string `json:"partial_token"`
		TOTPCode     string `json:"totp_code"`
	}
	if err := json.Unmarshal(req.CredentialData, &creds); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid credential data")
	}
	if creds.PartialToken == "" || creds.TOTPCode == "" {
		return &authv1.AuthenticateResponse{
			Authenticated: false,
			Error:         "partial_token and totp_code are required",
		}, nil
	}

	if !s.checkRateLimit("totp:" + creds.PartialToken) {
		s.loginFailed.Add(1)
		return &authv1.AuthenticateResponse{
			Authenticated: false,
			Error:         "too many login attempts; try again in one minute",
		}, nil
	}

	// Validate the partial session.
	partialSess, err := s.store.GetSession(creds.PartialToken)
	if err != nil {
		return &authv1.AuthenticateResponse{
			Authenticated: false,
			Error:         "invalid or expired partial session",
		}, nil
	}
	if partialSess.Kind != "partial" {
		return &authv1.AuthenticateResponse{
			Authenticated: false,
			Error:         "session is not a partial token",
		}, nil
	}

	// Get the user's TOTP secret and validate the code.
	secret, enabled, err := s.store.GetTOTPSecret(partialSess.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "lookup totp secret")
	}
	if !enabled {
		return &authv1.AuthenticateResponse{
			Authenticated: false,
			Error:         "TOTP is not enabled for this user",
		}, nil
	}
	if !totp.Validate(creds.TOTPCode, secret) {
		slog.Warn("auth: invalid TOTP code", "user_id", partialSess.UserID)
		s.loginFailed.Add(1)
		return &authv1.AuthenticateResponse{
			Authenticated: false,
			Error:         "invalid TOTP code",
		}, nil
	}

	// Upgrade partial session to full.
	fullSess, err := s.store.UpgradeSession(creds.PartialToken)
	if err != nil {
		return nil, status.Error(codes.Internal, "upgrade session failed")
	}
	s.loginSuccess.Add(1)
	user, err := s.store.GetUser(fullSess.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "lookup user")
	}

	return &authv1.AuthenticateResponse{
		Authenticated: true,
		SessionToken:  fullSess.Token,
		UserId:        user.ID,
		Username:      user.Username,
		Roles:         user.Roles,
		TenantId:      user.TenantID,
	}, nil
}

func (s *AuthServer) authAPIKey(req *authv1.AuthenticateRequest) (*authv1.AuthenticateResponse, error) {
	var creds struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(req.CredentialData, &creds); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid credential data")
	}

	token, err := s.store.ValidateAPIToken(creds.Key)
	if err != nil {
		slog.Warn("auth: invalid API key")
		s.loginFailed.Add(1)
		return &authv1.AuthenticateResponse{
			Authenticated: false,
			Error:         "invalid API key",
		}, nil
	}

	user, err := s.store.GetUser(token.UserID)
	if err != nil {
		return &authv1.AuthenticateResponse{
			Authenticated: false,
			Error:         "user not found",
		}, nil
	}

	s.loginSuccess.Add(1)
	return &authv1.AuthenticateResponse{
		Authenticated: true,
		SessionToken:  token.Token,
		UserId:        user.ID,
		Username:      user.Username,
		Roles:         user.Roles,
		TenantId:      user.TenantID,
	}, nil
}

func (s *AuthServer) Validate(ctx context.Context, req *authv1.ValidateRequest) (*authv1.ValidateResponse, error) {
	sess, err := s.store.GetSession(req.Token)
	if err != nil {
		return &authv1.ValidateResponse{Valid: false, Error: "invalid or expired token"}, nil
	}
	if sess.Kind != "full" && sess.Kind != "api-token" {
		return &authv1.ValidateResponse{Valid: false, Error: "session not fully authenticated"}, nil
	}

	user, err := s.store.GetUser(sess.UserID)
	if err != nil {
		return &authv1.ValidateResponse{Valid: false, Error: "user not found"}, nil
	}

	return &authv1.ValidateResponse{
		Valid:    true,
		UserId:   user.ID,
		Username: user.Username,
		Roles:    user.Roles,
		TenantId: user.TenantID,
	}, nil
}

func (s *AuthServer) Revoke(ctx context.Context, req *authv1.RevokeRequest) (*authv1.RevokeResponse, error) {
	_ = s.store.DeleteSession(req.Token)
	return &authv1.RevokeResponse{}, nil
}

func (s *AuthServer) Can(ctx context.Context, req *authv1.CanRequest) (*authv1.CanResponse, error) {
	var roles []string
	user, err := s.store.GetUser(req.UserId)
	if err == nil {
		roles = user.Roles
	} else {
		// Service modules authenticate via x-caller-id (not a DB user). ExtractIdentity
		// assigns role "module"; evaluate RBAC against that instead of deny-all.
		roles = []string{"module"}
	}

	var allowed bool
	var reason string
	if s.policy != nil {
		allowed, reason = s.policy.IsAllowed(roles, req.Action, req.Resource)
	} else {
		allowed, reason = false, "no policy loaded"
	}
	return &authv1.CanResponse{Allowed: allowed, Reason: reason}, nil
}

func (s *AuthServer) ExtractIdentity(ctx context.Context, req *authv1.ExtractIdentityRequest) (*authv1.ExtractIdentityResponse, error) {
	if req.Token == "" && req.CallerId == "" {
		return &authv1.ExtractIdentityResponse{Found: false}, nil
	}

	if req.Token != "" {
		sess, err := s.store.GetSession(req.Token)
		if err == nil && (sess.Kind == "full" || sess.Kind == "api-token") {
			user, err := s.store.GetUser(sess.UserID)
			if err == nil {
				return &authv1.ExtractIdentityResponse{
					Found:    true,
					Id:       user.ID,
					Kind:     "user",
					Roles:    user.Roles,
					TenantId: user.TenantID,
				}, nil
			}
		}
	}

	if req.CallerId != "" {
		return &authv1.ExtractIdentityResponse{
			Found: true,
			Id:    req.CallerId,
			Kind:  "service",
			Roles: []string{"module"},
		}, nil
	}

	return &authv1.ExtractIdentityResponse{Found: false}, nil
}

// --- TOTP Management ---

func (s *AuthServer) EnableTOTP(ctx context.Context, req *authv1.EnableTOTPRequest) (*authv1.EnableTOTPResponse, error) {
	if err := s.requireSelfOrAdmin(ctx, req.UserId); err != nil {
		if st, ok := status.FromError(err); ok {
			return &authv1.EnableTOTPResponse{Error: st.Message()}, nil
		}
		return nil, err
	}
	user, err := s.store.GetUser(req.UserId)
	if err != nil {
		return &authv1.EnableTOTPResponse{Error: "user not found"}, nil
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuerName,
		AccountName: user.Username,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "generate totp secret")
	}

	if err := s.store.SetTOTPSecret(user.ID, key.Secret()); err != nil {
		return nil, status.Error(codes.Internal, "save totp secret")
	}

	q := url.Values{}
	q.Set("secret", key.Secret())
	q.Set("issuer", issuerName)
	qrURL := fmt.Sprintf("otpauth://totp/%s:%s?%s", issuerName, user.Username, q.Encode())

	return &authv1.EnableTOTPResponse{
		Secret:    key.Secret(),
		QrCodeUrl: qrURL,
	}, nil
}

func (s *AuthServer) DisableTOTP(ctx context.Context, req *authv1.DisableTOTPRequest) (*authv1.DisableTOTPResponse, error) {
	if err := s.requireSelfOrAdmin(ctx, req.UserId); err != nil {
		if st, ok := status.FromError(err); ok {
			return &authv1.DisableTOTPResponse{Error: st.Message()}, nil
		}
		return nil, err
	}
	if err := s.store.DisableTOTP(req.UserId); err != nil {
		return &authv1.DisableTOTPResponse{Error: err.Error()}, nil
	}
	return &authv1.DisableTOTPResponse{}, nil
}

func (s *AuthServer) TOTPStatus(ctx context.Context, req *authv1.TOTPStatusRequest) (*authv1.TOTPStatusResponse, error) {
	_, enabled, err := s.store.GetTOTPSecret(req.UserId)
	if err != nil {
		return &authv1.TOTPStatusResponse{Enabled: false}, nil
	}
	return &authv1.TOTPStatusResponse{Enabled: enabled}, nil
}

func (s *AuthServer) VerifyTOTPSetup(ctx context.Context, req *authv1.VerifyTOTPSetupRequest) (*authv1.VerifyTOTPSetupResponse, error) {
	if err := s.requireSelfOrAdmin(ctx, req.UserId); err != nil {
		if st, ok := status.FromError(err); ok {
			return &authv1.VerifyTOTPSetupResponse{Verified: false, Error: st.Message()}, nil
		}
		return nil, err
	}
	secret, loginRequired, err := s.store.GetTOTPSecret(req.UserId)
	if err != nil || secret == "" {
		return &authv1.VerifyTOTPSetupResponse{Verified: false, Error: "TOTP not configured for this user"}, nil
	}
	if loginRequired {
		return &authv1.VerifyTOTPSetupResponse{Verified: false, Error: "TOTP already verified for this user"}, nil
	}

	if !totp.Validate(req.TotpCode, secret) {
		return &authv1.VerifyTOTPSetupResponse{Verified: false, Error: "invalid TOTP code"}, nil
	}

	if err := s.store.VerifyTOTPSetup(req.UserId); err != nil {
		return nil, status.Error(codes.Internal, "save verification")
	}

	return &authv1.VerifyTOTPSetupResponse{Verified: true}, nil
}

// --- User Management ---

func (s *AuthServer) CreateUser(ctx context.Context, req *authv1.CreateUserRequest) (*authv1.CreateUserResponse, error) {
	if req.Username == "" || req.Password == "" {
		return &authv1.CreateUserResponse{Error: "username and password are required"}, nil
	}
	count, err := s.userCount()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if count > 0 {
		if err := s.requireAdmin(ctx); err != nil {
			if st, ok := status.FromError(err); ok {
				return &authv1.CreateUserResponse{Error: st.Message()}, nil
			}
			return nil, err
		}
	}
	user, err := s.store.CreateUser(req.Username, req.Password)
	if err != nil {
		return &authv1.CreateUserResponse{Error: err.Error()}, nil
	}
	if count == 0 {
		if err := s.store.SetRoles(user.ID, []string{"admin"}); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		user.Roles = []string{"admin"}
	}
	return &authv1.CreateUserResponse{UserId: user.ID}, nil
}

func (s *AuthServer) DeleteUser(ctx context.Context, req *authv1.DeleteUserRequest) (*authv1.DeleteUserResponse, error) {
	if err := s.requireAdmin(ctx); err != nil {
		if st, ok := status.FromError(err); ok {
			return &authv1.DeleteUserResponse{Error: st.Message()}, nil
		}
		return nil, err
	}
	if err := s.store.DeleteUser(req.UserId); err != nil {
		return &authv1.DeleteUserResponse{Error: err.Error()}, nil
	}
	return &authv1.DeleteUserResponse{}, nil
}

func (s *AuthServer) ListUsers(ctx context.Context, req *authv1.ListUsersRequest) (*authv1.ListUsersResponse, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	users, err := s.store.ListUsers()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	var infos []*authv1.UserInfo
	for _, u := range users {
		_, totpEnabled, _ := s.store.GetTOTPSecret(u.ID)
		infos = append(infos, &authv1.UserInfo{
			Id:          u.ID,
			Username:    u.Username,
			Roles:       u.Roles,
			TotpEnabled: totpEnabled,
			TenantId:    u.TenantID,
		})
	}
	return &authv1.ListUsersResponse{Users: infos}, nil
}

func (s *AuthServer) SetPassword(ctx context.Context, req *authv1.SetPasswordRequest) (*authv1.SetPasswordResponse, error) {
	if err := s.requireAdmin(ctx); err != nil {
		if st, ok := status.FromError(err); ok {
			return &authv1.SetPasswordResponse{Error: st.Message()}, nil
		}
		return nil, err
	}
	if err := s.store.SetPassword(req.UserId, req.Password); err != nil {
		return &authv1.SetPasswordResponse{Error: err.Error()}, nil
	}
	return &authv1.SetPasswordResponse{}, nil
}

func (s *AuthServer) SetRoles(ctx context.Context, req *authv1.SetRolesRequest) (*authv1.SetRolesResponse, error) {
	if err := s.requireAdmin(ctx); err != nil {
		if st, ok := status.FromError(err); ok {
			return &authv1.SetRolesResponse{Error: st.Message()}, nil
		}
		return nil, err
	}
	if err := s.store.SetRoles(req.UserId, req.Roles); err != nil {
		return &authv1.SetRolesResponse{Error: err.Error()}, nil
	}
	return &authv1.SetRolesResponse{}, nil
}

// --- API Tokens ---

func (s *AuthServer) CreateAPIToken(ctx context.Context, req *authv1.CreateAPITokenRequest) (*authv1.CreateAPITokenResponse, error) {
	if req.UserId == "" || req.Name == "" {
		return &authv1.CreateAPITokenResponse{Error: "user_id and name are required"}, nil
	}
	if err := s.requireSelfOrAdmin(ctx, req.UserId); err != nil {
		if st, ok := status.FromError(err); ok {
			return &authv1.CreateAPITokenResponse{Error: st.Message()}, nil
		}
		return nil, err
	}
	token, info, err := s.store.CreateAPIToken(req.UserId, req.Name, req.Scopes)
	if err != nil {
		return &authv1.CreateAPITokenResponse{Error: err.Error()}, nil
	}
	return &authv1.CreateAPITokenResponse{
		Token:   token,
		TokenId: info.ID,
	}, nil
}

func (s *AuthServer) ListAPITokens(ctx context.Context, req *authv1.ListAPITokensRequest) (*authv1.ListAPITokensResponse, error) {
	if err := s.requireSelfOrAdmin(ctx, req.UserId); err != nil {
		return nil, err
	}
	tokens, err := s.store.ListAPITokens(req.UserId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	var infos []*authv1.APITokenInfo
	for _, t := range tokens {
		infos = append(infos, &authv1.APITokenInfo{
			Id:        t.ID,
			Name:      t.Name,
			Prefix:    t.Prefix,
			Scopes:    t.Scopes,
			CreatedAt: t.CreatedAt.Format(time.RFC3339),
		})
	}
	return &authv1.ListAPITokensResponse{Tokens: infos}, nil
}

func (s *AuthServer) DeleteAPIToken(ctx context.Context, req *authv1.DeleteAPITokenRequest) (*authv1.DeleteAPITokenResponse, error) {
	ownerID, err := s.store.APITokenUserID(req.TokenId)
	if err != nil {
		return &authv1.DeleteAPITokenResponse{Error: err.Error()}, nil
	}
	if err := s.requireSelfOrAdmin(ctx, ownerID); err != nil {
		if st, ok := status.FromError(err); ok {
			return &authv1.DeleteAPITokenResponse{Error: st.Message()}, nil
		}
		return nil, err
	}
	if err := s.store.DeleteAPIToken(req.TokenId); err != nil {
		return &authv1.DeleteAPITokenResponse{Error: err.Error()}, nil
	}
	return &authv1.DeleteAPITokenResponse{}, nil
}

// --- WebAuthn Credential Management ---

func (s *AuthServer) ListWebAuthnCredentials(ctx context.Context, req *authv1.ListWebAuthnCredentialsRequest) (*authv1.ListWebAuthnCredentialsResponse, error) {
	if err := s.requireSelfOrAdmin(ctx, req.UserId); err != nil {
		if st, ok := status.FromError(err); ok {
			return &authv1.ListWebAuthnCredentialsResponse{Error: st.Message()}, nil
		}
		return nil, err
	}
	infos, err := s.store.ListWebAuthnCredentialMeta(req.UserId)
	if err != nil {
		return &authv1.ListWebAuthnCredentialsResponse{Error: "list failed"}, nil
	}
	var pbCreds []*authv1.WebAuthnCredentialInfo
	for _, info := range infos {
		pbCreds = append(pbCreds, &authv1.WebAuthnCredentialInfo{
			Id:             info.ID,
			CredentialType: info.CredentialType,
			Transports:     info.Transports,
			Aaguid:         info.AAGUID,
			CreatedAt:      info.CreatedAt.Format(time.RFC3339),
			LastUsedAt:     info.LastUsedAt.Format(time.RFC3339),
		})
	}
	return &authv1.ListWebAuthnCredentialsResponse{Credentials: pbCreds}, nil
}

func (s *AuthServer) DeleteWebAuthnCredential(ctx context.Context, req *authv1.DeleteWebAuthnCredentialRequest) (*authv1.DeleteWebAuthnCredentialResponse, error) {
	if err := s.requireSelfOrAdmin(ctx, req.UserId); err != nil {
		if st, ok := status.FromError(err); ok {
			return &authv1.DeleteWebAuthnCredentialResponse{Error: st.Message()}, nil
		}
		return nil, err
	}
	if err := s.store.DeleteWebAuthnCredential(req.UserId, req.CredentialId); err != nil {
		return &authv1.DeleteWebAuthnCredentialResponse{Error: "delete failed"}, nil
	}
	return &authv1.DeleteWebAuthnCredentialResponse{}, nil
}

func (s *AuthServer) BeginAdminRegistration(ctx context.Context, req *authv1.BeginAdminRegistrationRequest) (*authv1.BeginAdminRegistrationResponse, error) {
	if err := s.requireAdmin(ctx); err != nil {
		if st, ok := status.FromError(err); ok {
			return &authv1.BeginAdminRegistrationResponse{Error: st.Message()}, nil
		}
		return nil, err
	}
	// Load user with WebAuthn credentials
	user, err := s.loadWebAuthnUser(req.UserId)
	if err != nil {
		return &authv1.BeginAdminRegistrationResponse{Error: err.Error()}, nil
	}

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: s.rpName,
		RPID:          s.rpID,
		RPOrigins:     s.rpOrigins,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "webauthn init failed")
	}

	options, sessionData, err := web.BeginRegistration(user)
	if err != nil {
		return &authv1.BeginAdminRegistrationResponse{Error: "registration failed"}, nil
	}

	sd, _ := json.Marshal(sessionData)
	if err := s.store.SaveWebAuthnSession(req.UserId, sessionData.Challenge, sd); err != nil {
		return nil, status.Error(codes.Internal, "save session failed")
	}

	optsJSON, _ := json.Marshal(options)
	return &authv1.BeginAdminRegistrationResponse{
		OptionsJson: optsJSON,
		Challenge:   sessionData.Challenge,
	}, nil
}

func (s *AuthServer) CompleteAdminRegistration(ctx context.Context, req *authv1.CompleteAdminRegistrationRequest) (*authv1.CompleteAdminRegistrationResponse, error) {
	if err := s.requireAdmin(ctx); err != nil {
		if st, ok := status.FromError(err); ok {
			return &authv1.CompleteAdminRegistrationResponse{Error: st.Message()}, nil
		}
		return nil, err
	}
	sd, err := s.store.GetWebAuthnSession(req.Challenge)
	if err != nil {
		return &authv1.CompleteAdminRegistrationResponse{Error: "challenge not found or expired"}, nil
	}
	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sd, &sessionData); err != nil {
		return &authv1.CompleteAdminRegistrationResponse{Error: "invalid session data"}, nil
	}
	_ = s.store.DeleteWebAuthnSession(sessionData.Challenge)

	user, err := s.loadWebAuthnUser(req.UserId)
	if err != nil {
		return &authv1.CompleteAdminRegistrationResponse{Error: err.Error()}, nil
	}

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: s.rpName,
		RPID:          s.rpID,
		RPOrigins:     s.rpOrigins,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "webauthn init failed")
	}

	// Reconstruct HTTP request for FinishRegistration with the first allowed origin.
	origin := "http://localhost:8082"
	if len(s.rpOrigins) > 0 {
		origin = s.rpOrigins[0]
	}
	httpReq, _ := http.NewRequest("POST", "/", bytes.NewReader(req.CredentialResponseJson))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Origin", origin)

	credential, err := web.FinishRegistration(user, sessionData, httpReq)
	if err != nil {
		return &authv1.CompleteAdminRegistrationResponse{Error: "registration verification failed"}, nil
	}

	credData, _ := json.Marshal(credential)
	if err := s.store.AddWebAuthnCredential(req.UserId, credData); err != nil {
		return nil, status.Error(codes.Internal, "save credential failed")
	}

	slog.Info("webauthn: credential registered via gRPC", "user", user.store.Username)
	return &authv1.CompleteAdminRegistrationResponse{}, nil
}

func (s *AuthServer) loadWebAuthnUser(userID string) (*webUser, error) {
	su, err := s.store.GetUser(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	u := &webUser{store: su}
	creds, err := s.store.ListWebAuthnCredentials(su.ID)
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

// webUser wraps authStore.User to implement webauthn.User.
type webUser struct {
	store *authStore.User
	creds []webauthn.Credential
}

func (u *webUser) WebAuthnID() []byte                         { return []byte(u.store.ID) }
func (u *webUser) WebAuthnName() string                       { return u.store.Username }
func (u *webUser) WebAuthnDisplayName() string                { return u.store.Username }
func (u *webUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// AuthorizeForTest evaluates RBAC without a store user lookup (tests only).
func (s *AuthServer) AuthorizeForTest(roles []string, action, resource string) (bool, string) {
	if s.policy == nil {
		return false, "no policy loaded"
	}
	return s.policy.IsAllowed(roles, action, resource)
}

func rateLimitKey(ctx context.Context, username string) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	if username != "" {
		return "user:" + username
	}
	return "unknown"
}

func (s *AuthServer) checkRateLimit(key string) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	rec, exists := s.rateRecords[key]
	if !exists {
		rec = &loginRateRecord{}
		s.rateRecords[key] = rec
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
