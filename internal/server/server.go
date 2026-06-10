package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"

	"github.com/Muxcore-Media/auth-local/internal/policy"
	"github.com/Muxcore-Media/auth-local/internal/store"
)

const issuerName = "MuxCore"

// AuthServer implements the AuthService gRPC server.
type AuthServer struct {
	authv1.UnimplementedAuthServiceServer
	store  *store.Store
	policy *policy.Policy
}

func New(s *store.Store, p *policy.Policy) *AuthServer {
	return &AuthServer{store: s, policy: p}
}

func (s *AuthServer) RegisterWithGRPC(srv *grpc.Server) {
	authv1.RegisterAuthServiceServer(srv, s)
}

func (s *AuthServer) Authenticate(ctx context.Context, req *authv1.AuthenticateRequest) (*authv1.AuthenticateResponse, error) {
	switch req.CredentialType {
	case "password":
		return s.authPassword(req)
	case "totp":
		return s.authTOTP(req)
	case "api-key":
		return s.authAPIKey(req)
	default:
		return &authv1.AuthenticateResponse{
			Authenticated: false,
			Error:         "unsupported credential type: " + req.CredentialType,
		}, nil
	}
}

func (s *AuthServer) authPassword(req *authv1.AuthenticateRequest) (*authv1.AuthenticateResponse, error) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(req.CredentialData, &creds); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid credential data")
	}

	user, err := s.store.VerifyPassword(creds.Username, creds.Password)
	if err != nil {
		slog.Warn("auth: password verification failed", "username", creds.Username)
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
			Requires_2Fa:      true,
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

	return &authv1.AuthenticateResponse{
		Authenticated: true,
		SessionToken:  sess.Token,
		UserId:        user.ID,
		Username:      user.Username,
		Roles:         user.Roles,
	}, nil
}

func (s *AuthServer) authTOTP(req *authv1.AuthenticateRequest) (*authv1.AuthenticateResponse, error) {
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

	return &authv1.AuthenticateResponse{
		Authenticated: true,
		SessionToken:  token.Token,
		UserId:        user.ID,
		Username:      user.Username,
		Roles:         user.Roles,
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
	}, nil
}

func (s *AuthServer) Revoke(ctx context.Context, req *authv1.RevokeRequest) (*authv1.RevokeResponse, error) {
	s.store.DeleteSession(req.Token)
	return &authv1.RevokeResponse{}, nil
}

func (s *AuthServer) Can(ctx context.Context, req *authv1.CanRequest) (*authv1.CanResponse, error) {
	user, err := s.store.GetUser(req.UserId)
	if err != nil {
		return &authv1.CanResponse{Allowed: false, Reason: "user not found"}, nil
	}

	var allowed bool
	var reason string
	if s.policy != nil {
		allowed, reason = s.policy.IsAllowed(user.Roles, req.Action, req.Resource)
	} else {
		allowed, reason = authorizeBuiltin(user.Roles, req.Action, req.Resource)
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
					Found: true,
					Id:    user.ID,
					Kind:  "user",
					Roles: user.Roles,
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
		Secret:     key.Secret(),
		QrCodeUrl:  qrURL,
	}, nil
}

func (s *AuthServer) DisableTOTP(ctx context.Context, req *authv1.DisableTOTPRequest) (*authv1.DisableTOTPResponse, error) {
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
	secret, enabled, err := s.store.GetTOTPSecret(req.UserId)
	if err != nil || !enabled {
		return &authv1.VerifyTOTPSetupResponse{Verified: false, Error: "TOTP not enabled for this user"}, nil
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
	user, err := s.store.CreateUser(req.Username, req.Password)
	if err != nil {
		return &authv1.CreateUserResponse{Error: err.Error()}, nil
	}
	return &authv1.CreateUserResponse{UserId: user.ID}, nil
}

func (s *AuthServer) DeleteUser(ctx context.Context, req *authv1.DeleteUserRequest) (*authv1.DeleteUserResponse, error) {
	if err := s.store.DeleteUser(req.UserId); err != nil {
		return &authv1.DeleteUserResponse{Error: err.Error()}, nil
	}
	return &authv1.DeleteUserResponse{}, nil
}

func (s *AuthServer) ListUsers(ctx context.Context, req *authv1.ListUsersRequest) (*authv1.ListUsersResponse, error) {
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
		})
	}
	return &authv1.ListUsersResponse{Users: infos}, nil
}

func (s *AuthServer) SetPassword(ctx context.Context, req *authv1.SetPasswordRequest) (*authv1.SetPasswordResponse, error) {
	if err := s.store.SetPassword(req.UserId, req.Password); err != nil {
		return &authv1.SetPasswordResponse{Error: err.Error()}, nil
	}
	return &authv1.SetPasswordResponse{}, nil
}

func (s *AuthServer) SetRoles(ctx context.Context, req *authv1.SetRolesRequest) (*authv1.SetRolesResponse, error) {
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
	if err := s.store.DeleteAPIToken(req.TokenId); err != nil {
		return &authv1.DeleteAPITokenResponse{Error: err.Error()}, nil
	}
	return &authv1.DeleteAPITokenResponse{}, nil
}

func authorizeBuiltin(roles []string, action, resource string) (bool, string) {
	for _, role := range roles {
		switch role {
		case "admin":
			return true, ""
		case "manager":
			if resource == "modules.manage" {
				return true, ""
			}
			fallthrough
		case "user":
			if action == "read" || action == "view" || action == "request" {
				return true, ""
			}
		case "viewer":
			if action == "view" || action == "read" {
				return true, ""
			}
		}
	}
	return false, "insufficient permissions"
}
