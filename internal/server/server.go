package server

import (
	"context"
	"encoding/json"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"

	"github.com/Muxcore-Media/auth-local/internal/store"
)

// AuthServer implements the AuthService gRPC server.
type AuthServer struct {
	authv1.UnimplementedAuthServiceServer
	store *store.Store
}

func New(s *store.Store) *AuthServer {
	return &AuthServer{store: s}
}

func (s *AuthServer) RegisterWithGRPC(srv *grpc.Server) {
	authv1.RegisterAuthServiceServer(srv, s)
}

func (s *AuthServer) Authenticate(ctx context.Context, req *authv1.AuthenticateRequest) (*authv1.AuthenticateResponse, error) {
	switch req.CredentialType {
	case "password":
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
		if user.TOTPEnabled {
			sess, err := s.store.CreatePartialSession(user.ID)
			if err != nil {
				return nil, status.Error(codes.Internal, "create partial session failed")
			}
			return &authv1.AuthenticateResponse{
				Authenticated:    false,
				Requires_2Fa:      true,
				PartialToken:     sess.Token,
				AvailableMethods: []string{"totp", "passkey"},
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

	default:
		return &authv1.AuthenticateResponse{
			Authenticated: false,
			Error:         "unsupported credential type: " + req.CredentialType,
		}, nil
	}
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
		Valid:       true,
		UserId:      user.ID,
		Username:    user.Username,
		Roles:       user.Roles,
	}, nil
}

func (s *AuthServer) Revoke(ctx context.Context, req *authv1.RevokeRequest) (*authv1.RevokeResponse, error) {
	s.store.DeleteSession(req.Token)
	return &authv1.RevokeResponse{}, nil
}

func (s *AuthServer) Can(ctx context.Context, req *authv1.CanRequest) (*authv1.CanResponse, error) {
	// Look up the user's roles.
	user, err := s.store.GetUser(req.UserId)
	if err != nil {
		return &authv1.CanResponse{Allowed: false, Reason: "user not found"}, nil
	}

	allowed, reason := authorize(user.Roles, req.Action, req.Resource)
	return &authv1.CanResponse{Allowed: allowed, Reason: reason}, nil
}

func (s *AuthServer) ExtractIdentity(ctx context.Context, req *authv1.ExtractIdentityRequest) (*authv1.ExtractIdentityResponse, error) {
	if req.Token == "" && req.CallerId == "" {
		return &authv1.ExtractIdentityResponse{Found: false}, nil
	}

	// Try token-based auth first.
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

	// Try module identity.
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

// authorize checks if the given roles permit an action on a resource.
func authorize(roles []string, action, resource string) (bool, string) {
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
