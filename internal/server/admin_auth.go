package server

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

const (
	authTokenMetadataKey = "x-auth-token"
	callerIDMetadataKey  = "x-caller-id"
)

func sessionTokenFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get(authTokenMetadataKey)
	if len(vals) == 0 {
		return ""
	}
	return strings.TrimSpace(vals[0])
}

func meshCallerFromContext(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	vals := md.Get(callerIDMetadataKey)
	if len(vals) == 0 {
		return "", false
	}
	callerID := strings.TrimSpace(vals[0])
	return callerID, callerID != ""
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

func (s *AuthServer) callerFromContext(ctx context.Context) (*authStore.User, error) {
	token := sessionTokenFromContext(ctx)
	if token == "" {
		return nil, status.Error(codes.Unauthenticated, "missing auth token")
	}
	sess, err := s.store.GetSession(token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired session")
	}
	if sess.Kind != "full" && sess.Kind != "api-token" {
		return nil, status.Error(codes.Unauthenticated, "session not fully authenticated")
	}
	user, err := s.store.GetUser(sess.UserID)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "user not found")
	}
	return user, nil
}

func (s *AuthServer) requireAdmin(ctx context.Context) error {
	if _, ok := meshCallerFromContext(ctx); ok {
		return nil
	}
	user, err := s.callerFromContext(ctx)
	if err != nil {
		return err
	}
	if !hasRole(user.Roles, "admin") {
		return status.Error(codes.PermissionDenied, "admin role required")
	}
	return nil
}

func (s *AuthServer) requireAuthOrMesh(ctx context.Context) (*authStore.User, bool, error) {
	if _, ok := meshCallerFromContext(ctx); ok {
		return nil, true, nil
	}
	user, err := s.callerFromContext(ctx)
	if err != nil {
		return nil, false, err
	}
	return user, false, nil
}

func (s *AuthServer) requireSelfOrAdmin(ctx context.Context, userID string) error {
	if _, ok := meshCallerFromContext(ctx); ok {
		return nil
	}
	user, err := s.callerFromContext(ctx)
	if err != nil {
		return err
	}
	if user.ID == userID {
		return nil
	}
	if hasRole(user.Roles, "admin") {
		return nil
	}
	return status.Error(codes.PermissionDenied, "permission denied")
}

func (s *AuthServer) userCount() (int, error) {
	users, err := s.store.ListUsers()
	if err != nil {
		return 0, err
	}
	return len(users), nil
}
