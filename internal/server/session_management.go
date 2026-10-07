package server

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"
)

// requireSessionAdmin intentionally differs from requireAdmin: these RPCs
// require an end-user bearer even when the transport has a verified mesh peer.
func (s *AuthServer) requireSessionAdmin(ctx context.Context) error {
	token := sessionTokenFromContext(ctx)
	if token == "" {
		return status.Error(codes.Unauthenticated, "missing auth token")
	}
	roles, err := s.store.SessionAdminRoles(ctx, token)
	if errors.Is(err, sql.ErrNoRows) {
		return status.Error(codes.Unauthenticated, "invalid or expired session")
	}
	if err != nil {
		return sessionManagementError(err, "session authentication failed")
	}
	if !hasRole(roles, "admin") {
		return status.Error(codes.PermissionDenied, "admin role required")
	}
	return nil
}

func (s *AuthServer) ListSessions(ctx context.Context, req *authv1.ListSessionsRequest) (*authv1.ListSessionsResponse, error) {
	if err := s.requireSessionAdmin(ctx); err != nil {
		return nil, err
	}
	entries, next, err := s.store.ListActiveSessions(ctx, req.GetUserId(), int(req.GetPageSize()), req.GetPageToken())
	if errors.Is(err, authStore.ErrInvalidSessionPage) {
		return nil, status.Error(codes.InvalidArgument, "invalid session pagination")
	}
	if err != nil {
		return nil, sessionManagementError(err, "list sessions failed")
	}
	response := &authv1.ListSessionsResponse{NextPageToken: next}
	for _, entry := range entries {
		response.Sessions = append(response.Sessions, &authv1.SessionInfo{
			SessionId: entry.ID, UserId: entry.UserID, Username: entry.Username, Kind: entry.Kind,
			CreatedAt: entry.CreatedAt.Format(time.RFC3339Nano), ExpiresAt: entry.ExpiresAt.Format(time.RFC3339Nano),
		})
	}
	return response, nil
}

func (s *AuthServer) RevokeSession(ctx context.Context, req *authv1.RevokeSessionRequest) (*authv1.RevokeSessionResponse, error) {
	if err := s.requireSessionAdmin(ctx); err != nil {
		return nil, err
	}
	if req.GetUserId() == "" || req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id and session_id are required")
	}
	if err := s.store.RevokeSession(ctx, req.GetUserId(), req.GetSessionId()); err != nil {
		return nil, sessionManagementError(err, "revoke session failed")
	}
	return &authv1.RevokeSessionResponse{}, nil
}

func sessionManagementError(err error, message string) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	return status.Error(codes.Internal, message)
}
