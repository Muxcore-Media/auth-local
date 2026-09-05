package server

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

const defaultInviteTTL = 7 * 24 * time.Hour

func inviteInfoFromStore(inv *authStore.Invite) *authv1.InviteInfo {
	if inv == nil {
		return nil
	}
	info := &authv1.InviteInfo{
		Id:        inv.ID,
		Prefix:    inv.Prefix,
		CreatedBy: inv.CreatedBy,
		Role:      inv.Role,
		TenantId:  inv.TenantID,
		MaxUses:   int32(inv.MaxUses),
		UseCount:  int32(inv.UseCount),
		ExpiresAt: inv.ExpiresAt.UTC().Format(time.RFC3339),
		CreatedAt: inv.CreatedAt.UTC().Format(time.RFC3339),
	}
	if !inv.RevokedAt.IsZero() {
		info.RevokedAt = inv.RevokedAt.UTC().Format(time.RFC3339)
	}
	return info
}

func (s *AuthServer) inviteCreatedBy(ctx context.Context) string {
	if caller, ok := meshCallerFromContext(ctx); ok {
		return caller
	}
	user, err := s.callerFromContext(ctx)
	if err != nil || user == nil {
		return ""
	}
	return user.Username
}

func (s *AuthServer) CreateInvite(ctx context.Context, req *authv1.CreateInviteRequest) (*authv1.CreateInviteResponse, error) {
	if err := s.requireAdmin(ctx); err != nil {
		if st, ok := status.FromError(err); ok {
			return &authv1.CreateInviteResponse{Error: st.Message()}, nil
		}
		return nil, err
	}

	ttl := defaultInviteTTL
	if req.TtlSeconds > 0 {
		ttl = time.Duration(req.TtlSeconds) * time.Second
	}
	maxUses := 1
	if req.MaxUses < 0 {
		maxUses = 0
	} else if req.MaxUses > 0 {
		maxUses = int(req.MaxUses)
	}

	role := strings.TrimSpace(req.Role)
	tenantID := strings.TrimSpace(req.TenantId)
	inv, err := s.store.CreateInvite(s.inviteCreatedBy(ctx), role, tenantID, maxUses, ttl)
	if err != nil {
		return &authv1.CreateInviteResponse{Error: err.Error()}, nil
	}
	return &authv1.CreateInviteResponse{
		InviteId: inv.ID,
		Token:    inv.Token,
		Prefix:   inv.Prefix,
	}, nil
}

func (s *AuthServer) ListInvites(ctx context.Context, req *authv1.ListInvitesRequest) (*authv1.ListInvitesResponse, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	list, err := s.store.ListInvites()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	var infos []*authv1.InviteInfo
	for _, inv := range list {
		infos = append(infos, inviteInfoFromStore(inv))
	}
	return &authv1.ListInvitesResponse{Invites: infos}, nil
}

func (s *AuthServer) RevokeInvite(ctx context.Context, req *authv1.RevokeInviteRequest) (*authv1.RevokeInviteResponse, error) {
	if err := s.requireAdmin(ctx); err != nil {
		if st, ok := status.FromError(err); ok {
			return &authv1.RevokeInviteResponse{Error: st.Message()}, nil
		}
		return nil, err
	}
	if strings.TrimSpace(req.InviteId) == "" {
		return &authv1.RevokeInviteResponse{Error: "invite_id is required"}, nil
	}
	if err := s.store.RevokeInvite(req.InviteId); err != nil {
		return &authv1.RevokeInviteResponse{Error: err.Error()}, nil
	}
	return &authv1.RevokeInviteResponse{}, nil
}

func (s *AuthServer) RedeemInvite(ctx context.Context, req *authv1.RedeemInviteRequest) (*authv1.RedeemInviteResponse, error) {
	user, _, err := s.store.RedeemInvite(req.Token, req.Username, req.Password)
	if err != nil {
		return &authv1.RedeemInviteResponse{Error: err.Error()}, nil
	}
	return &authv1.RedeemInviteResponse{
		UserId:   user.ID,
		Username: user.Username,
		Roles:    user.Roles,
		TenantId: user.TenantID,
	}, nil
}
