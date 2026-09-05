package server

import (
	"context"
	"testing"
	"time"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"
)

func adminContext(t *testing.T, srv *AuthServer) context.Context {
	t.Helper()
	user, err := srv.store.CreateUser("admin", "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := srv.store.SetRoles(user.ID, []string{"admin"}); err != nil {
		t.Fatalf("SetRoles: %v", err)
	}
	return authContext(t, srv, user.ID)
}

func TestCreateInvite_RequiresAdmin(t *testing.T) {
	srv := newTestServer(t)
	_, _ = srv.store.CreateUser("alice", "password123")

	resp, err := srv.CreateInvite(context.Background(), &authv1.CreateInviteRequest{
		Role:       "user",
		TtlSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if resp.Error == "" {
		t.Fatal("expected unauthenticated CreateInvite to fail")
	}
}

func TestCreateInvite_NonAdminDenied(t *testing.T) {
	srv := newTestServer(t)
	user, _ := srv.store.CreateUser("alice", "password123")

	resp, err := srv.CreateInvite(authContext(t, srv, user.ID), &authv1.CreateInviteRequest{
		Role:       "user",
		TtlSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if resp.Error == "" {
		t.Fatal("expected non-admin CreateInvite to fail")
	}
}

func TestInviteGRPC_CreateListRevokeRedeem(t *testing.T) {
	srv := newTestServer(t)
	ctx := adminContext(t, srv)

	createResp, err := srv.CreateInvite(ctx, &authv1.CreateInviteRequest{
		Role:       "viewer",
		TenantId:   "household-a",
		MaxUses:    1,
		TtlSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if createResp.Error != "" || createResp.Token == "" {
		t.Fatalf("create: %+v", createResp)
	}

	listResp, err := srv.ListInvites(ctx, &authv1.ListInvitesRequest{})
	if err != nil {
		t.Fatalf("ListInvites: %v", err)
	}
	if len(listResp.Invites) != 1 || listResp.Invites[0].Prefix != createResp.Prefix {
		t.Fatalf("list: %+v", listResp.Invites)
	}
	if listResp.Invites[0].TenantId != "household-a" {
		t.Fatalf("tenant: %+v", listResp.Invites[0])
	}

	redeemResp, err := srv.RedeemInvite(context.Background(), &authv1.RedeemInviteRequest{
		Token:    createResp.Token,
		Username: "newbie",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("RedeemInvite: %v", err)
	}
	if redeemResp.Error != "" || redeemResp.Username != "newbie" {
		t.Fatalf("redeem: %+v", redeemResp)
	}
	if len(redeemResp.Roles) != 1 || redeemResp.Roles[0] != "viewer" {
		t.Fatalf("roles: %+v", redeemResp.Roles)
	}

	revokeResp, err := srv.RevokeInvite(ctx, &authv1.RevokeInviteRequest{InviteId: createResp.InviteId})
	if err != nil {
		t.Fatalf("RevokeInvite: %v", err)
	}
	if revokeResp.Error != "" {
		t.Fatalf("revoke: %+v", revokeResp)
	}
}

func TestRedeemInvite_Expired(t *testing.T) {
	srv := newTestServer(t)
	ctx := adminContext(t, srv)

	createResp, err := srv.CreateInvite(ctx, &authv1.CreateInviteRequest{
		Role:       "user",
		MaxUses:    1,
		TtlSeconds: 1,
	})
	if err != nil || createResp.Error != "" {
		t.Fatalf("CreateInvite: %v %+v", err, createResp)
	}
	time.Sleep(1100 * time.Millisecond)

	redeemResp, err := srv.RedeemInvite(context.Background(), &authv1.RedeemInviteRequest{
		Token:    createResp.Token,
		Username: "late",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("RedeemInvite: %v", err)
	}
	if redeemResp.Error == "" {
		t.Fatal("expected expired invite redeem to fail")
	}
}

func TestRedeemInvite_Revoked(t *testing.T) {
	srv := newTestServer(t)
	ctx := adminContext(t, srv)

	createResp, err := srv.CreateInvite(ctx, &authv1.CreateInviteRequest{
		Role:       "user",
		MaxUses:    1,
		TtlSeconds: 3600,
	})
	if err != nil || createResp.Error != "" {
		t.Fatalf("CreateInvite: %v %+v", err, createResp)
	}
	revokeResp, err := srv.RevokeInvite(ctx, &authv1.RevokeInviteRequest{InviteId: createResp.InviteId})
	if err != nil || revokeResp.Error != "" {
		t.Fatalf("RevokeInvite: %v %+v", err, revokeResp)
	}

	redeemResp, err := srv.RedeemInvite(context.Background(), &authv1.RedeemInviteRequest{
		Token:    createResp.Token,
		Username: "blocked",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("RedeemInvite: %v", err)
	}
	if redeemResp.Error == "" {
		t.Fatal("expected revoked invite redeem to fail")
	}
}

func TestCreateInvite_MeshCaller(t *testing.T) {
	srv := newTestServer(t)
	resp, err := srv.CreateInvite(verifiedMeshContext("muxcore"), &authv1.CreateInviteRequest{
		Role:       "admin",
		TtlSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if resp.Error != "" || resp.Token == "" {
		t.Fatalf("mesh create: %+v", resp)
	}
}

func TestListInvites_RequiresAdmin(t *testing.T) {
	srv := newTestServer(t)
	_, err := srv.ListInvites(context.Background(), &authv1.ListInvitesRequest{})
	if err == nil {
		t.Fatal("expected unauthenticated ListInvites to fail")
	}
}
