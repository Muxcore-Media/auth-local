package server

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"
)

func TestCreateInviteSuppliedBearerCannotFallBackToMesh(t *testing.T) {
	srv := newTestServer(t)
	admin := mkUser(t, srv, "admin", "", "admin")
	member := mkUser(t, srv, "member", "")
	demoted := mkUser(t, srv, "demoted", "", "admin")
	demotedToken := bearer(t, srv, demoted.ID, "full", time.Hour)
	if err := srv.store.SetRoles(demoted.ID, []string{"user"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		code codes.Code
	}{
		{"invalid", withBearer(verifiedMeshContext("muxcore"), "invalid-token"), codes.Unauthenticated},
		{"empty", withBearer(verifiedMeshContext("muxcore"), ""), codes.Unauthenticated},
		{"whitespace", withBearer(verifiedMeshContext("muxcore"), "  "), codes.Unauthenticated},
		{"partial", withBearer(verifiedMeshContext("muxcore"), bearer(t, srv, admin.ID, "partial", time.Hour)), codes.Unauthenticated},
		{"expired", withBearer(verifiedMeshContext("muxcore"), bearer(t, srv, admin.ID, "full", -time.Hour)), codes.Unauthenticated},
		{"non-admin", withBearer(verifiedMeshContext("muxcore"), bearer(t, srv, member.ID, "full", time.Hour)), codes.PermissionDenied},
		{"demoted", withBearer(verifiedMeshContext("muxcore"), demotedToken), codes.PermissionDenied},
		{"unverified-certificate", unverifiedMeshContext("muxcore"), codes.Unauthenticated},
		{"spoofed-header", meshContext("muxcore"), codes.Unauthenticated},
		{"no-credentials", context.Background(), codes.Unauthenticated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, authErr := srv.inviteCreator(tc.ctx)
			requireCode(t, authErr, tc.code)
			resp, err := srv.CreateInvite(tc.ctx, &authv1.CreateInviteRequest{Role: "viewer", TtlSeconds: 3600})
			if err != nil || resp.GetError() != status.Convert(authErr).Message() || resp.GetToken() != "" {
				t.Fatalf("refused authority returned invitation or changed error contract: %+v, %v", resp, err)
			}
			if invites, err := srv.store.ListInvites(); err != nil || len(invites) != 0 {
				t.Fatalf("refused authority persisted invites: %+v, %v", invites, err)
			}
		})
	}
}

func TestCreateInviteSelectsAdminBearerAlongsideMesh(t *testing.T) {
	for _, kind := range []string{"full", "api-token"} {
		t.Run(kind, func(t *testing.T) {
			srv := newTestServer(t)
			root := mkUser(t, srv, "root", "", "admin")
			creator := mkUser(t, srv, "inviter", "", "admin")
			ctx := withBearer(verifiedMeshContext("muxcore"), bearer(t, srv, creator.ID, kind, time.Hour))
			resp, err := srv.CreateInvite(ctx, &authv1.CreateInviteRequest{Role: "viewer", TenantId: "destination", MaxUses: -1, TtlSeconds: 3600})
			if err != nil || resp.GetError() != "" || resp.GetToken() == "" {
				t.Fatalf("admin bearer creation: %+v, %v", resp, err)
			}
			invites, err := srv.store.ListInvites()
			if err != nil || len(invites) != 1 {
				t.Fatalf("list created invitation: %+v, %v", invites, err)
			}
			inv := invites[0]
			if inv.CreatedBy != creator.Username || inv.Role != "viewer" || inv.TenantID != "destination" || inv.MaxUses != 0 {
				t.Fatalf("wrong authority or changed grant: %+v", inv)
			}
			if _, err := srv.store.EraseUser(context.Background(), root.ID, "", creator.ID); err != nil {
				t.Fatal(err)
			}
			invites, err = srv.store.ListInvites()
			if err != nil || len(invites) != 1 {
				t.Fatalf("list erased creator's invitation: %+v, %v", invites, err)
			}
			if inv := invites[0]; inv.CreatedBy != authStore.DeletedUserMarker || inv.RevokedAt.IsZero() {
				t.Fatalf("user bearer invitation survived creator erasure: %+v", inv)
			}
		})
	}
}

func TestCreateInviteWithoutBearerRetainsModuleAttribution(t *testing.T) {
	srv := newTestServer(t)
	resp, err := srv.CreateInvite(verifiedMeshContext("muxcore"), &authv1.CreateInviteRequest{Role: "admin", TenantId: "destination", TtlSeconds: 3600})
	if err != nil || resp.GetError() != "" || resp.GetToken() == "" {
		t.Fatalf("module creation: %+v, %v", resp, err)
	}
	invites, err := srv.store.ListInvites()
	if err != nil || len(invites) != 1 {
		t.Fatalf("list module invitation: %+v, %v", invites, err)
	}
	if inv := invites[0]; inv.CreatedBy != "muxcore" || inv.Role != "admin" || inv.TenantID != "destination" || inv.MaxUses != 1 {
		t.Fatalf("module admission, attribution or grant changed: %+v", inv)
	}
}
