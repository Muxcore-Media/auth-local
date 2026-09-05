package server

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"
)

func TestCreateUser_RequiresAdminAfterBootstrap(t *testing.T) {
	srv := newTestServer(t)
	_, _ = srv.store.CreateUser("bootstrap", "pw")

	resp, err := srv.CreateUser(context.Background(), &authv1.CreateUserRequest{
		Username: "second",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if resp.Error == "" {
		t.Fatal("expected second user creation without auth to fail")
	}
}

func TestTOTPStatus_Unauthenticated(t *testing.T) {
	srv := newTestServer(t)
	user, _ := srv.store.CreateUser("alice", "pw")

	_, err := srv.TOTPStatus(context.Background(), &authv1.TOTPStatusRequest{UserId: user.ID})
	if err == nil {
		t.Fatal("expected unauthenticated TOTPStatus to fail")
	}
}

func TestCreateAPIToken_Unauthenticated(t *testing.T) {
	srv := newTestServer(t)
	user, _ := srv.store.CreateUser("alice", "pw")

	resp, err := srv.CreateAPIToken(context.Background(), &authv1.CreateAPITokenRequest{
		UserId: user.ID,
		Name:   "cli",
	})
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	if resp.Error == "" {
		t.Fatal("expected unauthenticated CreateAPIToken to fail")
	}
}

func TestDeleteUser_RequiresAdmin(t *testing.T) {
	srv := newTestServer(t)
	user, _ := srv.store.CreateUser("alice", "pw")

	resp, err := srv.DeleteUser(context.Background(), &authv1.DeleteUserRequest{UserId: user.ID})
	if err == nil {
		if resp.Error == "" {
			t.Fatal("expected unauthenticated DeleteUser to fail")
		}
	}
}

func TestRequireAdmin_RejectsSpoofedMeshMetadata(t *testing.T) {
	srv := newTestServer(t)
	_, _ = srv.store.CreateUser("alice", "pw")

	_, err := srv.ListUsers(meshContext("muxcore"), &authv1.ListUsersRequest{})
	if err == nil {
		t.Fatal("expected spoofed x-caller-id without TLS peer cert to be rejected")
	}
}

func TestRequireAdmin_AllowsVerifiedMeshCaller(t *testing.T) {
	srv := newTestServer(t)
	_, _ = srv.store.CreateUser("alice", "pw")

	resp, err := srv.ListUsers(verifiedMeshContext("muxcore"), &authv1.ListUsersRequest{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(resp.Users) == 0 {
		t.Fatal("expected verified mesh caller to list users")
	}
}

func TestRequireAdmin_RejectsMismatchedMeshMetadata(t *testing.T) {
	srv := newTestServer(t)
	_, _ = srv.store.CreateUser("alice", "pw")

	ctx := verifiedMeshContext("muxcore")
	md, _ := metadata.FromIncomingContext(ctx)
	md.Set(callerIDMetadataKey, "downloader")
	ctx = metadata.NewIncomingContext(ctx, md)

	_, err := srv.ListUsers(ctx, &authv1.ListUsersRequest{})
	if err == nil {
		t.Fatal("expected mismatched x-caller-id vs TLS CN to be rejected")
	}
}
