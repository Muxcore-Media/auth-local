package server

import (
	"context"
	"testing"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"
)

func TestDeleteUserPublishesIdentityEvent(t *testing.T) {
	srv := newTestServer(t)
	ctx := adminContext(t, srv)
	user, err := srv.store.CreateUser("pat", "password123")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	srv.SetUserDeletedPublisher(func(_ context.Context, userID string) {
		got = append(got, userID)
	})

	resp, err := srv.DeleteUser(ctx, &authv1.DeleteUserRequest{UserId: user.ID})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Error != "" {
		t.Fatal(resp.Error)
	}
	if len(got) != 1 || got[0] != user.ID {
		t.Fatalf("published %#v", got)
	}

	resp, err = srv.DeleteUser(ctx, &authv1.DeleteUserRequest{UserId: "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Error == "" {
		t.Fatal("expected missing user to fail")
	}
	if len(got) != 1 {
		t.Fatalf("published after failure %#v", got)
	}
}
