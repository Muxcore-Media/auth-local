package store

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestErasureRevokesInvitesForLiteralDeletedUser(t *testing.T) {
	for _, username := range []string{"ordinary-inviter", DeletedUserMarker} {
		t.Run(username, func(t *testing.T) {
			s := newTestStore(t)
			admin := makeAdmin(t, s, "root", "")
			victim := makeAdmin(t, s, username, "")
			seed := seedUser(t, s, victim)
			bystander, err := s.CreateInvite("another-user", "viewer", "another-tenant", 0, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			moduleInvite, err := s.CreateInvite("muxcore", "manager", "", 1, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			beforeBystander := inviteByID(t, s, bystander.ID)
			beforeModule := inviteByID(t, s, moduleInvite.ID)
			beforeConsumed := inviteByID(t, s, seed.invExhausted)

			if _, err := s.EraseUser(context.Background(), admin.ID, "", victim.ID); err != nil {
				t.Fatal(err)
			}
			requireNoUserRows(t, s, victim.ID)
			if inv := inviteByID(t, s, seed.invUnredeemed); inv.RevokedAt.IsZero() || inv.CreatedBy != DeletedUserMarker {
				t.Errorf("erased inviter %q retained an active or identifying invite: %+v", username, inv)
			}
			consumed := inviteByID(t, s, seed.invExhausted)
			beforeConsumed.CreatedBy = DeletedUserMarker
			if !reflect.DeepEqual(consumed, beforeConsumed) {
				t.Errorf("consumed invite changed beyond anonymisation: got %+v, want %+v", consumed, beforeConsumed)
			}
			if got := inviteByID(t, s, bystander.ID); !reflect.DeepEqual(got, beforeBystander) {
				t.Errorf("bystander invite changed: got %+v, want %+v", got, beforeBystander)
			}
			if got := inviteByID(t, s, moduleInvite.ID); !reflect.DeepEqual(got, beforeModule) {
				t.Errorf("module invite changed: got %+v, want %+v", got, beforeModule)
			}
		})
	}
}

func TestErasureInviteCleanupRollsBackBeforeTombstoneAndRetries(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin := makeAdmin(t, s, "root", "")
	victim := makeAdmin(t, s, "victim", "")
	seed := seedUser(t, s, victim)
	beforeRows := userRowCounts(t, s, victim.ID)
	beforeOpen := inviteByID(t, s, seed.invUnredeemed)
	beforeConsumed := inviteByID(t, s, seed.invExhausted)
	if _, err := s.db.Exec(`CREATE TRIGGER reject_erasure BEFORE INSERT ON user_erasures
		BEGIN SELECT RAISE(ABORT, 'injected tombstone failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EraseUser(ctx, admin.ID, "", victim.ID); err == nil || !strings.Contains(err.Error(), "injected tombstone failure") {
		t.Fatalf("expected failure at the final tombstone insertion, got %v", err)
	}
	if got := userRowCounts(t, s, victim.ID); !reflect.DeepEqual(got, beforeRows) {
		t.Errorf("credential or user deletion did not roll back: got %v, want %v", got, beforeRows)
	}
	if got := inviteByID(t, s, seed.invUnredeemed); !reflect.DeepEqual(got, beforeOpen) {
		t.Errorf("open invite cleanup did not roll back: got %+v, want %+v", got, beforeOpen)
	}
	if got := inviteByID(t, s, seed.invExhausted); !reflect.DeepEqual(got, beforeConsumed) {
		t.Errorf("consumed invite cleanup did not roll back: got %+v, want %+v", got, beforeConsumed)
	}
	if erased, err := s.IsErased(ctx, victim.ID); err != nil || erased {
		t.Fatalf("failed erasure recorded a tombstone: erased=%v, err=%v", erased, err)
	}
	if _, err := s.ValidateSession(ctx, seed.full); err != nil {
		t.Fatalf("rolled-back erasure revoked a valid session: %v", err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_erasure`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EraseUser(ctx, admin.ID, "", victim.ID); err != nil {
		t.Fatal(err)
	}
	requireNoUserRows(t, s, victim.ID)
	if inv := inviteByID(t, s, seed.invUnredeemed); inv.RevokedAt.IsZero() || inv.CreatedBy != DeletedUserMarker {
		t.Fatalf("retry left an active or identifying invite: %+v", inv)
	}
}
