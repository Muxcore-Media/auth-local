package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCreateInviteForUserRejectsStaleCreatorID(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	root := makeAdmin(t, s, "root", "")
	creator := makeAdmin(t, s, "creator", "")
	if _, err := s.EraseUser(ctx, root.ID, "", creator.ID); err != nil {
		t.Fatal(err)
	}
	replacement := makeAdmin(t, s, creator.Username, "")
	if replacement.ID == creator.ID {
		t.Fatal("replacement reused the erased ID")
	}
	if inv, err := s.CreateInviteForUser(ctx, creator.ID, "viewer", "destination", 1, time.Hour); !errors.Is(err, ErrUserNotFound) || inv != nil {
		t.Fatalf("stale creator rebound to replacement: invite=%+v, err=%v", inv, err)
	}
	if invites, err := s.ListInvites(); err != nil || len(invites) != 0 {
		t.Fatalf("refused creation inserted invites: %+v, %v", invites, err)
	}
	inv, err := s.CreateInviteForUser(ctx, replacement.ID, "viewer", "destination", 1, time.Hour)
	if err != nil || inv.CreatedBy != creator.Username || inv.Role != "viewer" || inv.TenantID != "destination" || inv.MaxUses != 1 {
		t.Fatalf("replacement's own authority failed: invite=%+v, err=%v", inv, err)
	}
}

func TestCreateInviteForUserRechecksCurrentAuthority(t *testing.T) {
	for _, state := range []string{"missing", "demoted", "tombstoned"} {
		t.Run(state, func(t *testing.T) {
			s := newTestStore(t)
			creator := makeAdmin(t, s, "creator", "")
			creatorID := creator.ID // identity already resolved by the adapter
			switch state {
			case "missing":
				creatorID = "unknown-user"
			case "demoted":
				if err := s.SetRoles(creatorID, []string{"user"}); err != nil {
					t.Fatal(err)
				}
			case "tombstoned":
				// A restored user may coexist with the newer ledger until sweep.
				if _, err := s.db.Exec(`INSERT INTO user_erasures (erasure_id, user_id, tenant_id, deleted_at, deleted_by)
					VALUES ('er_restored', ?, '', '2026-10-11T00:00:00Z', 'root')`, creatorID); err != nil {
					t.Fatal(err)
				}
			}
			if inv, err := s.CreateInviteForUser(context.Background(), creatorID, "user", "", 1, time.Hour); err == nil || inv != nil {
				t.Fatalf("invalid current authority created invite: %+v, %v", inv, err)
			}
			if invites, err := s.ListInvites(); err != nil || len(invites) != 0 {
				t.Fatalf("refused creation inserted invites: %+v, %v", invites, err)
			}
		})
	}
}

func TestCreateInviteForUserWriteFailureRollsBackAndRetries(t *testing.T) {
	s := newTestStore(t)
	creator := makeAdmin(t, s, "creator", "")
	if _, err := s.db.Exec(`CREATE TRIGGER reject_invite BEFORE INSERT ON invites
		BEGIN SELECT RAISE(ABORT, 'injected invite failure'); END`); err != nil {
		t.Fatal(err)
	}
	inv, err := s.CreateInviteForUser(context.Background(), creator.ID, "user", "", 1, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "injected invite failure") || inv != nil {
		t.Fatalf("expected injected insert failure without returned token: %+v, %v", inv, err)
	}
	if invites, err := s.ListInvites(); err != nil || len(invites) != 0 {
		t.Fatalf("failed insertion persisted an invite: %+v, %v", invites, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_invite`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateInviteForUser(context.Background(), creator.ID, "user", "", 1, time.Hour); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
}

func TestInviteCreationHoldsTransactionUntilInsert(t *testing.T) {
	s := newTestStore(t)
	root := makeAdmin(t, s, "root", "")
	creator := makeAdmin(t, s, "creator", "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var release sync.Once
	unblock := func() { release.Do(func() { close(resume) }) }
	originalID := newID
	// ID allocation happens after creator resolution but before the SQL insert.
	// Holding this boundary must hold the same write transaction throughout.
	newID = func() string {
		close(entered)
		select {
		case <-resume:
		case <-ctx.Done():
		}
		return originalID()
	}
	var invite *Invite
	var createErr error
	go func() {
		defer close(done)
		invite, createErr = s.CreateInviteForUser(ctx, creator.ID, "viewer", "", 0, time.Hour)
	}()
	t.Cleanup(func() {
		unblock()
		cancel()
		<-done
		newID = originalID
	})
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("creation did not reach the pre-insert boundary")
	}
	eraseCtx, eraseCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer eraseCancel()
	if _, err := s.EraseUser(eraseCtx, root.ID, "", creator.ID); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("erasure interleaved between creator check and insertion: %v", err)
	}
	unblock()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("creation did not finish after release")
	}
	if createErr != nil || invite == nil {
		t.Fatalf("creation first: %+v, %v", invite, createErr)
	}
	if _, err := s.EraseUser(ctx, root.ID, "", creator.ID); err != nil {
		t.Fatal(err)
	}
	if got := inviteByID(t, s, invite.ID); got.CreatedBy != DeletedUserMarker || got.RevokedAt.IsZero() {
		t.Fatalf("subsequent erasure left a live invite: %+v", got)
	}
}

func TestStartupSweepRevokesRestoredMarkerCreatorInvites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	creator := makeAdmin(t, s, DeletedUserMarker, "")
	seed := seedUser(t, s, creator)
	bystander := makeAdmin(t, s, "bystander", "")
	other := seedUser(t, s, bystander)
	beforeRows := userRowCounts(t, s, bystander.ID)
	beforeInvite := inviteByID(t, s, other.invUnredeemed)
	orphan, err := s.CreateInvite("historical-unresolved-label", "viewer", "", 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	beforeOrphan := inviteByID(t, s, orphan.ID)
	// Simulate an older database restored together with the newer erasure ledger.
	if _, err := s.db.Exec(`INSERT INTO user_erasures (erasure_id, user_id, tenant_id, deleted_at, deleted_by)
		VALUES ('er_restored_marker', ?, '', '2026-10-11T00:00:00Z', 'root')`, creator.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	s = reopened
	requireNoUserRows(t, s, creator.ID)
	if inv := inviteByID(t, s, seed.invUnredeemed); inv.CreatedBy != DeletedUserMarker || inv.RevokedAt.IsZero() {
		t.Errorf("restored marker-named creator retained live invite: %+v", inv)
	}
	if got := userRowCounts(t, s, bystander.ID); !reflect.DeepEqual(got, beforeRows) {
		t.Errorf("startup sweep changed bystander rows: got %v, want %v", got, beforeRows)
	}
	if got := inviteByID(t, s, other.invUnredeemed); !reflect.DeepEqual(got, beforeInvite) {
		t.Errorf("startup sweep changed bystander invite: got %+v, want %+v", got, beforeInvite)
	}
	if got := inviteByID(t, s, orphan.ID); !reflect.DeepEqual(got, beforeOrphan) {
		t.Errorf("startup sweep inferred orphan provenance: got %+v, want %+v", got, beforeOrphan)
	}
	if n, err := s.SweepTombstoned(context.Background()); err != nil || n != 0 {
		t.Errorf("second sweep = %d, %v; want no-op", n, err)
	}
}
