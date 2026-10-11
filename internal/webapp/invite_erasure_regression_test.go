package webapp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

// pausedInviteIdentity delegates real authentication, then holds the captured
// identity until the test completes the concurrent deletion. It does not
// replace authentication or bypass the production HTTP invitation handler.
type pausedInviteIdentity struct {
	AdminHTTPGuard
	captured chan *authStore.User
	resume   chan struct{}
	once     sync.Once
}

func (g *pausedInviteIdentity) HTTPUser(r *http.Request) (*authStore.User, error) {
	u, err := g.AdminHTTPGuard.HTTPUser(r)
	if err != nil {
		return nil, err
	}
	g.once.Do(func() {
		g.captured <- u
		select {
		case <-g.resume:
		case <-r.Context().Done():
		}
	})
	return u, err
}

func TestInviteCreationCannotOutliveErasedCreator(t *testing.T) {
	for _, reuseUsername := range []bool{false, true} {
		t.Run(fmt.Sprintf("reuse_username_%v", reuseUsername), func(t *testing.T) {
			h, srv, st := newInviteTestHandler(t)
			adminAuthHeader(t, st)
			admin, err := st.GetUserByUsername("admin")
			if err != nil {
				t.Fatal(err)
			}
			victim, err := st.CreateUser("inviter", "password123")
			if err != nil {
				t.Fatal(err)
			}
			if err := st.SetRoles(victim.ID, []string{"admin"}); err != nil {
				t.Fatal(err)
			}
			sess, err := st.CreateFullSession(victim.ID)
			if err != nil {
				t.Fatal(err)
			}
			guard := &pausedInviteIdentity{AdminHTTPGuard: srv, captured: make(chan *authStore.User, 1), resume: make(chan struct{})}
			h.auth = guard
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var release sync.Once
			resume := func() { release.Do(func() { close(guard.resume) }) }
			defer resume()
			req := httptest.NewRequest(http.MethodPost, "/api/invites", strings.NewReader(`{"role":"viewer","ttlHours":1}`)).WithContext(ctx)
			req.Header.Set("Authorization", "Bearer "+sess.Token)
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				h.apiInvites(rec, req)
			}()
			t.Cleanup(func() {
				resume()
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("invitation handler did not stop during cleanup")
				}
			})
			select {
			case captured := <-guard.captured:
				if captured.ID != victim.ID {
					t.Fatalf("captured creator %q, want %q", captured.ID, victim.ID)
				}
			case <-ctx.Done():
				t.Fatal("invitation did not reach the authenticated creator boundary")
			}
			if _, err := st.EraseUser(ctx, admin.ID, "", victim.ID); err != nil {
				t.Fatal(err)
			}
			var replacement *authStore.User
			if reuseUsername {
				replacement, err = st.CreateUser(victim.Username, "replacement-password")
				if err != nil {
					t.Fatal(err)
				}
				if err := st.SetRoles(replacement.ID, []string{"admin"}); err != nil {
					t.Fatal(err)
				}
				if replacement.ID == victim.ID {
					t.Fatal("replacement account reused the erased ID")
				}
			}
			resume()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("invitation did not finish after releasing its captured identity")
			}
			if rec.Code >= 200 && rec.Code < 300 {
				t.Errorf("invitation survived creator deletion: status=%d body=%s", rec.Code, rec.Body.String())
			}
			invites, err := st.ListInvites()
			if err != nil {
				t.Fatal(err)
			}
			if len(invites) != 0 {
				t.Errorf("in-flight request persisted %d invitation(s) after erasure: %+v", len(invites), invites)
			}
			if replacement != nil {
				if got, err := st.GetUser(replacement.ID); err != nil || got.Username != victim.Username {
					t.Errorf("replacement account changed: got %+v, err=%v", got, err)
				}
			}
		})
	}
}
