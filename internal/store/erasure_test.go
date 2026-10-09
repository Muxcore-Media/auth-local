package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var erasureIDShape = regexp.MustCompile(`^er_[0-9a-f]{32}$`)

func makeAdmin(t *testing.T, s *Store, name, tenant string) *User {
	t.Helper()
	u, err := s.CreateUserTenant(name, "password-"+name, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRoles(u.ID, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	return u
}

// userRowCounts counts every row carrying userID, per table.
func userRowCounts(t *testing.T, s *Store, userID string) map[string]int {
	t.Helper()
	out := map[string]int{}
	for table, col := range map[string]string{
		"users": "id", "sessions": "user_id", "api_tokens": "user_id", "webauthn_credentials": "user_id",
		"webauthn_sessions": "user_id", "totp": "user_id",
	} {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE `+col+` = ?`, userID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[table] = n
	}
	return out
}

func requireNoUserRows(t *testing.T, s *Store, userID string) {
	t.Helper()
	for table, n := range userRowCounts(t, s, userID) {
		if n != 0 {
			t.Errorf("%s still has %d rows for the erased user", table, n)
		}
	}
}

type seeded struct {
	user                         *User
	full, partial, apiSess, apiK string
	invUnredeemed, invExhausted  string
}

// seedUser gives u every kind of credential, session and invite.
func seedUser(t *testing.T, s *Store, u *User) seeded {
	t.Helper()
	full, err := s.CreateFullSession(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	partial, err := s.CreatePartialSession(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	apiKey, _, err := s.CreateAPIToken(u.ID, "cli", []string{"read"})
	if err != nil {
		t.Fatal(err)
	}
	apiSess, err := s.ValidateAPIToken(apiKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetTOTPSecret(u.ID, "KRSXG5CTMVRXEZLU"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddWebAuthnCredential(u.ID, []byte("passkey-"+u.ID)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveWebAuthnSession(u.ID, "challenge-"+u.ID, []byte{1}); err != nil {
		t.Fatal(err)
	}
	open, err := s.CreateInvite(u.Username, "user", u.TenantID, 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	exhausted, err := s.CreateInvite(u.Username, "user", u.TenantID, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE invites SET use_count = 1 WHERE id = ?`, exhausted.ID); err != nil {
		t.Fatal(err)
	}
	return seeded{user: u, full: full.Token, partial: partial.Token, apiSess: apiSess.Token, apiK: apiKey,
		invUnredeemed: open.ID, invExhausted: exhausted.ID}
}

func inviteByID(t *testing.T, s *Store, id string) *Invite {
	t.Helper()
	row := s.db.QueryRow(`SELECT id, prefix, created_by, role, COALESCE(tenant_id,''), max_uses, use_count, expires_at, revoked_at, created_at FROM invites WHERE id = ?`, id)
	inv, err := scanInvite(row)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestEraseUserRevokesEverything(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin := makeAdmin(t, s, "root", "")
	victim, _ := s.CreateUser("victim", "pw")
	bystander, _ := s.CreateUser("bystander", "pw")
	v := seedUser(t, s, victim)
	b := seedUser(t, s, bystander)
	before := userRowCounts(t, s, victim.ID)
	for table, n := range before {
		if n == 0 {
			t.Fatalf("seed left %s empty for the victim", table)
		}
	}

	erasureID, err := s.EraseUser(ctx, admin.ID, "", victim.ID)
	if err != nil {
		t.Fatalf("EraseUser: %v", err)
	}
	if !erasureIDShape.MatchString(erasureID) || strings.Contains(erasureID, victim.ID) {
		t.Fatalf("erasure id %q is not a random opaque id", erasureID)
	}
	requireNoUserRows(t, s, victim.ID)
	for _, tok := range []string{v.full, v.apiSess} {
		if _, err := s.ValidateSession(ctx, tok); !errors.Is(err, ErrInvalidSession) {
			t.Errorf("ValidateSession after erasure = %v, want ErrInvalidSession", err)
		}
	}
	if _, err := s.GetSession(v.partial); err == nil {
		t.Error("partial session survived the erasure")
	}
	if _, err := s.ValidateAPIToken(v.apiK); err == nil {
		t.Error("API key still validates after the erasure")
	}
	if _, err := s.GetWebAuthnSession("challenge-" + victim.ID); err == nil {
		t.Error("passkey session survived the erasure")
	}
	if _, enabled, _ := s.GetTOTPSecret(victim.ID); enabled {
		t.Error("TOTP survived the erasure")
	}
	// Invites: unredeemed revoked, all anonymised; the bystander's untouched.
	if inv := inviteByID(t, s, v.invUnredeemed); inv.CreatedBy != DeletedUserMarker || inv.RevokedAt.IsZero() {
		t.Errorf("unredeemed invite = %+v; want anonymised and revoked", inv)
	}
	if inv := inviteByID(t, s, v.invExhausted); inv.CreatedBy != DeletedUserMarker || !inv.RevokedAt.IsZero() {
		t.Errorf("exhausted invite = %+v; want anonymised, not revoked", inv)
	}
	if inv := inviteByID(t, s, b.invUnredeemed); inv.CreatedBy != "bystander" || !inv.RevokedAt.IsZero() {
		t.Errorf("bystander invite changed: %+v", inv)
	}
	// Bystander intact.
	for table, n := range userRowCounts(t, s, bystander.ID) {
		if n == 0 {
			t.Errorf("bystander lost its %s rows", table)
		}
	}
	if _, err := s.ValidateSession(ctx, b.full); err != nil {
		t.Errorf("bystander session: %v", err)
	}
	// Tombstone: id, tenant, time, deleting admin; no username anywhere.
	var gotUser, gotTenant, gotAt, gotBy string
	if err := s.db.QueryRow(`SELECT user_id, tenant_id, deleted_at, deleted_by FROM user_erasures WHERE erasure_id = ?`, erasureID).
		Scan(&gotUser, &gotTenant, &gotAt, &gotBy); err != nil {
		t.Fatal(err)
	}
	if gotUser != victim.ID || gotTenant != "" || gotBy != admin.ID {
		t.Errorf("tombstone = %q %q %q", gotUser, gotTenant, gotBy)
	}
	if at, err := time.Parse(time.RFC3339Nano, gotAt); err != nil || time.Since(at) > time.Minute {
		t.Errorf("deleted_at %q: %v", gotAt, err)
	}
	requireNoUsernameInLedger(t, s, "victim")
}

func requireNoUsernameInLedger(t *testing.T, s *Store, username string) {
	t.Helper()
	for _, table := range []string{"user_erasures", "erasure_acks"} {
		rows, err := s.db.Query(`SELECT * FROM ` + table)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]sql.NullString, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			for i, v := range vals {
				if strings.Contains(v.String, username) {
					t.Errorf("%s.%s contains the username", table, cols[i])
				}
			}
		}
		_ = rows.Close()
	}
}

func TestEraseUserIdempotentTenantAndSelf(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin := makeAdmin(t, s, "root", "")
	admin2 := makeAdmin(t, s, "root2", "")
	otherAdmin := makeAdmin(t, s, "other-root", "household-2")
	victim, _ := s.CreateUser("victim", "pw")
	foreign, _ := s.CreateUserTenant("foreign", "pw", "household-2")

	if _, err := s.EraseUser(ctx, admin.ID, "", admin.ID); !errors.Is(err, ErrSelfErasure) {
		t.Fatalf("self erasure = %v, want ErrSelfErasure", err)
	}
	// Cross-tenant: indistinguishable from unknown, target untouched.
	if _, err := s.EraseUser(ctx, admin.ID, "", foreign.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("cross-tenant erasure = %v, want ErrUserNotFound", err)
	}
	if _, err := s.EraseUser(ctx, otherAdmin.ID, "household-2", victim.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("cross-tenant erasure (other direction) = %v, want ErrUserNotFound", err)
	}
	if _, err := s.GetUser(foreign.ID); err != nil {
		t.Fatalf("cross-tenant target was touched: %v", err)
	}
	if _, err := s.EraseUser(ctx, admin.ID, "", "never-seen"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("never-seen id = %v, want ErrUserNotFound", err)
	}

	first, err := s.EraseUser(ctx, admin.ID, "", victim.ID)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.EraseUser(ctx, admin2.ID, "", victim.ID)
	if err != nil || again != first {
		t.Fatalf("repeat erasure = %q, %v; want the same %q", again, err, first)
	}
	// The repeat is not visible across tenants.
	if _, err := s.EraseUser(ctx, otherAdmin.ID, "household-2", victim.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("repeat from another tenant = %v, want ErrUserNotFound", err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM user_erasures`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("tombstones = %d, %v; want 1", n, err)
	}

	// Tenant-scoped erasure records the tenant.
	if _, err := s.EraseUser(ctx, otherAdmin.ID, "household-2", foreign.ID); err != nil {
		t.Fatal(err)
	}
	var tenant string
	if err := s.db.QueryRow(`SELECT tenant_id FROM user_erasures WHERE user_id = ?`, foreign.ID).Scan(&tenant); err != nil || tenant != "household-2" {
		t.Fatalf("tombstone tenant = %q, %v", tenant, err)
	}
}

func TestEraseUserLastAdminPerTenant(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	soleAdmin := makeAdmin(t, s, "sole", "")
	member, _ := s.CreateUser("member", "pw")
	tenantAdmin := makeAdmin(t, s, "t-admin", "household-2")
	// Admins in other tenants do not count.
	_ = makeAdmin(t, s, "t3-admin", "household-3")

	// The store trusts its caller's authority; the transport checks the
	// bearer. Erasing the tenant's only admin is refused regardless.
	if _, err := s.EraseUser(ctx, member.ID, "", soleAdmin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin = %v, want ErrLastAdmin", err)
	}
	if _, err := s.EraseUser(ctx, "someone", "household-2", tenantAdmin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last tenant admin = %v, want ErrLastAdmin", err)
	}
	if _, err := s.GetUser(soleAdmin.ID); err != nil {
		t.Fatal("last admin was deleted")
	}
	// A second admin makes the first erasable.
	second := makeAdmin(t, s, "second", "")
	if _, err := s.EraseUser(ctx, second.ID, "", soleAdmin.ID); err != nil {
		t.Fatalf("erase with another admin left: %v", err)
	}
}

// TestEraseUserConcurrentLastTwoAdmins: two administrators delete each other
// at the same time, through two independent store handles (as two processes
// would). Both pass every check that happens before the write transaction
// (the barrier below holds both until each has arrived), so only the admin
// count inside the transaction can stop the second deletion: exactly one
// succeeds.
func TestEraseUserConcurrentLastTwoAdmins(t *testing.T) {
	for _, mode := range []string{"two-handles", "one-handle"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "auth.db")
			s1, err := New(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s1.Close() })
			s2 := s1
			if mode == "two-handles" {
				if s2, err = New(path); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = s2.Close() })
			}
			a := makeAdmin(t, s1, "admin-a", "")
			b := makeAdmin(t, s1, "admin-b", "")

			var arrived sync.WaitGroup
			arrived.Add(2)
			eraseHookBeforeTx = func() {
				arrived.Done()
				done := make(chan struct{})
				go func() { arrived.Wait(); close(done) }()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
				}
			}
			t.Cleanup(func() { eraseHookBeforeTx = nil })

			errs := make([]error, 2)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); _, errs[0] = s1.EraseUser(context.Background(), a.ID, "", b.ID) }()
			go func() { defer wg.Done(); _, errs[1] = s2.EraseUser(context.Background(), b.ID, "", a.ID) }()
			wg.Wait()

			ok, last := 0, 0
			for _, err := range errs {
				switch {
				case err == nil:
					ok++
				case errors.Is(err, ErrLastAdmin):
					last++
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}
			if ok != 1 || last != 1 {
				t.Fatalf("results %v: want exactly one success and one ErrLastAdmin", errs)
			}
			admins, err := countTenantAdmins(context.Background(), s1.db, "")
			if err != nil || admins != 1 {
				t.Fatalf("admins left = %d, %v; want 1", admins, err)
			}
		})
	}
}

func TestErasedIDCannotBeRecreated(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin := makeAdmin(t, s, "root", "")
	victim, _ := s.CreateUser("victim", "pw")
	inv, err := s.CreateInvite("root", "user", "", 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EraseUser(ctx, admin.ID, "", victim.ID); err != nil {
		t.Fatal(err)
	}

	// Force the next generated id to collide with the tombstoned one.
	orig := newID
	newID = func() string { return victim.ID }
	if _, err := s.CreateUser("again", "pw"); !errors.Is(err, ErrUserIDErased) {
		t.Errorf("CreateUser with a tombstoned id = %v, want ErrUserIDErased", err)
	}
	if _, _, err := s.RedeemInvite(inv.Token, "invited", "password1"); !errors.Is(err, ErrUserIDErased) {
		t.Errorf("RedeemInvite with a tombstoned id = %v, want ErrUserIDErased", err)
	}
	newID = orig
	if got := inviteByID(t, s, inv.ID); got.UseCount != 0 {
		t.Errorf("refused redemption consumed the invite: use_count=%d", got.UseCount)
	}
	// No credential or session can be attached to the erased id (in-flight
	// logins racing the erasure).
	if _, err := s.CreateFullSession(victim.ID); !errors.Is(err, ErrUserIDErased) {
		t.Errorf("CreateFullSession = %v", err)
	}
	if _, _, err := s.CreateAPIToken(victim.ID, "x", nil); !errors.Is(err, ErrUserIDErased) {
		t.Errorf("CreateAPIToken = %v", err)
	}
	if err := s.SetTOTPSecret(victim.ID, "KRSXG5CTMVRXEZLU"); !errors.Is(err, ErrUserIDErased) {
		t.Errorf("SetTOTPSecret = %v", err)
	}
	if err := s.AddWebAuthnCredential(victim.ID, []byte("k")); !errors.Is(err, ErrUserIDErased) {
		t.Errorf("AddWebAuthnCredential = %v", err)
	}
	if err := s.SaveWebAuthnSession(victim.ID, "c", []byte{1}); !errors.Is(err, ErrUserIDErased) {
		t.Errorf("SaveWebAuthnSession = %v", err)
	}
	requireNoUserRows(t, s, victim.ID)

	// Username reuse creates a new, unrelated id.
	reused, err := s.CreateUser("victim", "pw2")
	if err != nil {
		t.Fatalf("username reuse: %v", err)
	}
	if reused.ID == victim.ID {
		t.Fatal("reused username got the erased id")
	}
	if erased, _ := s.IsErased(ctx, reused.ID); erased {
		t.Fatal("new user is reported erased")
	}
	sess, err := s.CreateFullSession(reused.ID)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := s.ValidateSession(ctx, sess.Token); err != nil || id.UserID != reused.ID {
		t.Fatalf("new user's session = %+v, %v", id, err)
	}
	if erased, _ := s.IsErased(ctx, victim.ID); !erased {
		t.Fatal("old tombstone lost")
	}
}

// TestStartupSweepTombstoneWins: rows of a tombstoned id that reappear (a
// restore of an older archive with the newer ledger) are deleted on open.
func TestStartupSweepTombstoneWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	admin := makeAdmin(t, s, "root", "")
	victim, _ := s.CreateUser("victim", "pw")
	if _, err := s.EraseUser(ctx, admin.ID, "", victim.ID); err != nil {
		t.Fatal(err)
	}
	// Restored rows, written below the store API.
	for _, q := range []string{
		`INSERT INTO users (id, username, password, roles) VALUES ('` + victim.ID + `', 'victim', 'x', '["admin"]')`,
		`INSERT INTO sessions (token, session_id, user_id, kind, expires_at) VALUES ('h1:r', 'sid_r', '` + victim.ID + `', 'full', '2099-01-01T00:00:00Z')`,
		`INSERT INTO api_tokens (id, user_id, name, token_hash, prefix) VALUES ('t-r', '` + victim.ID + `', 'n', 'h', 'p')`,
		`INSERT INTO webauthn_credentials (id, user_id, public_key) VALUES ('w-r', '` + victim.ID + `', x'01')`,
		`INSERT INTO webauthn_sessions (challenge, user_id, data, expires_at) VALUES ('c-r', '` + victim.ID + `', x'01', '2099-01-01 00:00:00')`,
		`INSERT INTO totp (user_id, secret) VALUES ('` + victim.ID + `', 'x')`,
		`INSERT INTO invites (id, token_hash, prefix, created_by, max_uses, expires_at, created_at) VALUES ('i-r', 'th', 'p', 'victim', 0, '2099-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	requireNoUserRows(t, s, victim.ID)
	if inv := inviteByID(t, s, "i-r"); inv.CreatedBy != DeletedUserMarker || inv.RevokedAt.IsZero() {
		t.Errorf("restored invite = %+v; want anonymised and revoked", inv)
	}
	if _, err := s.GetUser(admin.ID); err != nil {
		t.Errorf("bystander removed by sweep: %v", err)
	}
	if n, err := s.SweepTombstoned(ctx); err != nil || n != 0 {
		t.Errorf("second sweep = %d, %v; want a no-op", n, err)
	}
}

// insertTombstones writes n tombstones directly; every pair shares a
// deleted_at so ordering ties are broken by erasure_id.
func insertTombstones(t *testing.T, s *Store, n int, tenant string) []string {
	t.Helper()
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var ids []string
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("er_%s%02d", strings.ReplaceAll(tenant, "-", ""), n-i) // reverse lexical within ties
		at := base.Add(time.Duration(i/2) * time.Second)
		if _, err := s.db.Exec(`INSERT INTO user_erasures (erasure_id, user_id, tenant_id, deleted_at, deleted_by) VALUES (?, ?, ?, ?, 'adm')`,
			id, "user-"+id, tenant, formatErasureTime(at)); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

func TestListErasuresPagingAndAcks(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	insertTombstones(t, s, 7, "")
	insertTombstones(t, s, 2, "household-2")

	var all []LedgerEntry
	token, pages := "", 0
	for {
		page, next, err := s.ListErasures(ctx, "mod-a", 3, token)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) > 3 {
			t.Fatalf("page of %d", len(page))
		}
		all = append(all, page...)
		pages++
		if next == "" {
			break
		}
		token = next
	}
	if len(all) != 9 || pages != 3 {
		t.Fatalf("listed %d tombstones in %d pages; want 9 in 3 (every tenant)", len(all), pages)
	}
	for i := 1; i < len(all); i++ {
		p, c := all[i-1], all[i]
		if c.DeletedAt.Before(p.DeletedAt) || (c.DeletedAt.Equal(p.DeletedAt) && c.ErasureID <= p.ErasureID) {
			t.Fatalf("order broken at %d: %s@%v after %s@%v", i, c.ErasureID, c.DeletedAt, p.ErasureID, p.DeletedAt)
		}
	}

	// Bounds and malformed continuations.
	for _, size := range []int{-1, MaxErasurePageSize + 1} {
		if _, _, err := s.ListErasures(ctx, "m", size, ""); !errors.Is(err, ErrInvalidErasurePage) {
			t.Errorf("page size %d = %v", size, err)
		}
	}
	if page, _, err := s.ListErasures(ctx, "m", 0, ""); err != nil || len(page) != 9 {
		t.Errorf("default page = %d, %v", len(page), err)
	}
	_, next, _ := s.ListErasures(ctx, "m", 1, "")
	statusTok := ""
	if _, st, err := s.ErasureStatuses(ctx, "", "", false, nil, 1, ""); err == nil {
		statusTok = st
	}
	for _, bad := range []string{"garbage", erasureCursorPrefix + "AAAA", next[:len(next)-2] + "xx", statusTok} {
		if _, _, err := s.ListErasures(ctx, "m", 1, bad); !errors.Is(err, ErrInvalidErasurePage) {
			t.Errorf("token %q = %v; want ErrInvalidErasurePage", bad, err)
		}
	}

	// Acknowledgements: latest per (erasure, module) wins; idempotent.
	target := all[0].ErasureID
	for i := 0; i < 2; i++ {
		if err := s.AckErasure(ctx, target, "mod-a", ErasureOutcomeOK, "", map[string]int64{"rows": 2}); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM erasure_acks`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("ack rows = %d, %v; want 1", n, err)
	}
	ackedBy := func(module string) bool {
		page, _, err := s.ListErasures(ctx, module, 1, "")
		if err != nil || len(page) != 1 || page[0].ErasureID != target {
			t.Fatalf("list as %s: %+v, %v", module, page, err)
		}
		return page[0].AcknowledgedByCaller
	}
	if !ackedBy("mod-a") || ackedBy("mod-b") {
		t.Fatal("acknowledged_by_caller must be per verified module")
	}
	if err := s.AckErasure(ctx, target, "mod-a", ErasureOutcomeFailed, "apply_failed", nil); err != nil {
		t.Fatal(err)
	}
	if ackedBy("mod-a") {
		t.Fatal("a later FAILED ack must clear acknowledged_by_caller")
	}
	if err := s.AckErasure(ctx, "er_unknown", "mod-a", ErasureOutcomeOK, "", nil); !errors.Is(err, ErrErasureNotFound) {
		t.Fatalf("ack of unknown erasure = %v", err)
	}
	if err := s.AckErasure(ctx, target, "mod-a", "MAYBE", "", nil); err == nil {
		t.Fatal("invalid outcome accepted")
	}
}

func TestErasureStatuses(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ids := insertTombstones(t, s, 4, "")
	foreign := insertTombstones(t, s, 1, "household-2")
	required := []string{"mod-a", "mod-b", "mod-a"}
	ack := func(id, m, o string) {
		t.Helper()
		if err := s.AckErasure(ctx, id, m, o, "", nil); err != nil {
			t.Fatal(err)
		}
	}
	// ids are listed in ledger order: ids[1], ids[0], ids[3], ids[2].
	ack(ids[0], "mod-a", ErasureOutcomeOK)
	ack(ids[0], "mod-b", ErasureOutcomeOK) // complete
	ack(ids[1], "mod-a", ErasureOutcomeOK)
	ack(ids[1], "mod-b", ErasureOutcomeFailed) // pending (failed)
	ack(ids[2], "mod-a", ErasureOutcomeOK)
	ack(ids[2], "mod-x", ErasureOutcomeOK) // pending: mod-b missing; mod-x not required
	// ids[3]: no acks, pending

	all, next, err := s.ErasureStatuses(ctx, "", "", false, required, 0, "")
	if err != nil || len(all) != 4 || next != "" {
		t.Fatalf("all = %d, %q, %v; want this tenant's 4", len(all), next, err)
	}
	var pending []string
	tok := ""
	for {
		page, next, err := s.ErasureStatuses(ctx, "", "", true, required, 1, tok)
		if err != nil {
			t.Fatal(err)
		}
		for _, st := range page {
			pending = append(pending, st.ErasureID)
		}
		if next == "" {
			break
		}
		if _, _, err := s.ErasureStatuses(ctx, "", "", false, required, 1, next); !errors.Is(err, ErrInvalidErasurePage) {
			t.Fatalf("pending token reused without pending_only = %v", err)
		}
		if _, _, err := s.ErasureStatuses(ctx, "household-2", "", true, required, 1, next); !errors.Is(err, ErrInvalidErasurePage) {
			t.Fatalf("token reused in another tenant = %v", err)
		}
		tok = next
	}
	want := []string{ids[1], ids[3], ids[2]}
	if fmt.Sprint(pending) != fmt.Sprint(want) {
		t.Fatalf("pending = %v; want %v", pending, want)
	}
	one, _, err := s.ErasureStatuses(ctx, "", ids[2], true, required, 0, "")
	if err != nil || len(one) != 1 || len(one[0].Acks) != 2 || one[0].Acks[0].ModuleID != "mod-a" || one[0].Acks[1].ModuleID != "mod-x" {
		t.Fatalf("single status = %+v, %v", one, err)
	}
	if _, _, err := s.ErasureStatuses(ctx, "", foreign[0], false, required, 0, ""); !errors.Is(err, ErrErasureNotFound) {
		t.Fatalf("other tenant's erasure = %v; want ErrErasureNotFound", err)
	}
	// No required modules: nothing is pending.
	if page, _, err := s.ErasureStatuses(ctx, "", "", true, nil, 0, ""); err != nil || len(page) != 0 {
		t.Fatalf("pending with no required modules = %d, %v", len(page), err)
	}
}

func TestLedgerExportImportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live", "auth.db")
	s, err := New(live)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	admin := makeAdmin(t, s, "root", "")
	victim, _ := s.CreateUser("victim", "pw")
	seedUser(t, s, victim)
	// The pre-deletion "archive": a copy of the database taken now.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "archive.db")
	copyFile(t, live, archive)
	if s, err = New(live); err != nil {
		t.Fatal(err)
	}
	erasureID, err := s.EraseUser(ctx, admin.ID, "", victim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	ledger, err := ExportLedger(ctx, live)
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Erasures) != 1 || ledger.Erasures[0].ErasureID != erasureID || ledger.Erasures[0].UserID != victim.ID {
		t.Fatalf("export = %+v", ledger)
	}

	// Restore the archive over the live database, then import the ledger.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(live + suffix)
	}
	copyFile(t, archive, live)
	res, err := ImportLedger(ctx, live, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 1 || res.Present != 0 || res.Swept == 0 {
		t.Fatalf("import = %+v; want 1 imported and restored rows swept", res)
	}
	again, err := ImportLedger(ctx, live, ledger)
	if err != nil || again.Imported != 0 || again.Present != 1 || again.Swept != 0 {
		t.Fatalf("re-import = %+v, %v; want idempotent", again, err)
	}
	s, err = New(live)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	requireNoUserRows(t, s, victim.ID)
	if _, err := s.GetUser(admin.ID); err != nil {
		t.Fatal("bystander lost in restore")
	}
	if id, err := s.EraseUser(ctx, admin.ID, "", victim.ID); err != nil || id != erasureID {
		t.Fatalf("erasure after restore = %q, %v; want the original %q", id, err, erasureID)
	}
}

func TestLedgerImportConflictsAndOldDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "auth.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	insertTombstones(t, s, 1, "")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	existing, err := ExportLedger(ctx, path)
	if err != nil || len(existing.Erasures) != 1 {
		t.Fatalf("export = %+v, %v", existing, err)
	}
	e := existing.Erasures[0]
	now := time.Now().UTC()
	for name, bad := range map[string]Tombstone{
		"same erasure id, other user": {ErasureID: e.ErasureID, UserID: "someone-else", DeletedAt: now},
		"same user, other erasure id": {ErasureID: "er_other", UserID: e.UserID, DeletedAt: now},
	} {
		l := &Ledger{Version: LedgerVersion, Erasures: []Tombstone{
			{ErasureID: "er_fresh", UserID: "fresh-user", DeletedAt: now}, bad,
		}}
		if _, err := ImportLedger(ctx, path, l); !errors.Is(err, ErrErasureConflict) {
			t.Errorf("%s: import = %v; want ErrErasureConflict", name, err)
		}
	}
	after, _ := ExportLedger(ctx, path)
	if len(after.Erasures) != 1 {
		t.Fatalf("a refused import changed the ledger: %+v", after.Erasures)
	}
	for name, l := range map[string]*Ledger{
		"version":    {Version: 9},
		"bad id":     {Version: 1, Erasures: []Tombstone{{ErasureID: "bad id", UserID: "u", DeletedAt: now}}},
		"no user":    {Version: 1, Erasures: []Tombstone{{ErasureID: "er_x", DeletedAt: now}}},
		"no time":    {Version: 1, Erasures: []Tombstone{{ErasureID: "er_x", UserID: "u"}}},
		"self-split": {Version: 1, Erasures: []Tombstone{{ErasureID: "er_x", UserID: "u", DeletedAt: now}, {ErasureID: "er_y", UserID: "u", DeletedAt: now}}},
	} {
		if _, err := ImportLedger(ctx, path, l); err == nil {
			t.Errorf("%s: invalid ledger imported", name)
		}
	}
	if _, err := ImportLedger(ctx, filepath.Join(t.TempDir(), "missing.db"), &Ledger{Version: 1}); err == nil {
		t.Error("import created a missing database")
	}

	// A database from before the ledger exports an empty ledger, unchanged.
	old := filepath.Join(t.TempDir(), "old.db")
	copyFile(t, "testdata/upgrade/v0.1.5.db", old)
	l, err := ExportLedger(ctx, old)
	if err != nil || len(l.Erasures) != 0 {
		t.Fatalf("old export = %+v, %v", l, err)
	}
	db, err := sql.Open("sqlite", old)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var name string
	if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE name = 'user_erasures'`).Scan(&name); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("export modified the old database (%q, %v)", name, err)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
