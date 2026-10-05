package store

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Muxcore-Media/core/sdk/go/module/moduletest"
	"github.com/pquerna/otp/totp"
)

// TestUpgradeFromV0_1_5 opens the snapshot produced by tag v0.1.5 with the
// current code (twice) and checks schema, data, defaults, and integrity
// (ADR-0015, NFR-DATA-002).
func TestUpgradeFromV0_1_5(t *testing.T) {
	const fixture = "testdata/upgrade/v0.1.5.db"

	fresh, err := New(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatalf("open fresh: %v", err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	freshSchema := moduletest.Schema(t, fresh.db)

	path := moduletest.CopyFixture(t, fixture)
	for i := 0; i < 2; i++ { // the second open must be a no-op
		s, err := New(path)
		if err != nil {
			t.Fatalf("open #%d: %v", i+1, err)
		}
		checkUpgraded(t, s, freshSchema, i == 0)
		if err := s.Close(); err != nil {
			t.Fatalf("close #%d: %v", i+1, err)
		}
	}
}

func checkUpgraded(t *testing.T, s *Store, freshSchema moduletest.SchemaInfo, firstOpen bool) {
	t.Helper()
	moduletest.RequireSchemaSuperset(t, moduletest.Schema(t, s.db), freshSchema)
	moduletest.RequireIntegrity(t, s.db)

	// Users and legacy TOTP columns.
	users, err := s.ListUsers()
	if err != nil || len(users) != 3 {
		t.Fatalf("ListUsers = %d, %v; want 3", len(users), err)
	}
	alice, err := s.GetUserByUsername("alice")
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	if !reflect.DeepEqual(alice.Roles, []string{"admin", "user"}) {
		t.Errorf("alice roles = %v", alice.Roles)
	}
	if alice.TOTPSecret != "JBSWY3DPEHPK3PXP" || !alice.TOTPEnabled {
		t.Errorf("alice totp = %q/%v", alice.TOTPSecret, alice.TOTPEnabled)
	}
	if alice.CreatedAt.IsZero() {
		t.Error("alice created_at not parsed")
	}
	if alice.Password == "" {
		t.Error("alice password hash lost")
	}
	if _, err := s.VerifyPassword("alice", "alice-password-1"); err != nil {
		t.Errorf("alice password no longer verifies: %v", err)
	}
	if _, err := s.VerifyPassword("bob", "bob-password-2"); err != nil {
		t.Errorf("bob password no longer verifies: %v", err)
	}
	bob, _ := s.GetUserByUsername("bob")
	carol, _ := s.GetUserByUsername("carol")
	if bob == nil || carol == nil {
		t.Fatal("bob/carol missing")
	}

	// New column tenant_id defaults to empty on pre-existing rows.
	for _, u := range users {
		if u.TenantID != "" {
			t.Errorf("user %s tenant_id = %q, want empty default", u.Username, u.TenantID)
		}
	}
	// The new column is usable on old rows.
	if err := s.SetTenantID(bob.ID, "household-1"); err != nil {
		t.Fatalf("SetTenantID: %v", err)
	}
	if err := s.SetTenantID(bob.ID, ""); err != nil {
		t.Fatalf("reset tenant: %v", err)
	}

	// Sessions.
	for _, tc := range []struct{ token, userID, kind string }{
		{"seed-session-full", alice.ID, "full"},
		{"seed-session-partial", bob.ID, "partial"},
	} {
		sess, err := s.GetSession(tc.token)
		if err != nil {
			t.Fatalf("GetSession(%s): %v", tc.token, err)
		}
		if sess.UserID != tc.userID || sess.Kind != tc.kind || sess.ExpiresAt.Year() != 2099 {
			t.Errorf("session %s = %+v", tc.token, sess)
		}
		var stored string
		if err := s.db.QueryRow(`SELECT token FROM sessions WHERE user_id = ? AND kind = ?`, tc.userID, tc.kind).Scan(&stored); err != nil ||
			stored != hashSessionToken(tc.token) || strings.Contains(stored, tc.token) {
			t.Errorf("session %s stored as %q, %v; want hashed", tc.token, stored, err)
		}
	}

	// API tokens.
	toks, err := s.ListAPITokens(alice.ID)
	if err != nil || len(toks) != 1 {
		t.Fatalf("ListAPITokens(alice) = %d, %v", len(toks), err)
	}
	if toks[0].Name != "ci-token" || toks[0].Prefix != "mct_seedtok1" ||
		!reflect.DeepEqual(toks[0].Scopes, []string{"read", "write"}) {
		t.Errorf("alice token = %+v", toks[0])
	}
	// ValidateAPIToken below stamps last_used, so only the first open sees the default.
	if firstOpen && !toks[0].LastUsed.IsZero() {
		t.Errorf("last_used default should be empty, got %v", toks[0].LastUsed)
	}
	sess, err := s.ValidateAPIToken("mct_seedtoken_alice_0000000000000000")
	if err != nil || sess.UserID != alice.ID {
		t.Errorf("ValidateAPIToken = %+v, %v", sess, err)
	}
	if uid, err := s.APITokenUserID("tok-2"); err != nil || uid != bob.ID {
		t.Errorf("APITokenUserID(tok-2) = %q, %v", uid, err)
	}

	// TOTP table.
	secret, enabled, err := s.GetTOTPSecret(carol.ID)
	if err != nil || secret != "KRSXG5CTMVRXEZLU" || !enabled {
		t.Errorf("carol totp = %q, %v, %v", secret, enabled, err)
	}
	// NFR-SEC-005: seeded plaintext TOTP secrets are encrypted at rest after open,
	// and still validate.
	for _, q := range []string{
		`SELECT secret FROM totp WHERE user_id = '` + carol.ID + `'`,
		`SELECT totp_secret FROM users WHERE id = '` + alice.ID + `'`,
	} {
		var raw string
		if err := s.db.QueryRow(q).Scan(&raw); err != nil || !strings.HasPrefix(raw, "v1:") || strings.Contains(raw, "KRSXG5") || strings.Contains(raw, "JBSWY3") {
			t.Errorf("%s = %q, %v; want v1: ciphertext", q, raw, err)
		}
	}
	for _, c := range []struct{ secret string }{{secret}, {alice.TOTPSecret}} {
		code, err := totp.GenerateCode(c.secret, time.Now())
		if err != nil || !totp.Validate(code, c.secret) {
			t.Errorf("TOTP validation failed for seeded secret: %v", err)
		}
	}

	// WebAuthn credentials and sessions.
	if n, err := s.WebAuthnCredentialCount(alice.ID); err != nil || n != 2 {
		t.Errorf("alice passkeys = %d, %v; want 2", n, err)
	}
	creds, err := s.ListWebAuthnCredentials(bob.ID)
	if err != nil || len(creds) != 1 || string(creds[0]) != "seed-passkey-bob-1" {
		t.Errorf("bob passkeys = %q, %v", creds, err)
	}
	meta, err := s.ListWebAuthnCredentialMeta(alice.ID)
	if err != nil || len(meta) != 2 {
		t.Fatalf("passkey meta = %d, %v", len(meta), err)
	}
	if meta[0].CredentialType != "public-key" || meta[0].Transports != "[]" || meta[0].AAGUID != "" {
		t.Errorf("passkey meta defaults = %+v", meta[0])
	}
	data, err := s.GetWebAuthnSession("seed-challenge")
	if err != nil || !reflect.DeepEqual(data, []byte{1, 2, 3, 4}) {
		t.Errorf("webauthn session = %v, %v", data, err)
	}

	// Invites table is new: empty, and fully usable with old users.
	invs, err := s.ListInvites()
	if err != nil || len(invs) != 0 {
		t.Fatalf("ListInvites = %d, %v; want 0", len(invs), err)
	}
	inv, err := s.CreateInvite(alice.ID, "user", "", 1, time.Hour)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	u, _, err := s.RedeemInvite(inv.Token, "dave", "dave-password-4")
	if err != nil || u.TenantID != "" {
		t.Fatalf("RedeemInvite = %+v, %v", u, err)
	}
	// Leave the fixture copy as found for the second pass: remove what we added.
	if err := s.DeleteUser(u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := s.db.Exec(`DELETE FROM invites`); err != nil {
		t.Fatalf("cleanup invites: %v", err)
	}
	moduletest.RequireIntegrity(t, s.db)
}
