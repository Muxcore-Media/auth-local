package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(b byte) []byte { return []byte(strings.Repeat(string([]byte{b}), 32)) }

func TestSecretBoxRoundTrip(t *testing.T) {
	b, err := newSecretBox(testKey('a'))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := b.encrypt("JBSWY3DPEHPK3PXP")
	if err != nil || !strings.HasPrefix(enc, "v1:") || strings.Contains(enc, "JBSWY3") {
		t.Fatalf("encrypt = %q, %v", enc, err)
	}
	if again, _ := b.encrypt(enc); again != enc {
		t.Error("encrypt of ciphertext must be a no-op")
	}
	if got, err := b.decrypt(enc); err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("decrypt = %q, %v", got, err)
	}
	enc2, _ := b.encrypt("JBSWY3DPEHPK3PXP")
	if enc2 == enc {
		t.Error("nonce reuse: identical ciphertexts")
	}
	if got, _ := b.decrypt("legacyplain"); got != "legacyplain" {
		t.Error("plaintext passthrough failed")
	}
	other, _ := newSecretBox(testKey('b'))
	if _, err := other.decrypt(enc); !errors.Is(err, ErrWrongSecretKey) {
		t.Errorf("wrong key err = %v", err)
	}
	if _, err := b.decrypt(enc[:len(enc)-4] + "AAAA"); !errors.Is(err, ErrWrongSecretKey) {
		t.Errorf("tampered err = %v", err)
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	t.Setenv("AUTH_SECRET_KEY", "")
	t.Setenv("AUTH_SECRET_KEY_FILE", "")
	dir := filepath.Join(t.TempDir(), "data")
	k1, err := LoadOrCreateKey(dir)
	if err != nil || len(k1) != 32 {
		t.Fatalf("create: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, DefaultKeyFileName))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, %v", fi, err)
	}
	if di, _ := os.Stat(dir); di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v", di.Mode().Perm())
	}
	k2, err := LoadOrCreateKey(dir)
	if err != nil || string(k1) != string(k2) {
		t.Fatal("key not stable across loads")
	}
	t.Setenv("AUTH_SECRET_KEY", strings.Repeat("ab", 32))
	if k, err := LoadOrCreateKey(dir); err != nil || k[0] != 0xab {
		t.Errorf("env key: %v", err)
	}
	t.Setenv("AUTH_SECRET_KEY", "short")
	if _, err := LoadOrCreateKey(dir); err == nil {
		t.Error("bad key accepted")
	}
}

func TestTOTPEncryptedAtRestAndWrongKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.db")
	s, err := NewWithKey(path, testKey('a'))
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser("eve", "eve-password-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetTOTPSecret(u.ID, "KRSXG5CTMVRXEZLU"); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := s.db.QueryRow(`SELECT secret FROM totp WHERE user_id=?`, u.ID).Scan(&raw); err != nil || !strings.HasPrefix(raw, "v1:") {
		t.Fatalf("raw = %q, %v", raw, err)
	}
	if got, en, err := s.GetTOTPSecret(u.ID); err != nil || got != "KRSXG5CTMVRXEZLU" || !en {
		t.Fatalf("get = %q %v %v", got, en, err)
	}
	_ = s.Close()

	if _, err := NewWithKey(path, testKey('b')); !errors.Is(err, ErrWrongSecretKey) {
		t.Fatalf("wrong key open err = %v", err)
	}
	s, err = NewWithKey(path, testKey('a'))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	_ = s.Close()
}

func TestMigratePlaintextRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	s, err := NewWithKey(path, testKey('a'))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := s.CreateUser("frank", "frank-password-1")
	if _, err := s.db.Exec(`INSERT INTO totp (user_id, secret, enabled) VALUES (?, 'PLAINSECRET', 1)`, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE users SET totp_secret='LEGACYSECRET', totp_enabled=1 WHERE id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	for i := 0; i < 2; i++ { // idempotent
		s, err = NewWithKey(path, testKey('a'))
		if err != nil {
			t.Fatal(err)
		}
		var a, b string
		_ = s.db.QueryRow(`SELECT secret FROM totp WHERE user_id=?`, u.ID).Scan(&a)
		_ = s.db.QueryRow(`SELECT totp_secret FROM users WHERE id=?`, u.ID).Scan(&b)
		if !strings.HasPrefix(a, "v1:") || !strings.HasPrefix(b, "v1:") {
			t.Fatalf("not encrypted: %q %q", a, b)
		}
		if got, _, _ := s.GetTOTPSecret(u.ID); got != "PLAINSECRET" {
			t.Errorf("totp = %q", got)
		}
		if usr, _ := s.GetUser(u.ID); usr == nil || usr.TOTPSecret != "LEGACYSECRET" {
			t.Errorf("legacy = %+v", usr)
		}
		_ = s.Close()
	}
}

func TestSessionTokensHashedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.db")
	s, err := NewWithKey(path, testKey('a'))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := s.CreateUser("gina", "gina-password-1")
	sess, err := s.CreateFullSession(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	_ = s.db.QueryRow(`SELECT token FROM sessions`).Scan(&stored)
	if stored == sess.Token || !strings.HasPrefix(stored, "h1:") {
		t.Fatalf("stored = %q", stored)
	}
	if _, err := s.GetSession(stored); err == nil {
		t.Error("stored hash must not authenticate")
	}
	// Legacy plaintext row migrates; reopen is a no-op and sessions stay valid.
	if _, err := s.db.Exec(`INSERT INTO sessions (token, user_id, kind, expires_at) VALUES ('legacyraw', ?, 'full', '2099-01-01T00:00:00Z')`, u.ID); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	for i := 0; i < 2; i++ {
		s, err = NewWithKey(path, testKey('a'))
		if err != nil {
			t.Fatal(err)
		}
		for _, tok := range []string{sess.Token, "legacyraw"} {
			if _, err := s.GetSession(tok); err != nil {
				t.Errorf("session %q invalid after migration: %v", tok, err)
			}
		}
		var n int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token = 'legacyraw'`).Scan(&n)
		if n != 0 {
			t.Error("plaintext token still stored")
		}
		_ = s.Close()
	}
	s, _ = NewWithKey(path, testKey('a'))
	defer func() { _ = s.Close() }()
	if err := s.DeleteSession("legacyraw"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession("legacyraw"); err == nil {
		t.Error("deleted session still valid")
	}
}
