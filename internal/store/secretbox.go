package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// secretPrefix marks an AES-256-GCM encrypted value: "v1:" + base64(nonce||ciphertext).
// Anything without the prefix is treated as legacy plaintext and migrated on open.
const secretPrefix = "v1:"

// DefaultKeyFileName is created next to the database when no key is configured.
const DefaultKeyFileName = "auth-secret.key"

// ErrWrongSecretKey is returned when stored secrets cannot be decrypted with the configured key.
var ErrWrongSecretKey = errors.New("stored TOTP secrets cannot be decrypted with the configured key (AUTH_SECRET_KEY / AUTH_SECRET_KEY_FILE): " +
	"the key does not match the one the database was encrypted with; restore the original key file, " +
	"or disable TOTP for the affected users after restoring the database from backup")

type secretBox struct{ aead cipher.AEAD }

func newSecretBox(key []byte) (*secretBox, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secret key must be 32 bytes, got %d", len(key))
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &secretBox{aead: g}, nil
}

func isEncrypted(v string) bool { return strings.HasPrefix(v, secretPrefix) }

func (b *secretBox) encrypt(plain string) (string, error) {
	if plain == "" || isEncrypted(plain) {
		return plain, nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := b.aead.Seal(nonce, nonce, []byte(plain), nil)
	return secretPrefix + base64.StdEncoding.EncodeToString(out), nil
}

// decrypt returns plaintext values unchanged (legacy rows not yet migrated).
func (b *secretBox) decrypt(v string) (string, error) {
	if !isEncrypted(v) {
		return v, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, secretPrefix))
	if err != nil || len(raw) < b.aead.NonceSize() {
		return "", fmt.Errorf("corrupt encrypted secret: %w", ErrWrongSecretKey)
	}
	n := b.aead.NonceSize()
	plain, err := b.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", ErrWrongSecretKey
	}
	return string(plain), nil
}

// ParseKey accepts a 32-byte key as hex (64 chars) or base64.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if k, err := hex.DecodeString(s); err == nil && len(k) == 32 {
		return k, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if k, err := enc.DecodeString(s); err == nil && len(k) == 32 {
			return k, nil
		}
	}
	return nil, errors.New("secret key must be 32 bytes encoded as hex or base64")
}

// LoadOrCreateKey resolves the secret key: AUTH_SECRET_KEY, else the file named
// by AUTH_SECRET_KEY_FILE, else <dbDir>/auth-secret.key (generated 0600 once).
func LoadOrCreateKey(dbDir string) ([]byte, error) {
	if v := os.Getenv("AUTH_SECRET_KEY"); v != "" {
		return ParseKey(v)
	}
	path := os.Getenv("AUTH_SECRET_KEY_FILE")
	explicit := path != ""
	if !explicit {
		path = filepath.Join(dbDir, DefaultKeyFileName)
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-configured path
	if err == nil {
		if fi, serr := os.Stat(path); serr == nil && fi.Mode().Perm()&0o077 != 0 {
			_ = os.Chmod(path, 0o600)
		}
		k, perr := ParseKey(string(data))
		if perr != nil {
			return nil, fmt.Errorf("key file %s: %w", path, perr)
		}
		return k, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("create key file %s: %w", path, err)
	}
	if _, err := f.WriteString(hex.EncodeToString(k) + "\n"); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return k, nil
}

// migrateTOTPSecrets encrypts plaintext secrets in place (idempotent) and
// verifies already-encrypted ones decrypt with the current key.
func (s *Store) migrateTOTPSecrets() error {
	for _, t := range []struct{ table, keycol, col string }{
		{"totp", "user_id", "secret"},
		{"users", "id", "totp_secret"},
	} {
		rows, err := s.db.Query(fmt.Sprintf(`SELECT %s, %s FROM %s WHERE %s IS NOT NULL AND %s != ''`, t.keycol, t.col, t.table, t.col, t.col))
		if err != nil {
			return fmt.Errorf("scan %s: %w", t.table, err)
		}
		type kv struct{ k, v string }
		var plain []kv
		for rows.Next() {
			var e kv
			if err := rows.Scan(&e.k, &e.v); err != nil {
				_ = rows.Close()
				return err
			}
			if isEncrypted(e.v) {
				if _, err := s.box.decrypt(e.v); err != nil {
					_ = rows.Close()
					return err
				}
				continue
			}
			plain = append(plain, e)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		_ = rows.Close()
		for _, e := range plain {
			enc, err := s.box.encrypt(e.v)
			if err != nil {
				return err
			}
			if _, err := s.db.Exec(fmt.Sprintf(`UPDATE %s SET %s = ? WHERE %s = ?`, t.table, t.col, t.keycol), enc, e.k); err != nil {
				return fmt.Errorf("encrypt %s secret: %w", t.table, err)
			}
		}
	}
	return nil
}
