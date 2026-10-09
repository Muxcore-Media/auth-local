package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := runErasures(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func copyDB(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(to + suffix)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestErasuresExportImportRestore walks the ADR-0035 §4 restore flow: export
// the live ledger, restore a pre-deletion archive, import, and start.
func TestErasuresExportImportRestore(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "auth.db")
	s, err := authStore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := s.CreateUser("root", "pw")
	if err := s.SetRoles(admin.ID, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	victim, _ := s.CreateUser("victim-name", "pw")
	if _, err := s.CreateFullSession(victim.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "archive.db")
	copyDB(t, db, archive)
	if s, err = authStore.New(db); err != nil {
		t.Fatal(err)
	}
	erasureID, err := s.EraseUser(context.Background(), admin.ID, "", victim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	ledgerFile := filepath.Join(dir, "ledger.json")
	if code, _, stderr := run(t, "export", "-db", db, ledgerFile); code != 0 {
		t.Fatalf("export exit %d: %s", code, stderr)
	}
	info, err := os.Stat(ledgerFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("ledger file mode = %v, %v; want 0600", info.Mode(), err)
	}
	raw, _ := os.ReadFile(ledgerFile)
	if strings.Contains(string(raw), "victim-name") || strings.Contains(string(raw), "$2") {
		t.Fatalf("ledger leaks a username or secret: %s", raw)
	}
	var ledger authStore.Ledger
	if err := json.Unmarshal(raw, &ledger); err != nil || len(ledger.Erasures) != 1 || ledger.Erasures[0].ErasureID != erasureID {
		t.Fatalf("ledger = %s, %v", raw, err)
	}
	if code, _, _ := run(t, "export", "-db", db, ledgerFile); code == 0 {
		t.Fatal("export overwrote an existing file")
	}

	// Restore the pre-deletion archive: the victim is back until import.
	copyDB(t, archive, db)
	code, stdout, stderr := run(t, "import", "-db", db, ledgerFile)
	if code != 0 || !strings.Contains(stdout, "imported 1") {
		t.Fatalf("import exit %d: %s %s", code, stdout, stderr)
	}
	if code, stdout, _ := run(t, "import", "-db", db, ledgerFile); code != 0 || !strings.Contains(stdout, "imported 0") || !strings.Contains(stdout, "1 already present") {
		t.Fatalf("re-import exit %d: %s", code, stdout)
	}
	s, err = authStore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.GetUser(victim.ID); err == nil {
		t.Fatal("restore resurrected the erased user")
	}
	if erased, _ := s.IsErased(context.Background(), victim.ID); !erased {
		t.Fatal("tombstone not imported")
	}
}

func TestErasuresImportRefusesConflictsAndBadInput(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "auth.db")
	s, err := authStore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := s.CreateUser("root", "pw")
	_ = s.SetRoles(admin.ID, []string{"admin"})
	victim, _ := s.CreateUser("victim", "pw")
	erasureID, err := s.EraseUser(context.Background(), admin.ID, "", victim.ID)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	conflict := write("conflict.json", `{"version":1,"erasures":[`+
		`{"erasure_id":"er_new","user_id":"someone","deleted_at":"2026-10-01T00:00:00Z"},`+
		`{"erasure_id":"`+erasureID+`","user_id":"another-user","deleted_at":"2026-10-01T00:00:00Z"}]}`)
	if code, _, stderr := run(t, "import", "-db", db, conflict); code != 1 || !strings.Contains(stderr, "conflicting") {
		t.Fatalf("conflicting import exit %d: %s", code, stderr)
	}
	sameUser := write("same-user.json", `{"version":1,"erasures":[{"erasure_id":"er_other","user_id":"`+victim.ID+`","deleted_at":"2026-10-01T00:00:00Z"}]}`)
	if code, _, _ := run(t, "import", "-db", db, sameUser); code != 1 {
		t.Fatal("import re-erasing a user under another id was accepted")
	}
	for name, body := range map[string]string{
		"unknown-field.json": `{"version":1,"erasures":[],"username":"x"}`,
		"bad-version.json":   `{"version":2,"erasures":[]}`,
		"not-json.json":      `nope`,
	} {
		if code, _, _ := run(t, "import", "-db", db, write(name, body)); code != 1 {
			t.Errorf("%s accepted", name)
		}
	}
	if code, _, _ := run(t, "import", "-db", filepath.Join(dir, "missing.db"), conflict); code != 1 {
		t.Error("import into a missing database accepted")
	}
	ledger, err := authStore.ExportLedger(context.Background(), db)
	if err != nil || len(ledger.Erasures) != 1 {
		t.Fatalf("ledger changed by refused imports: %+v, %v", ledger, err)
	}
	if code, _, _ := run(t); code != 2 {
		t.Error("missing subcommand")
	}
	if code, _, _ := run(t, "export"); code != 2 {
		t.Error("missing output path")
	}
}
