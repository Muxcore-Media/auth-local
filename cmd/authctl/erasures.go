package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

// maxLedgerFile bounds the size of an imported ledger file.
const maxLedgerFile = 64 << 20

const erasuresUsage = `usage:
  authctl erasures export [-db <auth.db>] <ledger.json>
  authctl erasures import [-db <auth.db>] <ledger.json>

Offline restore of the ADR-0035 erasure ledger. Both commands open
auth-local's SQLite database directly: run them only while auth-local is
stopped. export writes every tombstone (no usernames, no secrets) to a new
file with mode 0600 and refuses to overwrite. import merges tombstones
(idempotent; a conflicting erasure_id/user_id pair aborts the whole import)
and then deletes every restored row of a tombstoned user ("the tombstone
wins"). -db defaults to AUTH_DB_PATH, else ~/.muxcore/auth.db.
`

func defaultDBPath() string {
	if p := os.Getenv("AUTH_DB_PATH"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "auth.db"
	}
	return filepath.Join(home, ".muxcore", "auth.db")
}

// runErasures implements `authctl erasures ...` and returns the exit code.
func runErasures(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || (args[0] != "export" && args[0] != "import") {
		_, _ = fmt.Fprint(stderr, erasuresUsage)
		return 2
	}
	fs := flag.NewFlagSet("erasures "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", defaultDBPath(), "auth-local SQLite database (auth-local must be stopped)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 1 || fs.Arg(0) == "" {
		_, _ = fmt.Fprint(stderr, erasuresUsage)
		return 2
	}
	ctx := context.Background()
	var err error
	switch args[0] {
	case "export":
		err = exportLedger(ctx, *dbPath, fs.Arg(0), stdout)
	case "import":
		err = importLedger(ctx, *dbPath, fs.Arg(0), stdout)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "erasures %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

func exportLedger(ctx context.Context, dbPath, out string, stdout io.Writer) error {
	ledger, err := authStore.ExportLedger(ctx, dbPath)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return err
	}
	// O_EXCL: never overwrite (or follow a planted symlink to) an existing file.
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-chosen output path
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		_ = os.Remove(out)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "exported %d erasure tombstones to %s\n", len(ledger.Erasures), out)
	return nil
}

func importLedger(ctx context.Context, dbPath, in string, stdout io.Writer) error {
	f, err := os.Open(in) //nolint:gosec // operator-chosen input path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxLedgerFile+1))
	if err != nil {
		return err
	}
	if len(data) > maxLedgerFile {
		return errors.New("ledger file too large")
	}
	var ledger authStore.Ledger
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ledger); err != nil {
		return fmt.Errorf("parse ledger: %w", err)
	}
	res, err := authStore.ImportLedger(ctx, dbPath, &ledger)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "imported %d erasure tombstones (%d already present); removed %d restored rows of erased users\n",
		res.Imported, res.Present, res.Swept)
	return nil
}
