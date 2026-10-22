package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

// The kit file is written in full and fsynced, then linked into place and
// its directory fsynced, before showKit reports it saved.
func TestKitFileIsDurable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kit.txt")
	var synced []string
	kitSync = func(f *os.File) error {
		synced = append(synced, f.Name())
		return f.Sync()
	}
	t.Cleanup(func() { kitSync = func(f *os.File) error { return f.Sync() } })

	var out bytes.Buffer
	e := &Env{Stdout: &out, Stderr: &out}
	kit := store.Kit{AccountID: "acct", SecretKey: "H1-SECRET", RecoveryKey: "R1-RECOVERY"}
	if err := showKit(e, kit, path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != kit.Text() {
		t.Fatalf("kit file = %q, %v", b, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if len(synced) != 2 || !strings.HasPrefix(filepath.Base(synced[0]), ".hop-kit-") || synced[1] != dir {
		t.Errorf("synced %q, want the temp file and then %s", synced, dir)
	}
	if !strings.Contains(out.String(), "also written to "+path) {
		t.Errorf("output %q", out.String())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("left behind: %v", ents)
	}

	// An existing file is never replaced.
	if err := showKit(e, kit, path); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("second write: %v", err)
	}
	// A failed fsync is an error, and nothing is reported saved.
	kitSync = func(*os.File) error { return os.ErrInvalid }
	out.Reset()
	if err := showKit(e, kit, filepath.Join(dir, "other.txt")); err == nil || strings.Contains(out.String(), "also written") {
		t.Errorf("failed sync: %v, output %q", err, out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "other.txt")); err == nil {
		t.Error("a kit file whose fsync failed was linked into place")
	}
}

// A daemon that finds the vault owned by another one says so and exits
// cleanly, as it does when the sockets are taken.
func TestDaemonWithTheVaultOwned(t *testing.T) {
	var stderr bytes.Buffer
	e := &Env{
		Stdout: &stderr, Stderr: &stderr,
		OpenStore: func() (model.Store, error) { return nil, store.ErrVaultBusy },
	}
	if err := runDaemon(context.Background(), e, nil); err != nil {
		t.Fatalf("runDaemon: %v", err)
	}
	if !strings.Contains(stderr.String(), "already running") {
		t.Errorf("stderr %q", stderr.String())
	}
}
