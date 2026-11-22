package store

import (
	"errors"
	"os"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
)

// writeRevocation writes the record a wipe leaves in dataDir.
func writeRevocation(t *testing.T, dataDir string) {
	t.Helper()
	b, err := canonjson.Marshal(RevocationRecord{V: 1, How: "revoked", Seq: 9})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout{data: dataDir}.revocationFile(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if rec, err := ReadRevocation(dataDir); rec == nil || err != nil {
		t.Fatalf("setup: the revocation record: %v, %v", rec, err)
	}
}

// The cleanup outside the store is owed where the mark says so, or where
// a revocation wiped the vault and the ssh files are still there; then
// the mark goes down first. A vault that is there, a new sign-in's, owes
// nothing without the mark, nor does a device with no revocation record or
// no files left.
func TestOweSSHCleanup(t *testing.T) {
	for _, c := range []struct {
		name                    string
		mark, vault, rev, files bool
		owed, marked            bool
	}{
		{name: "the mark", mark: true, owed: true, marked: true},
		{name: "the mark, a vault there", mark: true, vault: true, owed: true, marked: true},
		{name: "wiped, files left", rev: true, files: true, owed: true, marked: true},
		{name: "wiped, nothing left", rev: true},
		{name: "a new sign-in's vault", vault: true, rev: true, files: true},
		{name: "no revocation", files: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := t.TempDir()
			l := layout{data: data}
			if c.mark {
				if err := markLogoutCleanup(data); err != nil {
					t.Fatal(err)
				}
			}
			if c.vault {
				if err := os.MkdirAll(l.vault(), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(l.stateFile(), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if c.rev {
				writeRevocation(t, data)
			}
			asked := false
			owed, err := OweSSHCleanup(data, func() (bool, error) { asked = true; return c.files, nil })
			if err != nil || owed != c.owed {
				t.Errorf("owed %v, %v; want %v", owed, err, c.owed)
			}
			if marked, _ := LogoutCleanupPending(data); marked != c.marked {
				t.Errorf("marked %v, want %v", marked, c.marked)
			}
			if asked && (c.mark || c.vault || !c.rev) {
				t.Error("the ssh files were looked at when the answer did not need them")
			}
		})
	}

	// A failure to look at the files is no decision to wipe.
	data := t.TempDir()
	writeRevocation(t, data)
	boom := errors.New("boom")
	if owed, err := OweSSHCleanup(data, func() (bool, error) { return false, boom }); owed || !errors.Is(err, boom) {
		t.Errorf("a failed look: owed %v, %v", owed, err)
	}
	if marked, _ := LogoutCleanupPending(data); marked {
		t.Error("a failed look marked the cleanup owed")
	}
}
