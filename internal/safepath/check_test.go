//go:build unix

package safepath

import (
	"os"
	"path/filepath"
	"testing"
)

// Check says what EnsurePrivateDir would, and creates and changes nothing.
func TestCheckAcceptsAndRefusesLikeEnsurePrivateDirWithoutCreating(t *testing.T) {
	base, err := os.MkdirTemp("", "sp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	below := filepath.Join(base, "a", "b")
	if err := Check(below); err != nil {
		t.Fatalf("a private path that does not exist yet: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(base, "a")); !os.IsNotExist(err) {
		t.Errorf("Check created a directory: %v", err)
	}
	// Open to group and others, and not sticky: refused, as Ensure refuses.
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := Check(below); err == nil {
		t.Error("Check accepted a path below a world-writable directory")
	}
	if _, err := EnsurePrivateDir(below); err == nil {
		t.Error("EnsurePrivateDir accepted it")
	}
	// An existing directory is not tightened by Check.
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Check(loose); err != nil {
		t.Errorf("an existing directory of ours: %v", err)
	}
	if fi, _ := os.Stat(loose); fi.Mode().Perm() != 0o755 {
		t.Errorf("Check changed the mode to %o", fi.Mode().Perm())
	}
}

// Check and EnsurePrivateDir agree on symlinks: a final component that is
// one is refused, dangling or not, and a symlinked ancestor is followed.
func TestCheckTreatsSymlinksAsEnsurePrivateDirDoes(t *testing.T) {
	base, err := os.MkdirTemp("", "sp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(base, "dangling")
	if err := os.Symlink(filepath.Join(base, "gone"), dangling); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		what, dir string
		ok        bool
	}{
		{"a final symlink to a private directory", link, false},
		{"a dangling final symlink", dangling, false},
		{"a directory below a symlinked ancestor", filepath.Join(link, "below"), true},
		{"a directory below a dangling symlink", filepath.Join(dangling, "below"), false},
	} {
		checkErr := Check(c.dir)
		_, ensureErr := EnsurePrivateDir(c.dir)
		if (checkErr == nil) != c.ok || (ensureErr == nil) != c.ok {
			t.Errorf("%s: Check %v, EnsurePrivateDir %v; want accepted %v", c.what, checkErr, ensureErr, c.ok)
		}
	}
}
