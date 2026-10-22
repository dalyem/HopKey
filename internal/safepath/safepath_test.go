//go:build unix

package safepath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// base returns a fresh 0700 directory of our own. It is a private
// subdirectory of the system temp dir, which is how the production code
// sees /tmp too (sticky, with our 0700 directory below it).
func base(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sp")
	if err != nil {
		t.Fatal(err)
	}
	// The system temp dir may itself sit behind a symlink (macOS).
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func mkdir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // beat the umask
		t.Fatal(err)
	}
}

func mustFail(t *testing.T, dir, wantSubstr string) {
	t.Helper()
	got, err := EnsurePrivateDir(dir)
	if err == nil {
		t.Fatalf("EnsurePrivateDir(%s) = %q, want an error", dir, got)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Errorf("error = %v, want it to mention %q", err, wantSubstr)
	}
}

func TestCreatesPrivateDirs(t *testing.T) {
	dir := filepath.Join(base(t), "a", "b")
	got, err := EnsurePrivateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Errorf("resolved = %q, want %q", got, dir)
	}
	for _, d := range []string{dir, filepath.Dir(dir)} {
		fi, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("%s mode = %o, want 700", d, fi.Mode().Perm())
		}
	}
}

func TestTightensFinalMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o755, 0o777, 0o770, 0o500, 0o600} {
		dir := filepath.Join(base(t), "d")
		mkdir(t, dir, mode)
		if _, err := EnsurePrivateDir(dir); err != nil {
			t.Fatalf("mode %o: %v", mode, err)
		}
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("mode %o: got %o, want 700", mode, fi.Mode().Perm())
		}
	}
}

func TestIntermediateSymlinkToSafeDirPasses(t *testing.T) {
	b := base(t)
	real := filepath.Join(b, "real")
	mkdir(t, real, 0o700)
	if err := os.Symlink(real, filepath.Join(b, "link")); err != nil {
		t.Fatal(err)
	}

	got, err := EnsurePrivateDir(filepath.Join(b, "link", "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(real, "sub"); got != want {
		t.Errorf("resolved = %q, want %q", got, want)
	}
}

func TestIntermediateSymlinkToUnsafeDirFails(t *testing.T) {
	b := base(t)
	loose := filepath.Join(b, "loose")
	mkdir(t, loose, 0o777)
	if err := os.Symlink(loose, filepath.Join(b, "link")); err != nil {
		t.Fatal(err)
	}
	mustFail(t, filepath.Join(b, "link", "sub"), "writable")
}

func TestGroupOrWorldWritableAncestorFails(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777, 0o720} {
		t.Run(mode.String(), func(t *testing.T) {
			b := base(t)
			mkdir(t, filepath.Join(b, "anc"), mode)
			mustFail(t, filepath.Join(b, "anc", "x", "d"), "writable")
		})
	}
}

func TestFinalSymlinkFails(t *testing.T) {
	b := base(t)
	real := filepath.Join(b, "real")
	mkdir(t, real, 0o700)
	link := filepath.Join(b, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	mustFail(t, link, "symlink")

	// A dangling final symlink must not be followed or replaced either.
	dangling := filepath.Join(b, "dangling")
	if err := os.Symlink(filepath.Join(b, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsurePrivateDir(dangling); err == nil {
		t.Error("dangling final symlink accepted")
	}
}

func TestFinalMustBeDirectory(t *testing.T) {
	b := base(t)
	f := filepath.Join(b, "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsurePrivateDir(f); err == nil {
		t.Error("regular file accepted as a directory")
	}
}

func TestRelativePathFails(t *testing.T) {
	mustFail(t, "relative/dir", "not absolute")
}

func TestStickyAncestor(t *testing.T) {
	t.Run("own 0700 directory below sticky passes", func(t *testing.T) {
		b := base(t)
		sticky := filepath.Join(b, "sticky")
		mkdir(t, sticky, 0o777|os.ModeSticky)
		mine := filepath.Join(sticky, "mine")
		mkdir(t, mine, 0o700)
		if _, err := EnsurePrivateDir(filepath.Join(mine, "d")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("final directory directly below sticky passes", func(t *testing.T) {
		b := base(t)
		sticky := filepath.Join(b, "sticky")
		mkdir(t, sticky, 0o777|os.ModeSticky)
		if _, err := EnsurePrivateDir(filepath.Join(sticky, "d")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("0755 directory below sticky fails", func(t *testing.T) {
		b := base(t)
		sticky := filepath.Join(b, "sticky")
		mkdir(t, sticky, 0o777|os.ModeSticky)
		mine := filepath.Join(sticky, "mine")
		mkdir(t, mine, 0o755)
		mustFail(t, filepath.Join(mine, "d"), "0700")
	})
	t.Run("writable without sticky fails", func(t *testing.T) {
		b := base(t)
		loose := filepath.Join(b, "loose")
		mkdir(t, loose, 0o777)
		mine := filepath.Join(loose, "mine")
		mkdir(t, mine, 0o700)
		mustFail(t, filepath.Join(mine, "d"), "writable")
	})
}

// The next tests need a directory owned by another user, which only root can
// make. They skip otherwise; that leaves the foreign-owner branch untested
// when the suite runs unprivileged (as it does on Kiln).

func TestForeignOwnedAncestorFails(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown a directory to another user")
	}
	b := base(t)
	foreign := filepath.Join(b, "foreign")
	mkdir(t, foreign, 0o755)
	if err := os.Chown(foreign, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	mustFail(t, filepath.Join(foreign, "d"), "owned by")
}

func TestForeignOwnedFinalFails(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown a directory to another user")
	}
	b := base(t)
	d := filepath.Join(b, "d")
	mkdir(t, d, 0o700)
	if err := os.Chown(d, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	mustFail(t, d, "not owned")
}
