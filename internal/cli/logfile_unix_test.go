//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestOpenLog(t *testing.T) {
	uid := os.Getuid()
	dir := t.TempDir()
	log := func(name string) string { return filepath.Join(dir, name) }
	perm := func(path string) os.FileMode {
		t.Helper()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode().Perm()
	}

	t.Run("a new log is private whatever the umask", func(t *testing.T) {
		old := syscall.Umask(0)
		defer syscall.Umask(old)
		f, err := openLog(log("new.log"), uid)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if p := perm(log("new.log")); p != 0o600 {
			t.Errorf("mode = %o", p)
		}
	})
	t.Run("a looser existing log is tightened and appended to", func(t *testing.T) {
		path := log("loose.log")
		if err := os.WriteFile(path, []byte("before\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		os.Chmod(path, 0o644)
		f, err := openLog(path, uid)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString("after\n")
		f.Close()
		if b, _ := os.ReadFile(path); string(b) != "before\nafter\n" {
			t.Errorf("content = %q", b)
		}
		if p := perm(path); p != 0o600 {
			t.Errorf("mode = %o, want 600", p)
		}
	})
	t.Run("a symlink is refused and its target untouched", func(t *testing.T) {
		target := log("victim")
		if err := os.WriteFile(target, []byte("secret\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		os.Chmod(target, 0o644)
		link := log("link.log")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		f, err := openLog(link, uid)
		if err == nil {
			f.Close()
			t.Fatal("a symlinked log was opened")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("err = %v", err)
		}
		if b, _ := os.ReadFile(target); string(b) != "secret\n" || perm(target) != 0o644 {
			t.Errorf("the target was touched: %q %o", b, perm(target))
		}
		// A dangling link is no different.
		dangling := log("dangling.log")
		os.Symlink(log("not-there"), dangling)
		if f, err := openLog(dangling, uid); err == nil {
			f.Close()
			t.Error("a dangling symlink was opened")
		}
		if _, err := os.Lstat(log("not-there")); err == nil {
			t.Error("opening through a dangling symlink created its target")
		}
	})
	t.Run("a file owned by someone else is refused", func(t *testing.T) {
		path := log("theirs.log")
		os.WriteFile(path, nil, 0o600)
		if f, err := openLog(path, uid+1); err == nil {
			f.Close()
			t.Error("a log not owned by the caller was opened")
		} else if !strings.Contains(err.Error(), "belongs to uid") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("something that is not a regular file is refused", func(t *testing.T) {
		path := log("fifo.log")
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Skip("no mkfifo here")
		}
		done := make(chan error, 1)
		go func() {
			f, err := openLog(path, uid)
			if err == nil {
				f.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Error("a named pipe was opened")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("openLog blocked on a named pipe")
		}
	})
	t.Run("a log that grew too big is moved aside", func(t *testing.T) {
		path := log("big.log")
		if err := os.WriteFile(path, make([]byte, maxLogSize+1), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := openLog(path, uid)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if fi, _ := os.Stat(path); fi.Size() != 0 {
			t.Errorf("new log has %d bytes", fi.Size())
		}
		if fi, err := os.Stat(path + ".1"); err != nil || fi.Size() != maxLogSize+1 {
			t.Errorf("previous generation: %v %v", fi, err)
		}
	})
}
