//go:build unix

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
)

// hop daemon starts past a hold marker it must not read: a FIFO, which an
// unrestricted read waits on for a writer that never comes, while the
// daemon owns the vault; and a symlink to a handback marker elsewhere,
// which is not the marker its cleanup inspected, so it is left.
func TestDaemonStartsPastAnUnsafeHoldMarker(t *testing.T) {
	cases := []struct {
		name  string
		plant func(t *testing.T, path string)
	}{
		{"fifo", func(t *testing.T, path string) {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink to a handback", func(t *testing.T, path string) {
			target := filepath.Join(t.TempDir(), "planted")
			if err := os.WriteFile(target, []byte("1 handback\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newInterruptEnv(t)
			if err := os.MkdirAll(x.e.Paths.RunDir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := x.e.holdMarker()
			c.plant(t, path)
			d := &Env{Stdout: &strings.Builder{}, Stderr: &syncBuffer{}, Getenv: x.e.Getenv, DataDir: x.e.DataDir, Paths: x.e.Paths}
			d.OpenStore = func() (model.Store, error) { return openReal(d) }
			dctx, dcancel := context.WithCancel(context.Background())
			ran := make(chan error, 1)
			go func() { ran <- runDaemon(dctx, d, nil) }()
			if !answersWithin(x.e.Paths.ControlSocket(), 5*time.Second) {
				t.Errorf("hop daemon does not serve with an unsafe hold marker; stderr %q", d.Stderr.(*syncBuffer).String())
				// Free a read stuck on the FIFO, so the daemon can end.
				if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					f.Close()
				}
			}
			dcancel()
			select {
			case <-ran:
			case <-time.After(10 * time.Second):
				t.Fatal("hop daemon did not end")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Errorf("the marker it did not inspect was removed: %v", err)
			}
		})
	}
}

// answersWithin reports whether a daemon answers a status request on sock
// within d.
func answersWithin(sock string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if c, err := daemon.Dial(context.Background(), sock); err == nil {
			err = c.Call(context.Background(), daemon.OpStatus, nil, nil)
			c.Close()
			if err == nil {
				return true
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}
