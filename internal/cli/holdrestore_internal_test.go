package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
)

// deadPID is the pid of a process that has exited.
func deadPID(t *testing.T) int {
	t.Helper()
	c := exec.Command(os.Args[0], "-test.run=^$")
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	return c.Process.Pid
}

// serveDaemon runs hop daemon on x's vault until the test ends, and
// returns its first status.
func serveDaemon(t *testing.T, x *interruptEnv) daemon.StatusResult {
	t.Helper()
	st, _, stop := startServing(t, x)
	t.Cleanup(stop)
	return st
}

// startServing runs hop daemon on x's vault, and returns its first status,
// what it writes on stderr, and what stops it.
func startServing(t *testing.T, x *interruptEnv) (daemon.StatusResult, *syncBuffer, func()) {
	t.Helper()
	stderr := &syncBuffer{}
	d := &Env{
		Stdout: &strings.Builder{}, Stderr: stderr, Getenv: x.e.Getenv,
		DataDir: x.e.DataDir, Paths: x.e.Paths,
	}
	d.OpenStore = func() (model.Store, error) { return openReal(d) }
	dctx, dcancel := context.WithCancel(context.Background())
	ran := make(chan error, 1)
	go func() { ran <- runDaemon(dctx, d, nil) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			dcancel()
			if err := <-ran; err != nil {
				t.Errorf("runDaemon: %v; stderr %q", err, stderr)
			}
		})
	}
	var st daemon.StatusResult
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := daemon.Dial(context.Background(), x.e.Paths.ControlSocket())
		if err == nil {
			err = c.Call(context.Background(), daemon.OpStatus, nil, &st)
			c.Close()
			if err == nil {
				return st, stderr, stop
			}
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatalf("the daemon does not answer: %v; stderr %q", err, stderr)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// Away from a prompt, abandon launches the daemon without waiting for it,
// and the process exits: the daemon may read the marker after its holder
// is gone. A vault that was locked is still served locked.
func TestHandbackOfALockedVaultOutlivesTheHolder(t *testing.T) {
	x := newInterruptEnv(t)
	ctx, cancel := interrupted()
	h, err := holdVault(ctx, x.e, false)
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.keepOpen, h.wasLocked = true, true // what holdVaultKeeping finds
	h.mu.Unlock()
	go x.e.watchInterrupt(ctx, make(chan struct{}), false, false)
	cancel(ErrInterrupted)
	select {
	case <-x.exits:
	case <-time.After(5 * time.Second):
		t.Fatal("no exit after the interrupt")
	}
	// The holder has exited by the time the daemon looks.
	b, err := os.ReadFile(x.e.holdMarker())
	if err != nil {
		t.Fatal(err)
	}
	gone := strings.Replace(string(b), strconv.Itoa(os.Getpid()), strconv.Itoa(deadPID(t)), 1)
	if err := os.WriteFile(x.e.holdMarker(), []byte(gone), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := serveDaemon(t, x); st.Vault == nil || !st.Vault.Locked {
		t.Errorf("the daemon serves the vault open: %+v", st.Vault)
	}
	if err := goneSoon(x.e.startLockedFile()); !os.IsNotExist(err) {
		t.Errorf("the instruction to start locked is left after the daemon took it: %v", err)
	}
}

// An instruction to start locked is for its own vault, and for a while:
// another vault's daemon leaves it alone, and an old one is not followed.
func TestStartLockedIsForItsVaultAndForAWhile(t *testing.T) {
	t.Run("another vault", func(t *testing.T) {
		x := newInterruptEnv(t)
		other := filepath.Join(t.TempDir(), "data")
		writeStartLocked(t, x, other, time.Now())
		if st := serveDaemon(t, x); st.Vault == nil || st.Vault.Locked {
			t.Errorf("another vault's instruction locked this one: %+v", st.Vault)
		}
		if b, err := os.ReadFile(x.e.startLockedFile()); err != nil || strings.TrimSpace(string(b)) != other {
			t.Errorf("another vault's instruction is gone: %q, %v", b, err)
		}
	})
	t.Run("too old", func(t *testing.T) {
		x := newInterruptEnv(t)
		writeStartLocked(t, x, x.e.storeConfig().DataDir, time.Now().Add(-2*startLockedMaxAge))
		if st := serveDaemon(t, x); st.Vault == nil || st.Vault.Locked {
			t.Errorf("an old instruction locked the vault: %+v", st.Vault)
		}
		if _, err := os.Lstat(x.e.startLockedFile()); !os.IsNotExist(err) {
			t.Errorf("an old instruction is left: %v", err)
		}
	})
}

// goneSoon waits a moment for path to go, and returns what Lstat last said
// of it: the daemon removes the instruction to start locked just after it
// begins to serve, so a status can come first.
func goneSoon(path string) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := os.Lstat(path)
		if os.IsNotExist(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func writeStartLocked(t *testing.T, x *interruptEnv, dataDir string, at time.Time) {
	t.Helper()
	if err := os.MkdirAll(x.e.Paths.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := x.e.startLockedFile()
	if err := os.WriteFile(path, []byte(dataDir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}
