package daemon

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/sshconfig"
	"github.com/dalyem/hopkey/internal/store"
)

// Tests for the third review of the revocation work (2caf4bb): a refusal
// is acted on only in the generation its request was made in, a stale
// check does not clear a newer unconfirmed lock, and a wiped device is
// called wiped only once the ssh files are gone, which the daemon sees to.

// A hop lock that lands after a pull or a push the server refused a
// session, and before the refusal is handled, stays a manual lock: the
// recheck that can't reach the server does not relabel it unconfirmed,
// so nothing unlocks it once the server accepts the device again. That
// holds for the sync loop's requests and for hop sync's.
func TestRefusalNeverTakesOverALaterManualLock(t *testing.T) {
	for _, path := range []string{"the sync loop", "hop sync"} {
		t.Run(path, func(t *testing.T) {
			x := newSyncSetup(t)
			var hook atomic.Pointer[func()]
			o := Options{Sync: SyncOptions{noPoll: path == "hop sync"}, sessionRefused: func() {
				if f := hook.Swap(nil); f != nil {
					(*f)()
				}
			}}
			x.w.startWith(x.n2, x.n2.st, o)
			if k := x.n2.agentKeys(); k != 1 {
				t.Fatalf("setup: the agent serves %d key(s)", k)
			}
			d := x.n2.d
			lock := func() { d.lockVault(d.store.(Vault)) }
			hook.Store(&lock)
			const (
				serve = iota
				refuse
				down
			)
			var phase atomic.Int32
			var unavailable atomic.Int32
			x.w.setIntercept(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
				switch phase.Load() {
				case refuse:
					if req.URL.Path == "/v1/auth/challenge" {
						phase.Store(down)
					}
					return unauthorized(rw)
				case down:
					unavailable.Add(1)
					http.Error(rw, "down for maintenance", http.StatusServiceUnavailable)
					return true
				}
				return false
			})
			phase.Store(refuse)
			if path == "hop sync" {
				x.n2.call(OpSyncNow, nil, nil) // fails: the session was refused
			} else {
				d.sync.wake()
			}
			eventually(t, 10*time.Second, "the recheck after the refused session", func() bool {
				return hook.Load() == nil && unavailable.Load() > 0 && x.n2.status().State == SyncLocked
			})
			if info := x.n2.st.Info(); !info.Locked || info.ServerUnconfirmed {
				t.Errorf("hop lock's lock was taken over as unconfirmed: %+v", info)
			}

			// The server back and accepting the device: nothing unlocks.
			x.w.intercept.Store(nil)
			if d.retryUnconfirmed(context.Background()) {
				t.Error("the retry unlocked a vault hop lock locked")
			}
			if !x.n2.st.Info().Locked {
				t.Error("the vault is unlocked")
			}
			if k := x.n2.agentKeys(); k != 0 {
				t.Errorf("the agent serves %d key(s) after hop lock", k)
			}
		})
	}
}

// A retry of an unconfirmed lock whose check comes back accepted after a
// refused hop unlock made a newer unconfirmed lock leaves that lock as it
// is: still unconfirmed, so the sync loop retries it, and unlocks it once
// the server accepts the device.
func TestStaleRetryKeepsANewerUnconfirmedLock(t *testing.T) {
	x := newSyncSetup(t)
	var hook atomic.Pointer[func()]
	o := Options{Sync: SyncOptions{noPoll: true}, unconfirmedRead: func() {
		if f := hook.Swap(nil); f != nil {
			(*f)()
		}
	}}
	x.w.startWith(x.n2, x.n2.st, o)
	if k := x.n2.agentKeys(); k != 1 {
		t.Fatalf("setup: the agent serves %d key(s)", k)
	}
	laptop := laptopID(t, x.n2)
	x.n2.pause(true)
	d := x.n2.d
	d.mu.Lock()
	d.unconfirmedLocked(store.ErrServerUnconfirmed)
	d.mu.Unlock()
	g, ok := x.n2.st.UnconfirmedLock()
	if !ok {
		t.Fatal("setup: the vault is not locked as unconfirmed")
	}
	ctx := context.Background()
	refusedUnlock := func() {
		refuseLaptop(x.w, laptop, model.ID{}, "no receipt")
		err := d.unlockVault(ctx, d.store.(Vault), UnlockParams{})
		x.w.intercept.Store(nil)
		if !errors.Is(err, store.ErrServerUnconfirmed) {
			t.Errorf("setup: the refused unlock: %v", err)
		}
	}
	hook.Store(&refusedUnlock)
	if d.retryUnconfirmed(ctx) {
		t.Fatal("the stale retry unlocked the newer lock")
	}
	if hook.Load() != nil {
		t.Fatal("setup: the refused unlock did not happen")
	}
	h, ok := x.n2.st.UnconfirmedLock()
	if !ok || h == g {
		t.Fatalf("setup: no newer unconfirmed lock (%d, %v; the old one %d)", h, ok, g)
	}
	if info := x.n2.st.Info(); !info.Locked || !info.ServerUnconfirmed {
		t.Errorf("the newer lock lost its unconfirmed reason: %+v", info)
	}

	x.n2.pause(false)
	eventually(t, 10*time.Second, "the loop unlocks the newer lock once the server accepts the device", func() bool {
		return x.n2.agentKeys() == 1
	})
}

// wipedLaptop is a laptop the desk revoked, whose daemon proved it and
// wiped it, ssh files included. o is for its daemon.
func wipedLaptop(t *testing.T, o Options) *syncSetup {
	t.Helper()
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.startWith(x.n2, x.n2.st, o)
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 5*time.Second, "web1 reaches the laptop", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })
	x.n2.pause(true)
	x.revokeLaptop(t)
	x.n2.pause(false)
	eventually(t, 15*time.Second, "the laptop is wiped", func() bool {
		r := x.n2.status().ServerRetirement
		return r != nil && r.Wiped
	})
	return x
}

// plantConfig writes an ssh config naming a host into n's ssh config
// directory, as a hop process that wrote after the wipe would.
func plantConfig(t *testing.T, n *node) {
	t.Helper()
	err := sshconfig.Write(sshconfig.Options{Dir: n.paths.ConfigDir, AgentSocket: filepath.Join(n.paths.RunDir, "agent.sock")},
		[]sshconfig.Host{{Alias: "planted", HostName: "203.0.113.50", User: "deploy", Keyless: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(n.config(), "Host planted") {
		t.Fatal("setup: nothing was planted")
	}
}

// Status calls a wiped device wiped only while its ssh config directory
// holds nothing the vault decrypted: files found there after the wipe
// make it pending again, in the retirement's fields and its warnings.
func TestWipedStatusCountsSSHFilesLeftAfterTheWipe(t *testing.T) {
	x := wipedLaptop(t, Options{configRetry: time.Hour})
	plantConfig(t, x.n2)
	s := x.n2.status()
	r := s.ServerRetirement
	if r == nil || r.Unverified {
		t.Fatalf("server retirement %+v", r)
	}
	if r.Wiped || !r.SSHFilesLeft || !strings.Contains(r.WipeError, "not removed yet") {
		t.Errorf("with ssh files left: wiped %v, ssh files left %v, wipe error %q", r.Wiped, r.SSHFilesLeft, r.WipeError)
	}
	for _, w := range s.Warnings {
		if strings.Contains(w, "ssh files hop wrote were wiped") {
			t.Errorf("a warning says the ssh files were wiped: %s", w)
		}
	}
	if err := sshconfig.Wipe(sshconfig.Options{Dir: x.n2.paths.ConfigDir}); err != nil {
		t.Fatal(err)
	}
	if r := x.n2.status().ServerRetirement; !r.Wiped || r.SSHFilesLeft || r.WipeError != "" {
		t.Errorf("with the files gone: %+v", r)
	}
}

// The daemon removes ssh files it finds on a wiped device, as it says it
// does: the cleanup is marked owed, the files go, and the mark with them.
func TestDaemonRemovesSSHFilesLeftAfterTheWipe(t *testing.T) {
	x := wipedLaptop(t, Options{configRetry: 100 * time.Millisecond})
	plantConfig(t, x.n2)
	o := sshconfig.Options{Dir: x.n2.paths.ConfigDir}
	eventually(t, 10*time.Second, "the daemon removes the planted files", func() bool {
		left, err := sshconfig.Generated(o)
		return err == nil && !left
	})
	eventually(t, 5*time.Second, "status says wiped again", func() bool {
		r := x.n2.status().ServerRetirement
		return r != nil && r.Wiped
	})
	if _, err := os.Lstat(filepath.Join(x.n2.cfg.DataDir, "logout-cleanup")); !os.IsNotExist(err) {
		t.Errorf("the cleanup mark is still there: %v", err)
	}
}
