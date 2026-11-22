package daemon

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// Regression tests for the live revocation run (REPORT-r2 P1-1, P2-1,
// P2-2). They use only what the daemon had before, so each runs against
// the old code too, where it fails.

// withoutProof makes the server answer the revocation proof with a 404,
// as one that withholds it does: a revocation then stays the server's
// word.
func withoutProof(w *syncWorld) {
	f := interceptor(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		if req.URL.Path == "/v1/retire-status/proof" {
			http.Error(rw, `{"error":{"code":"not_found","message":"not found"}}`, http.StatusNotFound)
			return true
		}
		return false
	})
	w.intercept.Store(&f)
}

// revokeLaptop has the desk revoke the laptop, outside the desk daemon's
// loop.
func (x *syncSetup) revokeLaptop(t *testing.T) {
	t.Helper()
	x.n1.pause(true)
	defer x.n1.pause(false)
	dev1, err := syncclient.StoreDevice(x.n1.st.DeviceAuth)
	if err != nil {
		t.Fatal(err)
	}
	r1 := x.w.client(t).Remote(x.pub.VaultID, dev1)
	laptop := x.n2.st.Info().DeviceID
	if laptop == "" {
		t.Fatal("the laptop has no device ID")
	}
	if _, err := x.n1.st.RevokeDevices(context.Background(), r1, []byte(syncPassword), []string{laptop}, store.CheckpointOptions{}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

// restart stops n's daemon, which closes its store, opens the store again
// and starts a new daemon over it.
func (w *syncWorld) restart(n *node) {
	t := n.t
	t.Helper()
	n.c.Close()
	if err := n.d.Close(); err != nil {
		t.Logf("closing %s: %v", n.name, err)
	}
	st, err := store.Open(context.Background(), n.cfg)
	if err != nil {
		t.Fatalf("reopening %s: %v", n.name, err)
	}
	n.st = st
	w.startWatched(n, st)
}

// agentWatch lists the agent at path over and over, from before the daemon
// that serves it starts, and keeps the most keys it ever saw.
type agentWatch struct {
	most    atomic.Int32
	answers atomic.Int32
	stop    chan struct{}
	done    sync.WaitGroup
}

func watchAgent(path string) *agentWatch {
	a := &agentWatch{stop: make(chan struct{})}
	a.done.Add(1)
	go func() {
		defer a.done.Done()
		for {
			select {
			case <-a.stop:
				return
			default:
			}
			conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
			if err != nil {
				time.Sleep(time.Millisecond)
				continue
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			keys, err := agent.NewClient(conn).List()
			conn.Close()
			if err != nil {
				continue
			}
			a.answers.Add(1)
			if n := int32(len(keys)); n > a.most.Load() {
				a.most.Store(n)
			}
		}
	}()
	return a
}

func (a *agentWatch) end() (most, answers int) {
	close(a.stop)
	a.done.Wait()
	return int(a.most.Load()), int(a.answers.Load())
}

// startWatched starts n's daemon over ms while watching its agent from
// before the socket exists until a second and a half after Start returns,
// and fails if the agent ever served a key.
func (w *syncWorld) startWatched(n *node, ms *store.Store) {
	t := n.t
	t.Helper()
	base := shortDir(t)
	paths := Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg"), StateDir: filepath.Join(base, "state")}
	watch := watchAgent(paths.AgentSocket())
	name := n.name
	d, err := Start(Options{
		Paths: paths, Store: ms, Version: "test", Tailscale: fakeTS{},
		Sync: SyncOptions{Client: syncclient.Options{RootCAs: w.pool}},
		Logf: func(format string, args ...any) { t.Logf(name+": "+format, args...) },
	})
	if err != nil {
		watch.end()
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	time.Sleep(1500 * time.Millisecond)
	most, answers := watch.end()
	if answers == 0 {
		t.Fatalf("%s: the agent never answered", n.name)
	}
	if most > 0 {
		t.Errorf("%s: the agent of a revoked device served %d key(s) after the daemon started", n.name, most)
	}
	c, err := Dial(context.Background(), d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	n.d, n.c, n.paths = d, c, paths
}

// assertCutOff checks that n serves nothing, and that hop unlock does not
// bring the keys back.
func assertCutOff(t *testing.T, n *node, when string) {
	t.Helper()
	if k := n.agentKeys(); k != 0 {
		t.Errorf("%s: the revoked laptop's agent serves %d key(s)", when, k)
	}
	if strings.Contains(n.config(), "Host ") {
		t.Errorf("%s: the revoked laptop's ssh config still has hosts:\n%s", when, n.config())
	}
	err := n.call(OpUnlock, nil, nil)
	if !IsCode(err, CodeRevoked) {
		t.Errorf("%s: hop unlock on the revoked laptop: %v, want a revoked refusal", when, err)
	}
	if k := n.agentKeys(); k != 0 {
		t.Errorf("%s: after hop unlock, the revoked laptop's agent serves %d key(s)", when, k)
	}
}

// P1-1: an online device the server reports revoked locks, and hop unlock
// does not bring its keys back; nor does a restart.
func TestRevokedOnlineDeviceStaysLockedThroughUnlock(t *testing.T) {
	x := newSyncSetup(t)
	withoutProof(x.w)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 5*time.Second, "web1 reaches the laptop", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })

	// The laptop's long-poll would see the checkpoint itself, which is
	// the verified path: keep it out of the way while the desk revokes.
	x.n2.pause(true)
	x.revokeLaptop(t)
	x.n2.pause(false)
	eventually(t, 10*time.Second, "the laptop stops", func() bool { return x.n2.status().State == SyncRevoked })
	assertCutOff(t, x.n2, "online")

	x.w.restart(x.n2)
	assertCutOff(t, x.n2, "after a restart")
}

// P2-1: a device revoked while it could not reach the server keeps its
// keys only until it reaches it; then it is cut off, and stays cut off
// across restarts, with the server down too.
func TestDeviceRevokedOfflineIsCutOffOnReconnectAndStaysCutOff(t *testing.T) {
	x := newSyncSetup(t)
	withoutProof(x.w)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 5*time.Second, "web1 reaches the laptop", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })

	x.n2.pause(true) // offline
	x.revokeLaptop(t)
	if x.n2.agentKeys() != 1 {
		t.Fatal("the offline laptop lost its keys before it reached the server")
	}
	x.n2.pause(false) // back online
	eventually(t, 10*time.Second, "the laptop is cut off", func() bool { return x.n2.status().State == SyncRevoked })
	assertCutOff(t, x.n2, "on reconnect")

	x.w.down.Store(true)
	x.w.restart(x.n2)
	assertCutOff(t, x.n2, "after a restart with the server down")
	x.w.down.Store(false)
	x.w.restart(x.n2)
	assertCutOff(t, x.n2, "after a restart with the server up")
}

// P2-2: a daemon that starts on a device the server has revoked serves no
// key at all, not even for the moment before the server answers.
func TestDaemonStartOnARevokedDeviceServesNoKeys(t *testing.T) {
	x := newSyncSetup(t)
	withoutProof(x.w)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	// The laptop's store pulls web1 without a daemon.
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 5*time.Second, "the desk pushes", func() bool { return x.n1.status().Pending == 0 })
	dev2, err := syncclient.StoreDevice(x.n2.st.DeviceAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.n2.st.Pull(context.Background(), x.w.client(t).Remote(x.pub.VaultID, dev2)); err != nil {
		t.Fatal(err)
	}
	x.revokeLaptop(t)

	x.w.startWatched(x.n2, x.n2.st)
	assertCutOff(t, x.n2, "after start")
}
