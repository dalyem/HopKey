package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/model/modeltest"
	"github.com/dalyem/hopkey/internal/store"
)

// envDumpVar makes the test binary, started as "<binary> daemon" or
// "<binary> dump", write its environment to the named file and exit: it
// stands in for the processes hop starts.
const envDumpVar = "HOPKEY_TEST_DUMP_ENV"

func TestMain(m *testing.M) {
	// ssh runs this binary as hop session attach, the LocalCommand of a
	// machine whose daemon has hopBin (sessions_e2e_test.go).
	if len(os.Args) >= 2 && os.Args[1] == "session" {
		if len(os.Args) >= 3 && os.Args[2] == "attach" {
			SessionAttach(os.Args[3:])
		}
		os.Exit(0)
	}
	if out := os.Getenv(envDumpVar); out != "" && len(os.Args) > 1 {
		if last := os.Args[len(os.Args)-1]; last == "daemon" || last == "dump" {
			if err := os.WriteFile(out, []byte(strings.Join(os.Environ(), "\x00")), 0o600); err != nil {
				os.Exit(3)
			}
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

var testSecrets = []string{
	"HOP_PASSWORD=hunter2-password", "HOP_NEW_PASSWORD=hunter2-new", "HOP_SECRET_KEY=A3-SECRET-KEY",
	"HOP_RECOVERY_KEY=R1-RECOVERY-KEY", "HOP_KIT_CONFIRM=AAAAA BBBBB",
}

func hasVar(environ []string, name string) bool {
	return slices.ContainsFunc(environ, func(kv string) bool { return strings.HasPrefix(kv, name+"=") })
}

func noSecrets(t *testing.T, what string, environ []string) {
	t.Helper()
	for _, kv := range testSecrets {
		name, val, _ := strings.Cut(kv, "=")
		if hasVar(environ, name) || slices.ContainsFunc(environ, func(e string) bool { return strings.Contains(e, val) }) {
			t.Errorf("%s gets %s", what, name)
		}
	}
	if !hasVar(environ, "PATH") {
		t.Errorf("%s lost PATH: %q", what, environ)
	}
}

// Every process hop starts gets the caller's environment without the hop
// auth secrets: the daemon (started for real), ssh, and systemctl or
// launchctl (run for real). Only the daemon keeps the device passphrase.
func TestChildProcessesGetNoAuthSecrets(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := shortTempDir(t)
	dump := filepath.Join(dir, "env")
	base := append([]string{"PATH=" + os.Getenv("PATH"), "SSH_AUTH_SOCK=/tmp/agent", store.PassphraseEnv + "=pp", envDumpVar + "=" + dump}, testSecrets...)
	e := &Env{
		Stdout: &strings.Builder{}, Stderr: &strings.Builder{}, Getenv: func(string) string { return "" },
		Environ: base, Executable: self,
		Paths: daemon.Paths{RunDir: filepath.Join(dir, "run"), StateDir: filepath.Join(dir, "state")},
	}

	env := e.environ()
	noSecrets(t, "environ", env)
	if !hasVar(env, store.PassphraseEnv) || !hasVar(env, "SSH_AUTH_SOCK") {
		t.Errorf("environ dropped what the daemon needs: %q", env)
	}
	ssh := e.sshEnviron()
	noSecrets(t, "ssh", ssh)
	if hasVar(ssh, store.PassphraseEnv) || hasVar(ssh, "SSH_AUTH_SOCK") {
		t.Errorf("ssh gets the agent or the device passphrase: %q", ssh)
	}

	var got []string
	e.ExecSSH = func(_ string, _, environ []string) error { got = environ; return nil }
	if err := e.execSSH([]string{"sh"}); err != nil {
		t.Fatal(err)
	}
	noSecrets(t, "hop <target>'s ssh", got)

	readDump := func(what string) []string {
		t.Helper()
		var b []byte
		deadline := time.Now().Add(10 * time.Second)
		for {
			var err error
			if b, err = os.ReadFile(dump); err == nil && len(b) > 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s never ran", what)
			}
			time.Sleep(20 * time.Millisecond)
		}
		os.Remove(dump)
		return strings.Split(string(b), "\x00")
	}
	// The real launch: a detached process, as autostart and every hop
	// auth command's restart run it.
	if err := launchDaemon(e); err != nil {
		t.Fatal(err)
	}
	noSecrets(t, "the daemon", readDump("the daemon"))

	if _, err := e.runCommand(context.Background(), []string{self, "dump"}); err != nil {
		t.Fatal(err)
	}
	svc := readDump("the service command")
	noSecrets(t, "systemctl", svc)
	if hasVar(svc, store.PassphraseEnv) {
		t.Errorf("systemctl gets the device passphrase: %q", svc)
	}
}

// interruptEnv is an Env with a vault, whose daemon start and exit are
// recorded.
type interruptEnv struct {
	e      *Env
	mu     sync.Mutex
	starts []string // the marker's text at each daemon start
	exits  chan int
}

func newInterruptEnv(t *testing.T) *interruptEnv {
	t.Helper()
	dir := shortTempDir(t)
	x := &interruptEnv{exits: make(chan int, 4)}
	x.e = &Env{
		Stdout: &strings.Builder{}, Stderr: &strings.Builder{}, Getenv: func(string) string { return "" },
		DataDir: filepath.Join(dir, "data"),
		Paths:   daemon.Paths{RunDir: filepath.Join(dir, "run"), StateDir: filepath.Join(dir, "state"), ConfigDir: filepath.Join(dir, "ssh")},
		StartDaemon: func() error {
			b, _ := os.ReadFile(filepath.Join(dir, "run", holdMarkerName))
			x.mu.Lock()
			defer x.mu.Unlock()
			x.starts = append(x.starts, strings.TrimSpace(string(b)))
			return nil
		},
		DaemonWait:     50 * time.Millisecond,
		InterruptGrace: 50 * time.Millisecond,
		Exit:           func(code int) { x.exits <- code },
	}
	p, err := store.PrepareInit(x.e.storeConfig(), store.InitOptions{Password: []byte("interrupt test password"), DeviceStore: store.DeviceStoreFile})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	return x
}

func (x *interruptEnv) started() []string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return slices.Clone(x.starts)
}

func interrupted() (context.Context, context.CancelCauseFunc) {
	return context.WithCancelCause(context.Background())
}

// SIGINT while a hop auth flow is stuck at a prompt: the daemon is
// launched to take the vault after this process, the marker says so, and
// the process exits 130. The flow's own release, if it ever runs, does
// not start a second daemon.
func TestInterruptAbandonsAStuckFlow(t *testing.T) {
	x := newInterruptEnv(t)
	ctx, cancel := interrupted()
	h, err := holdVault(ctx, x.e, false)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(x.e.holdMarker()); err != nil || strings.TrimSpace(string(b)) != strconv.Itoa(os.Getpid()) {
		t.Fatalf("marker %q, %v", b, err)
	}
	done := make(chan struct{})
	go x.e.watchInterrupt(ctx, done, false)
	cancel(ErrInterrupted)
	select {
	case code := <-x.exits:
		if code != ExitInterrupted {
			t.Errorf("exit %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no exit after the interrupt")
	}
	want := strconv.Itoa(os.Getpid()) + " handback"
	if got := x.started(); len(got) != 1 || got[0] != want {
		t.Fatalf("daemon starts %q; want one, with the marker %q", got, want)
	}
	h.release(ctx)
	close(done)
	if got := x.started(); len(got) != 1 {
		t.Errorf("release after abandon started the daemon again: %q", got)
	}
}

// A flow that returns once its context is cancelled releases the vault
// itself: the watcher neither abandons it nor exits.
func TestInterruptLetsAReturningFlowRelease(t *testing.T) {
	x := newInterruptEnv(t)
	x.e.InterruptGrace = 2 * time.Second
	ctx, cancel := interrupted()
	h, err := holdVault(ctx, x.e, false)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	watched := make(chan struct{})
	go func() { x.e.watchInterrupt(ctx, done, false); close(watched) }()
	cancel(ErrInterrupted)
	<-ctx.Done()
	h.release(ctx)
	close(done)
	<-watched
	if got := x.started(); len(got) != 1 || got[0] != "" {
		t.Errorf("daemon starts %q; want one, after the marker is gone", got)
	}
	select {
	case code := <-x.exits:
		t.Errorf("exited %d", code)
	default:
	}
}

// With no hold, a signal ends the command at once, as it did before
// hop caught signals; hop daemon handles it itself; a deadline is not a
// signal.
func TestInterruptWithoutAHold(t *testing.T) {
	x := newInterruptEnv(t)
	ctx, cancel := interrupted()
	go x.e.watchInterrupt(ctx, make(chan struct{}), false)
	cancel(ErrInterrupted)
	select {
	case code := <-x.exits:
		if code != ExitInterrupted {
			t.Errorf("exit %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no exit")
	}

	ctx, cancel = interrupted()
	watched := make(chan struct{})
	go func() { x.e.watchInterrupt(ctx, make(chan struct{}), true); close(watched) }()
	cancel(ErrInterrupted)
	<-watched

	dctx, dcancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer dcancel()
	watched = make(chan struct{})
	go func() { x.e.watchInterrupt(dctx, make(chan struct{}), false); close(watched) }()
	<-watched
	select {
	case code := <-x.exits:
		t.Errorf("exited %d", code)
	default:
	}
}

// While a hop auth command in another process holds the vault, autostart
// and hop daemon refuse to start a daemon, and a second hop auth command
// refuses to hold it. A marker whose process is gone counts for nothing.
func TestHoldMarkerKeepsOtherDaemonsOut(t *testing.T) {
	x := newInterruptEnv(t)
	if err := os.MkdirAll(x.e.Paths.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := x.e.holdMarker()
	other := os.Getppid() // alive, and not this process
	if err := os.WriteFile(marker, []byte(strconv.Itoa(other)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	want := "hop auth command (pid " + strconv.Itoa(other) + ")"
	if _, err := connect(ctx, x.e); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("autostart during a hold: %v", err)
	}
	opened := false
	x.e.OpenStore = func() (model.Store, error) { opened = true; return nil, errors.New("not here") }
	if err := runDaemon(ctx, x.e, nil); err == nil || !strings.Contains(err.Error(), want) || opened {
		t.Errorf("hop daemon during a hold: %v (opened the vault: %v)", err, opened)
	}
	if _, err := holdVault(ctx, x.e, false); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("a second hold: %v", err)
	}
	if got := x.started(); len(got) != 0 {
		t.Errorf("a daemon was started during the hold: %q", got)
	}

	// The holder is gone: the marker is stale.
	dead := exec.Command("true")
	if err := dead.Run(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte(strconv.Itoa(dead.Process.Pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := connect(ctx, x.e); err == nil || strings.Contains(err.Error(), "hop auth command") {
		t.Errorf("autostart with a stale marker: %v", err)
	}
	if got := x.started(); len(got) != 1 {
		t.Errorf("autostart with a stale marker did not start the daemon: %q", got)
	}
	h, err := holdVault(ctx, x.e, false)
	if err != nil {
		t.Fatalf("hold with a stale marker: %v", err)
	}
	h.release(ctx)
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("release left the marker: %v", err)
	}
}

// A daemon launched by an interrupted hop auth command finds the vault
// busy until that process exits, waits for it, and then serves; it
// removes the handback marker.
func TestDaemonWaitsForAHandback(t *testing.T) {
	x := newInterruptEnv(t)
	if err := os.MkdirAll(x.e.Paths.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	holder := exec.Command("sleep", "0.5")
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	gone := make(chan struct{})
	go func() { holder.Wait(); close(gone) }()
	marker := x.e.holdMarker()
	if err := os.WriteFile(marker, []byte(strconv.Itoa(holder.Process.Pid)+" handback\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var busy atomic.Int32
	x.e.OpenStore = func() (model.Store, error) {
		select {
		case <-gone:
			return modeltest.New(), nil
		default:
			busy.Add(1)
			return nil, store.ErrVaultBusy
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan error, 1)
	go func() { ran <- runDaemon(ctx, x.e, nil) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if c, err := daemon.Dial(ctx, x.e.Paths.ControlSocket()); err == nil {
			c.Close()
			break
		}
		select {
		case err := <-ran:
			t.Fatalf("the daemon ended: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the daemon never served")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if busy.Load() == 0 {
		t.Error("the vault was never busy: the test did not exercise the wait")
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the handback marker is left: %v", err)
	}
	cancel()
	if err := <-ran; err != nil {
		t.Errorf("runDaemon: %v", err)
	}
}

// fakeShutdown listens on the control socket and takes one request, then
// does what answer says with the connection and the listener.
func fakeShutdown(t *testing.T, e *Env, answer func(c net.Conn, ln net.Listener)) {
	t.Helper()
	if err := os.MkdirAll(e.Paths.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", e.Paths.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
			return
		}
		answer(c, ln)
	}()
}

// A signal that lands after the daemon took the shutdown request, before
// its answer is read: the daemon stops all the same, so hop auth starts
// it again rather than leave the device without one.
func TestInterruptedShutdownRestartsTheDaemon(t *testing.T) {
	x := newInterruptEnv(t)
	ctx, cancel := interrupted()
	fakeShutdown(t, x.e, func(c net.Conn, ln net.Listener) {
		cancel(ErrInterrupted)
		time.Sleep(100 * time.Millisecond) // the client gives up on the answer
		ln.Close()                         // the daemon exits; its socket goes
	})
	if _, err := holdVault(ctx, x.e, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("hold: %v", err)
	}
	if got := x.started(); len(got) != 1 || got[0] != "" {
		t.Errorf("daemon starts %q; want one, after the marker is gone", got)
	}
	if _, err := os.Lstat(x.e.holdMarker()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the marker is left: %v", err)
	}
	if x.e.currentHold() != nil {
		t.Error("the hold is left")
	}
}

// A daemon that refuses to stop keeps running: nothing is started, and
// the marker goes.
func TestRefusedShutdownStartsNothing(t *testing.T) {
	x := newInterruptEnv(t)
	fakeShutdown(t, x.e, func(c net.Conn, _ net.Listener) {
		json.NewEncoder(c).Encode(daemon.Response{Error: &daemon.Error{Code: "busy", Message: "not now"}})
	})
	if _, err := holdVault(context.Background(), x.e, false); err == nil || !strings.Contains(err.Error(), "not now") {
		t.Fatalf("hold: %v", err)
	}
	if got := x.started(); len(got) != 0 {
		t.Errorf("a running daemon was started again: %q", got)
	}
	if _, err := os.Lstat(x.e.holdMarker()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the marker is left: %v", err)
	}
}

// A signal while hop daemon starts, in the order the process meets them:
// Run's watcher already runs when dispatch reaches runDaemon. The watcher
// knows from the arguments that hop daemon handles the signal, so it
// neither races dispatch (go test -race) nor exits, and the daemon,
// closing on the signal, exits 0.
func TestSignalDuringDaemonStart(t *testing.T) {
	x := newInterruptEnv(t)
	x.e.OpenStore = func() (model.Store, error) { return modeltest.New(), nil }
	ctx, cancel := interrupted()
	cancel(ErrInterrupted)
	if code := Run(ctx, []string{"daemon"}, x.e); code != 0 {
		t.Errorf("hop daemon: exit %d: %s", code, x.e.Stderr)
	}
	select {
	case code := <-x.exits:
		t.Errorf("the watcher exited %d under hop daemon", code)
	case <-time.After(100 * time.Millisecond):
	}
}

// A --json flow abandoned on a signal, whose daemon does not start,
// warns in JSON like the rest of its stderr.
func TestAbandonWarnsInJSON(t *testing.T) {
	x := newInterruptEnv(t)
	x.e.StartDaemon = func() error { return errors.New("no daemon here") }
	ctx, cancel := interrupted()
	if _, err := holdVault(ctx, x.e, true); err != nil {
		t.Fatal(err)
	}
	go x.e.watchInterrupt(ctx, make(chan struct{}), false)
	cancel(ErrInterrupted)
	select {
	case <-x.exits:
	case <-time.After(5 * time.Second):
		t.Fatal("no exit after the interrupt")
	}
	out := x.e.Stderr.(*strings.Builder).String()
	var w struct {
		Warning string `json:"warning"`
	}
	if err := json.Unmarshal([]byte(out), &w); err != nil || !strings.Contains(w.Warning, "no daemon here") {
		t.Errorf("stderr %q is not one JSON warning: %v", out, err)
	}
}

// openReal opens the vault in e's data directory for real, so the
// owner lock is held while the returned store is open.
func openReal(e *Env) (model.Store, error) {
	s, err := store.Open(context.Background(), e.storeConfig())
	if err != nil {
		return nil, err
	}
	return s, nil
}

// A signal cuts the shutdown answer short, and the old daemon, its
// sockets gone, still owns the vault while it drains. hop auth waits for
// it to let go before it starts the daemon again, so the new one gets the
// vault and serves, instead of finding it busy and exiting.
func TestInterruptedShutdownWaitsForTheOldDaemon(t *testing.T) {
	x := newInterruptEnv(t)
	x.e.DaemonWait = 10 * time.Second
	old, err := store.Open(context.Background(), x.e.storeConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	var oldClosed atomic.Bool
	ctx, cancel := interrupted()
	fakeShutdown(t, x.e, func(c net.Conn, ln net.Listener) {
		cancel(ErrInterrupted)
		time.Sleep(100 * time.Millisecond) // the client gives up on the answer
		ln.Close()                         // the sockets go first
		time.Sleep(500 * time.Millisecond) // the store drains
		oldClosed.Store(true)
		old.Close()
	})

	// The replacement is the real hop daemon, on its own Env (its stderr is
	// its own), opening the vault for real.
	dctx, dcancel := context.WithCancel(context.Background())
	defer dcancel()
	replacement := &Env{
		Stdout: &strings.Builder{}, Stderr: &strings.Builder{}, Getenv: x.e.Getenv,
		DataDir: x.e.DataDir, Paths: x.e.Paths,
	}
	replacement.OpenStore = func() (model.Store, error) { return openReal(replacement) }
	ran := make(chan error, 1)
	var launched atomic.Int32
	x.e.StartDaemon = func() error {
		launched.Add(1)
		go func() { ran <- runDaemon(dctx, replacement, nil) }()
		return nil
	}

	if _, err := holdVault(ctx, x.e, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("hold: %v", err)
	}
	if !oldClosed.Load() {
		t.Error("holdVault returned before the old daemon let go of the vault")
	}
	if n := launched.Load(); n != 1 {
		t.Fatalf("the daemon was launched %d times, want once", n)
	}
	select {
	case err := <-ran:
		t.Fatalf("the new daemon ended: %v; stderr %q", err, replacement.Stderr)
	default:
	}
	c, err := daemon.Dial(context.Background(), x.e.Paths.ControlSocket())
	if err != nil {
		t.Fatalf("the new daemon does not listen: %v; hop auth's stderr %q", err, x.e.Stderr)
	}
	err = c.Call(context.Background(), daemon.OpStatus, nil, nil)
	c.Close()
	if err != nil {
		t.Fatalf("the new daemon does not answer: %v", err)
	}
	if s := x.e.Stderr.(*strings.Builder).String(); s != "" {
		t.Errorf("hop auth warned: %q", s)
	}
	dcancel()
	if err := <-ran; err != nil {
		t.Errorf("runDaemon: %v; stderr %q", err, replacement.Stderr)
	}
}

// A daemon started the ordinary way, with no handback, against a vault
// that another process really owns (its owner lock is held) and no
// daemon answering, fails within busyWait rather than wait for the vault.
func TestDaemonFailsFastAgainstALiveOwner(t *testing.T) {
	x := newInterruptEnv(t)
	owner, err := store.Open(context.Background(), x.e.storeConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	x.e.OpenStore = func() (model.Store, error) { return openReal(x.e) }
	start := time.Now()
	err = runDaemon(context.Background(), x.e, nil)
	elapsed := time.Since(start)
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != exitVaultBusy || ee.msg != "the vault is busy (another hop process owns it)" {
		t.Fatalf("runDaemon: %v, want a failure saying the vault is busy", err)
	}
	if limit := busyWait + 2*time.Second; elapsed > limit {
		t.Errorf("runDaemon took %v against a live owner, want under %v", elapsed, limit)
	}
	if busy, err := store.Busy(x.e.DataDir); err != nil || !busy {
		t.Errorf("store.Busy with the owner open = %v, %v", busy, err)
	}
}
