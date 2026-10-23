package cli

import (
	"context"
	"errors"
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
// launchctl (run for real).
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
	noSecrets(t, "systemctl", readDump("the service command"))
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
	h, err := holdVault(ctx, x.e)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(x.e.holdMarker()); err != nil || strings.TrimSpace(string(b)) != strconv.Itoa(os.Getpid()) {
		t.Fatalf("marker %q, %v", b, err)
	}
	done := make(chan struct{})
	go x.e.watchInterrupt(ctx, done)
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
	h.release(ctx, false)
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
	h, err := holdVault(ctx, x.e)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	watched := make(chan struct{})
	go func() { x.e.watchInterrupt(ctx, done); close(watched) }()
	cancel(ErrInterrupted)
	<-ctx.Done()
	h.release(ctx, false)
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
	go x.e.watchInterrupt(ctx, make(chan struct{}))
	cancel(ErrInterrupted)
	select {
	case code := <-x.exits:
		if code != ExitInterrupted {
			t.Errorf("exit %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no exit")
	}

	x.e.ctxAware = true
	ctx, cancel = interrupted()
	watched := make(chan struct{})
	go func() { x.e.watchInterrupt(ctx, make(chan struct{})); close(watched) }()
	cancel(ErrInterrupted)
	<-watched
	x.e.ctxAware = false

	dctx, dcancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer dcancel()
	watched = make(chan struct{})
	go func() { x.e.watchInterrupt(dctx, make(chan struct{})); close(watched) }()
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
	if _, err := holdVault(ctx, x.e); err == nil || !strings.Contains(err.Error(), want) {
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
	h, err := holdVault(ctx, x.e)
	if err != nil {
		t.Fatalf("hold with a stale marker: %v", err)
	}
	h.release(ctx, false)
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
