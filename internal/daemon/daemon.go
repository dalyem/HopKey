// Package daemon is the long-running part of hop. It owns a model.Store and
// an in-memory keyring, serves the keyring on an ssh-agent socket, keeps the
// generated ssh config in step with the vault, and answers the CLI on a
// control socket.
//
// Both sockets live in one private directory (Paths.RunDir) and accept only
// connections from the same uid. The agent can list and sign; nothing on
// either socket returns private key bytes.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/safepath"
	"github.com/dalyem/hopkey/internal/sshagent"
	"github.com/dalyem/hopkey/internal/sshconfig"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/tailscale"
)

// ErrAlreadyRunning means another daemon holds the run directory.
var ErrAlreadyRunning = errors.New("daemon: already running")

// Paths says where the daemon keeps its files.
type Paths struct {
	RunDir    string // agent.sock, control.sock and their lock
	ConfigDir string // the generated ssh config, known_hosts and public keys
	StateDir  string // daemon.log
}

// DefaultPaths puts sockets in $XDG_RUNTIME_DIR/hop when that is set and
// absolute, otherwise in ~/.ssh/hop/run. The ssh files go in ~/.ssh/hop and
// the log in $XDG_STATE_HOME/hop or ~/.local/state/hop.
func DefaultPaths(home string, getenv func(string) string) Paths {
	p := Paths{
		RunDir:    filepath.Join(home, ".ssh", "hop", "run"),
		ConfigDir: filepath.Join(home, ".ssh", "hop"),
		StateDir:  filepath.Join(home, ".local", "state", "hop"),
	}
	if x := getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(x) {
		p.RunDir = filepath.Join(x, "hop")
	}
	if x := getenv("XDG_STATE_HOME"); filepath.IsAbs(x) {
		p.StateDir = filepath.Join(x, "hop")
	}
	return p
}

func (p Paths) AgentSocket() string   { return filepath.Join(p.RunDir, "agent.sock") }
func (p Paths) ControlSocket() string { return filepath.Join(p.RunDir, "control.sock") }
func (p Paths) LogFile() string       { return filepath.Join(p.StateDir, "daemon.log") }

// TailscaleSource reads the local tailnet. *tailscale.Client satisfies it.
type TailscaleSource interface {
	Status(ctx context.Context) (*tailscale.Status, error)
}

// Options configures Start.
type Options struct {
	Paths Paths
	// Store is the vault. The daemon closes it when it shuts down, if it
	// is an io.Closer, which for the encrypted store gives up the vault's
	// owner lock. When Start fails, the caller still has to close it.
	Store   model.Store
	Version string

	// Tailscale defaults to the real command line client.
	Tailscale TailscaleSource
	// Sync configures automatic sync, which runs for a server-backed
	// encrypted store (sync.go).
	Sync SyncOptions
	// Logf receives log lines. Nil discards them.
	Logf func(format string, args ...any)

	// Test hooks: writeConfig replaces sshconfig.Write, wipeConfig
	// sshconfig.WipeIf with no condition, and configRetry
	// configRetryInterval.
	writeConfig func(sshconfig.Options, []sshconfig.Host) error
	wipeConfig  func(o sshconfig.Options, done func() error) error
	configRetry time.Duration
}

// Daemon is a running daemon.
type Daemon struct {
	opts  Options
	store model.Store
	ts    TailscaleSource
	logf  func(string, ...any)

	started time.Time
	live    *liveAgent
	agent   *sshagent.Server
	control *controlListener

	// writeConfig writes the ssh config (sshconfig.Write), and wipeConfig
	// empties it and removes its files, and then runs done under the same
	// hold of config.lock (sshconfig.WipeIf).
	writeConfig func(sshconfig.Options, []sshconfig.Host) error
	wipeConfig  func(o sshconfig.Options, done func() error) error

	// mu serializes changes to the vault and reloads, so the keyring and the
	// ssh config always come from one snapshot, newest last.
	mu    sync.Mutex
	state atomic.Pointer[state]
	// outboxGen moves whenever the outbox changes without the verified
	// head moving (a queued write, a hold, a resolution), so the next
	// request rebuilds from the overlay.
	outboxGen atomic.Uint64
	// clearErr says why a revoked device's ssh config could not be
	// emptied; nil when nothing is pending (clearConfigLocked).
	clearErr atomic.Pointer[string]

	sync *syncer // nil for a store that does not sync

	tsMu     sync.Mutex
	tsCached *tailscale.Status
	tsAt     time.Time

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
	done      chan struct{}
}

// Start prepares the run and config directories, takes the sockets, loads
// the vault and begins serving. It returns ErrAlreadyRunning if another
// daemon owns the run directory. A vault that cannot be read is an error:
// there is nothing useful to serve.
func Start(opts Options) (*Daemon, error) {
	if opts.Store == nil {
		return nil, errors.New("daemon: no store")
	}
	if opts.Tailscale == nil {
		opts.Tailscale = &tailscale.Client{}
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	for _, dir := range []string{opts.Paths.RunDir, opts.Paths.ConfigDir} {
		if !filepath.IsAbs(dir) {
			return nil, fmt.Errorf("daemon: directory %q is not absolute", dir)
		}
	}
	runDir, err := safepath.EnsurePrivateDir(opts.Paths.RunDir)
	if err != nil {
		return nil, fmt.Errorf("daemon: run directory: %w", err)
	}
	opts.Paths.RunDir = runDir

	live := newLiveAgent(fenceOf(opts.Store))
	agentSrv, err := sshagent.Listen(opts.Paths.AgentSocket(), live)
	if errors.Is(err, sshagent.ErrInUse) {
		return nil, ErrAlreadyRunning
	}
	if err != nil {
		return nil, err
	}
	agentSrv.Logf = logf
	control, err := listenControl(opts.Paths.ControlSocket())
	if err != nil {
		agentSrv.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	d := &Daemon{
		opts: opts, store: opts.Store, ts: opts.Tailscale, logf: logf,
		started: time.Now(), live: live, agent: agentSrv, control: control,
		ctx: ctx, cancel: cancel, done: make(chan struct{}),
		writeConfig: opts.writeConfig, wipeConfig: opts.wipeConfig,
	}
	if d.writeConfig == nil {
		d.writeConfig = sshconfig.Write
	}
	if d.wipeConfig == nil {
		d.wipeConfig = func(o sshconfig.Options, done func() error) error { return sshconfig.WipeIf(o, nil, done) }
	}
	if err := d.reload(ctx); (errors.Is(err, model.ErrLocked) || errors.Is(err, store.ErrDeviceRevoked)) && d.canUnlock() {
		// A locked vault (its device key unreadable, say) still gets a
		// daemon, so hop unlock can reach it, and a revoked one so hop
		// status can say so.
		if cur := d.state.Load(); cur == nil || !cur.locked {
			d.state.Store(lockedState())
		}
		logf("the vault is locked: %v", err)
	} else if err != nil && !errors.Is(err, errConfigWrite) {
		// A config that could not be written is retried (retryConfig).
		d.shutdown()
		return nil, fmt.Errorf("daemon: loading the vault: %w", err)
	}
	d.watchRevoked()
	d.startSync()
	d.retryConfig()

	d.wg.Add(2)
	go func() {
		defer d.wg.Done()
		if err := agentSrv.Serve(); err != nil {
			logf("agent socket: %v", err)
		}
	}()
	go func() {
		defer d.wg.Done()
		d.serveControl()
	}()
	logf("hop daemon %s serving agent %s and control %s", opts.Version, agentSrv.Path(), control.path)
	return d, nil
}

// Done is closed once the daemon has shut down, whether by Close or by a
// shutdown request.
func (d *Daemon) Done() <-chan struct{} { return d.done }

// AgentSocket is the path of the agent socket.
func (d *Daemon) AgentSocket() string { return d.agent.Path() }

// ControlSocket is the path of the control socket.
func (d *Daemon) ControlSocket() string { return d.control.path }

// Close stops serving and removes the sockets. It is safe to call more than
// once; every call returns after shutdown has finished.
func (d *Daemon) Close() error {
	d.shutdown()
	<-d.done
	return d.closeErr
}

func (d *Daemon) shutdown() {
	d.closeOnce.Do(func() {
		d.cancel()
		err := d.control.Close()
		if aerr := d.agent.Close(); err == nil {
			err = aerr
		}
		d.wg.Wait()
		if c, ok := d.store.(io.Closer); ok {
			if cerr := c.Close(); err == nil {
				err = cerr
			}
		}
		d.closeErr = err
		close(d.done)
	})
}

// controlListener is the control socket's listener and the open connections.
type controlListener struct {
	path string
	ln   *net.UnixListener
	info os.FileInfo

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// listenControl creates the control socket. The caller already holds the run
// directory's lock (through the agent server), so a socket file that is
// still there is a leftover and is replaced.
func listenControl(path string) (*controlListener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("daemon: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(false)
	fail := func(err error) (*controlListener, error) {
		ln.Close()
		os.Remove(path)
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fail(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fail(err)
	}
	return &controlListener{path: path, ln: ln, info: info, conns: map[net.Conn]struct{}{}}, nil
}

func (l *controlListener) track(c net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	l.conns[c] = struct{}{}
	l.wg.Add(1)
	return true
}

func (l *controlListener) untrack(c net.Conn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
	c.Close()
	l.wg.Done()
}

// Close stops accepting, drops open connections, waits for their handlers and
// removes the socket file if it is still the one this listener created.
func (l *controlListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	err := l.ln.Close()
	for c := range l.conns {
		c.Close()
	}
	l.mu.Unlock()
	l.wg.Wait()
	if cur, statErr := os.Lstat(l.path); statErr == nil && os.SameFile(cur, l.info) {
		if rmErr := os.Remove(l.path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) && err == nil {
			err = rmErr
		}
	}
	return err
}
