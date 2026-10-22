package sshagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// shortTempDir avoids t.TempDir, whose paths can approach the sockaddr_un limit.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// startServer serves a keyring holding n keys and returns the keyring's
// public keys in load order. Each opt runs before the server starts serving.
func startServer(t *testing.T, path string, n int, opts ...func(*Server)) (*Server, []ssh.PublicKey) {
	t.Helper()
	kr := NewKeyring()
	var pubs []ssh.PublicKey
	for i := range n {
		priv := newKey(t)
		if err := kr.Add(priv, "key"+string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		pubs = append(pubs, pub)
	}
	return startServerWith(t, path, kr, opts...), pubs
}

// startServerWith serves kr and registers cleanup that closes the server.
func startServerWith(t *testing.T, path string, kr *Keyring, opts ...func(*Server)) *Server {
	t.Helper()
	srv, err := Listen(path, kr.Agent())
	if err != nil {
		t.Fatal(err)
	}
	for _, opt := range opts {
		opt(srv)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		srv.Close()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return srv
}

func dial(t *testing.T, path string) agent.ExtendedAgent {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return agent.NewClient(c).(agent.ExtendedAgent)
}

func TestListAndSign(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "d", "agent.sock")
	_, pubs := startServer(t, path, 3)
	c := dial(t, path)

	keys, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != len(pubs) {
		t.Fatalf("List returned %d keys, want %d", len(keys), len(pubs))
	}

	data := []byte("challenge")
	sig, err := c.Sign(pubs[2], data)
	if err != nil {
		t.Fatal(err)
	}
	if err := pubs[2].Verify(data, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

func TestPermissions(t *testing.T) {
	tests := []struct {
		name string
		prep func(t *testing.T, dir string)
	}{
		{"new directory", func(*testing.T, string) {}},
		{"existing loose directory", func(t *testing.T, dir string) {
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o755); err != nil { // beat the umask
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(shortTempDir(t), "d")
			tt.prep(t, dir)
			srv, _ := startServer(t, filepath.Join(dir, "agent.sock"), 1)

			di, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got := di.Mode().Perm(); got != 0o700 {
				t.Errorf("dir mode = %o, want 700", got)
			}
			si, err := os.Stat(srv.Path())
			if err != nil {
				t.Fatal(err)
			}
			if got := si.Mode().Perm(); got != 0o600 {
				t.Errorf("socket mode = %o, want 600", got)
			}
			if si.Mode()&os.ModeSocket == 0 {
				t.Errorf("%s is not a socket", srv.Path())
			}
		})
	}
}

func TestReadOnly(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "d", "agent.sock")
	_, pubs := startServer(t, path, 2)
	c := dial(t, path)

	tests := []struct {
		name string
		call func() error
	}{
		{"add", func() error { return c.Add(agent.AddedKey{PrivateKey: newKey(t)}) }},
		{"remove", func() error { return c.Remove(pubs[0]) }},
		{"remove all", func() error { return c.RemoveAll() }},
		{"lock", func() error { return c.Lock([]byte("pw")) }},
		{"unlock", func() error { return c.Unlock([]byte("pw")) }},
		{"add with confirm-before-use", func() error {
			return c.Add(agent.AddedKey{PrivateKey: newKey(t), ConfirmBeforeUse: true})
		}},
		{"add with lifetime", func() error {
			return c.Add(agent.AddedKey{PrivateKey: newKey(t), LifetimeSecs: 60})
		}},
		{"add with extension constraint", func() error {
			return c.Add(agent.AddedKey{PrivateKey: newKey(t), ConfirmBeforeUse: true, ConstraintExtensions: []agent.ConstraintExtension{
				{ExtensionName: "restrict-destination-v00@openssh.com", ExtensionDetails: []byte("x")},
			}})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); err == nil {
				t.Error("request succeeded, want failure")
			}
		})
	}

	// None of that changed the keyring, and it still signs.
	keys, err := c.List()
	if err != nil || len(keys) != 2 {
		t.Fatalf("List = %d keys, %v; want 2 keys", len(keys), err)
	}
	if _, err := c.Sign(pubs[0], []byte("x")); err != nil {
		t.Errorf("Sign after rejected requests: %v", err)
	}
}

func TestRejectsForeignPeer(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "d", "agent.sock")
	startServer(t, path, 1, func(s *Server) {
		s.authorize = func(*net.UnixConn) error { return errors.New("foreign uid") }
	})

	c := dial(t, path)
	if keys, err := c.List(); err == nil {
		t.Fatalf("List succeeded with %d keys for a rejected peer", len(keys))
	}
}

func TestStaleSocketIsReplaced(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "d", "agent.sock")

	// A socket file with no listener, as left behind by a crashed daemon.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close()
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("setup: no stale socket at %s: %v", path, err)
	}

	_, pubs := startServer(t, path, 1)
	if _, err := dial(t, path).Sign(pubs[0], []byte("x")); err != nil {
		t.Errorf("Sign on the replacement server: %v", err)
	}
}

func TestSecondListenIsInUseAndFirstKeepsWorking(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "d", "agent.sock")
	_, pubs := startServer(t, path, 1)
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}

	// Concurrent attempts all lose, and none of them touches the socket.
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var s *Server
			s, errs[i] = Listen(path, NewKeyring().Agent())
			if s != nil {
				s.Close()
			}
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if !errors.Is(err, ErrInUse) {
			t.Errorf("Listen #%d error = %v, want ErrInUse", i, err)
		}
	}

	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("socket was replaced or removed by the failed Listen: %v", err)
	}
	c := dial(t, path)
	if keys, err := c.List(); err != nil || len(keys) != 1 {
		t.Fatalf("first server List = %d keys, %v; want 1 key", len(keys), err)
	}
	if _, err := c.Sign(pubs[0], []byte("x")); err != nil {
		t.Errorf("first server Sign: %v", err)
	}
}

func TestListenAfterCloseSucceeds(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "d", "agent.sock")
	srv, _ := startServer(t, path, 1)
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	// The lock file stays; the lock itself is gone.
	startServer(t, path, 1)
}

func TestCloseLeavesReplacedSocketAlone(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "d", "agent.sock")
	srv, _ := startServer(t, path, 1)

	// Someone removes our socket and puts a different file in its place.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "not ours" {
		t.Errorf("Close removed or changed a file it did not create: %q, %v", b, err)
	}
}

func TestListenRefusesUnsafeAncestor(t *testing.T) {
	base := shortTempDir(t)
	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o770); err != nil { // group-writable
		t.Fatal(err)
	}
	path := filepath.Join(loose, "d", "agent.sock")
	if _, err := Listen(path, NewKeyring().Agent()); err == nil {
		t.Fatal("Listen accepted a socket directory below a group-writable directory")
	}
	if _, err := os.Lstat(path); err == nil {
		t.Error("a socket was created anyway")
	}
}

func TestListenResolvesDirectorySymlinks(t *testing.T) {
	base := shortTempDir(t)
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	srv, _ := startServer(t, filepath.Join(base, "link", "d", "agent.sock"), 1)
	if want := filepath.Join(real, "d", "agent.sock"); srv.Path() != want {
		t.Errorf("Path = %q, want %q", srv.Path(), want)
	}
}

func TestListenRefusesSymlinkedSocketDirectory(t *testing.T) {
	base := shortTempDir(t)
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	// link is the socket's own directory, so it may not be a symlink.
	if _, err := Listen(filepath.Join(link, "agent.sock"), NewKeyring().Agent()); err == nil {
		t.Fatal("Listen accepted a symlink as the socket directory")
	}
	if _, err := os.Lstat(filepath.Join(real, "agent.sock")); err == nil {
		t.Error("a socket was created through the symlink")
	}
}

func TestListenRefusesNonSocket(t *testing.T) {
	dir := shortTempDir(t)
	path := filepath.Join(dir, "agent.sock")
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, NewKeyring().Agent()); err == nil {
		t.Fatal("Listen replaced a regular file")
	}
	if b, _ := os.ReadFile(path); string(b) != "precious" {
		t.Error("regular file was modified")
	}
}

func TestListenPathChecks(t *testing.T) {
	long := filepath.Join(shortTempDir(t), strings.Repeat("a", 120))
	for name, path := range map[string]string{
		"relative": "agent.sock",
		"too long": long,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Listen(path, NewKeyring().Agent()); err == nil {
				t.Error("Listen succeeded")
			}
		})
	}
}

func TestCloseDropsConnectionsAndRemovesSocket(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "d", "agent.sock")
	srv, _ := startServer(t, path, 1)
	c := dial(t, path)
	if _, err := c.List(); err != nil {
		t.Fatal(err)
	}

	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket still present after Close: %v", err)
	}
	if _, err := c.List(); err == nil {
		t.Error("open connection survived Close")
	}
	if err := srv.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestExtensionRefused(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "d", "agent.sock")
	startServer(t, path, 1)
	c := dial(t, path)

	for _, name := range []string{"session-bind@openssh.com", "query", "anything@example.com"} {
		if _, err := c.Extension(name, []byte("payload")); !errors.Is(err, agent.ErrExtensionUnsupported) {
			t.Errorf("Extension(%q) error = %v, want ErrExtensionUnsupported", name, err)
		}
	}
	if keys, err := c.List(); err != nil || len(keys) != 1 {
		t.Errorf("List after extension requests = %d keys, %v; want 1 key", len(keys), err)
	}

	// And directly, without the wire in between.
	if _, err := NewKeyring().Agent().Extension("x", nil); !errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Errorf("view Extension error = %v, want ErrExtensionUnsupported", err)
	}
}

func TestConstrainedAddLeavesKeyringUnchanged(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "d", "agent.sock")
	startServer(t, path, 1)
	c := dial(t, path)

	err := c.Add(agent.AddedKey{PrivateKey: newKey(t), Comment: "sneaky", ConfirmBeforeUse: true})
	if err == nil {
		t.Fatal("constrained add succeeded")
	}
	keys, err := c.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("List = %d keys, %v; want the original single key", len(keys), err)
	}
}

// TestUnlockRefusedWhileLocked locks the underlying keyring the way a buggy
// daemon (or a client, were Lock not refused) could, then shows that a
// client cannot unlock it. Without the read-only view the Unlock below would
// succeed and List would return the key again.
func TestUnlockRefusedWhileLocked(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "d", "agent.sock")
	kr := NewKeyring()
	priv := newKey(t)
	if err := kr.Add(priv, "k"); err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	startServerWith(t, path, kr)
	c := dial(t, path)

	if err := kr.kr.Lock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	if keys, err := c.List(); err != nil || len(keys) != 0 {
		t.Fatalf("locked keyring: List = %d keys, %v; want 0 keys", len(keys), err)
	}

	if err := c.Unlock([]byte("pw")); err == nil {
		t.Fatal("Unlock through the socket succeeded")
	}
	if keys, err := c.List(); err != nil || len(keys) != 0 {
		t.Errorf("keyring was unlocked: List = %d keys, %v", len(keys), err)
	}
	if _, err := c.Sign(pub, []byte("x")); err == nil {
		t.Error("Sign succeeded on a keyring that is still locked")
	}

	// Control: unlocking the real keyring does bring the key back, so the
	// assertions above can fail.
	if err := kr.kr.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	if keys, err := c.List(); err != nil || len(keys) != 1 {
		t.Errorf("after unlocking directly: List = %d keys, %v; want 1 key", len(keys), err)
	}
}

// blockingAgent stalls List until release is closed, holding a handler open.
type blockingAgent struct {
	agent.ExtendedAgent
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingAgent) List() ([]*agent.Key, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.ExtendedAgent.List()
}

func TestEveryCloseWaitsForHandlers(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "d", "agent.sock")
	ba := &blockingAgent{
		ExtendedAgent: NewKeyring().Agent(),
		entered:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	srv, _ := startServer(t, path, 0, func(s *Server) { s.agent = ba })

	c := dial(t, path)
	go c.List() // parks a handler inside blockingAgent.List
	select {
	case <-ba.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never started")
	}

	closed := make(chan int, 2)
	for i := range 2 {
		go func() {
			srv.Close()
			closed <- i
		}()
	}
	select {
	case i := <-closed:
		t.Fatalf("Close call #%d returned while a handler was still running", i)
	case <-time.After(200 * time.Millisecond):
	}

	close(ba.release)
	for range 2 {
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatal("Close did not return after the handler finished")
		}
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket still present after every Close returned: %v", err)
	}
}
