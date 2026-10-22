package sshagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	return srv, pubs
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

func TestStaleAndLiveSockets(t *testing.T) {
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

	startServer(t, path, 1)

	if _, err := Listen(path, NewKeyring().Agent()); !errors.Is(err, ErrInUse) {
		t.Errorf("second Listen error = %v, want ErrInUse", err)
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
