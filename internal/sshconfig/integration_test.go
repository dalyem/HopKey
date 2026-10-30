package sshconfig_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
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

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/sshagent"
	"github.com/dalyem/hopkey/internal/sshconfig"
)

// These tests run the real OpenSSH client against an in-process SSH server,
// with keys served by a sshagent.Server and the config written by
// sshconfig.Write. They skip when there is no ssh binary on PATH, unless
// HOPKEY_REQUIRE_SSH is set (as it is on Kiln), which turns the skip into a
// failure so the check cannot pass without running.

const (
	user  = "deploy"
	alias = "prod-db"
	// Total keys loaded into the agent. More than the server's default
	// MaxAuthTries (6), with the accepted key last.
	agentKeys = 7
)

func TestOpenSSHUsesAgentKey(t *testing.T) {
	sshBin := requireSSH(t)

	tests := []struct {
		name    string
		rsa     bool   // accepted key is RSA, which needs agent SignWithFlags
		dirName string // config directory name
	}{
		{name: "ed25519 key", dirName: "hop"},
		{name: "rsa key", rsa: true, dirName: "hop"},
		{name: "config directory with spaces", dirName: "hop config dir"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, tt.rsa, tt.dirName)
			stdout, stderr, err := e.ssh(t, sshBin, e.config(), "echo", "ok")
			if err != nil {
				t.Fatalf("ssh failed: %v\nstderr:\n%s", err, stderr)
			}
			if got := strings.TrimSpace(stdout); got != "ok" {
				t.Errorf("stdout = %q, want %q", got, "ok")
			}
		})
	}
}

// With hop's agent down, or up and holding no keys (the vault is locked), the
// login fails as plain "Permission denied". It must not be preceded by
// ssh's `Load key ".../keys/<id>.pub": error in libcrypto`, which is what ssh
// prints when it tries a public key file as a private key.
func TestOpenSSHWithoutTheKeyIsQuiet(t *testing.T) {
	sshBin := requireSSH(t)
	for _, tt := range []string{"agent down", "agent holds no keys"} {
		t.Run(tt, func(t *testing.T) {
			e := newEnv(t, false, "hop")
			cfg := e.config()
			if tt == "agent down" {
				if err := os.Remove(e.opts.AgentSocket); err != nil {
					t.Fatal(err)
				}
			} else {
				// A socket directory of its own: one agent per directory.
				emptyDir, err := os.MkdirTemp("", "hk")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(emptyDir) })
				empty, err := sshagent.Listen(filepath.Join(emptyDir, "agent.sock"), sshagent.NewKeyring().Agent())
				if err != nil {
					t.Fatal(err)
				}
				go empty.Serve()
				t.Cleanup(func() { empty.Close() })
				cfg = e.writeVariant(t, func(cfg, _ string) string {
					return replaceLine(cfg, "IdentityAgent", empty.Path())
				})
			}
			_, stderr, err := e.ssh(t, sshBin, cfg, "echo", "ok")
			if err == nil {
				t.Fatal("ssh succeeded without the key")
			}
			if strings.Contains(stderr, "Load key") || strings.Contains(stderr, "libcrypto") {
				t.Errorf("ssh complains about the key file:\n%s", stderr)
			}
			if !strings.Contains(stderr, "Permission denied") {
				t.Errorf("stderr lacks Permission denied:\n%s", stderr)
			}
		})
	}
}

func TestOpenSSHRejectsWrongHostKeyPin(t *testing.T) {
	sshBin := requireSSH(t)
	e := newEnv(t, false, "hop")
	e.pinWrongHostKey(t)

	_, stderr, err := e.ssh(t, sshBin, e.config(), "echo", "ok")
	if err == nil {
		t.Fatal("ssh succeeded against a server whose host key is not pinned")
	}
	if !strings.Contains(stderr, "Host key verification failed") {
		t.Errorf("stderr does not report host key verification failure:\n%s", stderr)
	}
	if e.server.authAttempts.Load() != 0 {
		t.Errorf("server saw %d auth attempts; ssh must stop before authenticating", e.server.authAttempts.Load())
	}
}

// TestOpenSSHWithoutIdentitiesOnly records what OpenSSH does when
// IdentitiesOnly is dropped and the agent holds more keys than the server's
// MaxAuthTries. The outcome depends on the OpenSSH version and on how it
// orders identities, so it is logged and not asserted.
func TestOpenSSHWithoutIdentitiesOnly(t *testing.T) {
	sshBin := requireSSH(t)
	out, _ := exec.Command(sshBin, "-V").CombinedOutput() // prints to stderr
	t.Logf("ssh -V: %s", bytes.TrimSpace(out))

	tests := []struct {
		name string
		// edit rewrites the generated config.
		edit func(cfg, dir string) string
	}{
		{
			name: "IdentityFile .pub kept",
			edit: func(cfg, _ string) string { return dropLines(cfg, "IdentitiesOnly") },
		},
		{
			// The key is only reachable by walking the agent's list in order.
			name: "IdentityFile points at nothing",
			edit: func(cfg, dir string) string {
				return replaceLine(dropLines(cfg, "IdentitiesOnly"), "IdentityFile", filepath.Join(dir, "no-such-key"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, false, "hop")
			cfg := e.writeVariant(t, tt.edit)
			stdout, stderr, err := e.ssh(t, sshBin, cfg, "-v", "echo", "ok")
			t.Logf("agent keys: %d, server MaxAuthTries: default (6)", agentKeys)
			t.Logf("ssh error: %v; stdout: %q", err, strings.TrimSpace(stdout))
			t.Logf("server auth attempts: %d", e.server.authAttempts.Load())
			t.Logf("relevant ssh -v lines:\n%s", grepLines(stderr,
				"Offering public key", "Server accepts key", "Authenticated to",
				"Too many authentication failures", "Permission denied", "Authentications that can continue"))
			t.Logf("last ssh stderr line: %s", lastLine(stderr))
		})
	}
}

// refused asserts that ssh to the alias stopped at host key verification,
// before the server saw any authentication attempt.
func (e *env) refused(t *testing.T, sshBin, to string) {
	t.Helper()
	before := e.server.authAttempts.Load()
	_, stderr, err := e.sshTo(t, sshBin, e.config(), to, "echo", "ok")
	if err == nil {
		t.Fatalf("ssh %s succeeded, want it refused", to)
	}
	if !strings.Contains(stderr, "Host key verification failed") {
		t.Errorf("ssh %s: stderr does not report host key verification failure:\n%s", to, stderr)
	}
	if got := e.server.authAttempts.Load(); got != before {
		t.Errorf("ssh %s: server saw %d auth attempts; ssh must stop before authenticating", to, got-before)
	}
}

func (e *env) accepted(t *testing.T, sshBin, to string) {
	t.Helper()
	stdout, stderr, err := e.sshTo(t, sshBin, e.config(), to, "echo", "ok")
	if err != nil {
		t.Fatalf("ssh %s failed: %v\nstderr:\n%s", to, err, stderr)
	}
	if got := strings.TrimSpace(stdout); got != "ok" {
		t.Errorf("ssh %s: stdout = %q, want ok", to, got)
	}
}

// sameEndpoint returns h under another alias, same address, port and keys.
func sameEndpoint(h sshconfig.Host, newAlias string, pins ...ssh.PublicKey) sshconfig.Host {
	h.Alias = newAlias
	h.HostKeys = pins
	return h
}

// An alias without pins must be refused even though another alias for the
// same host and port has a valid pin. Pooling pins by address would let the
// pinned alias vouch for the unpinned one.
func TestOpenSSHAliasWithoutPinsIsRefused(t *testing.T) {
	sshBin := requireSSH(t)
	e := newEnv(t, false, "hop")
	e.extra = []sshconfig.Host{sameEndpoint(e.host, "staging")}
	e.write(t)

	e.accepted(t, sshBin, alias)
	e.refused(t, sshBin, "staging")
}

// Two aliases for one endpoint pin different keys. Each accepts only its own,
// whichever key the server presents.
func TestOpenSSHPinsArePerAlias(t *testing.T) {
	sshBin := requireSSH(t)
	e := newEnv(t, false, "hop")
	s1 := e.server.hostSigner
	s2 := newHostSigner(t)
	e.host.Alias = "one"
	e.host.HostKeys = []ssh.PublicKey{s1.PublicKey()}
	e.extra = []sshconfig.Host{sameEndpoint(e.host, "two", s2.PublicKey())}
	e.write(t)

	// The server presents s1: only "one" accepts it.
	e.accepted(t, sshBin, "one")
	e.refused(t, sshBin, "two")

	// The server presents s2: only "two" accepts it.
	e.server.useHostKey(s2)
	e.refused(t, sshBin, "one")
	e.accepted(t, sshBin, "two")
}

// Aliases differ in case only in what the user typed; the pin lookup must not.
func TestOpenSSHMixedCaseAlias(t *testing.T) {
	sshBin := requireSSH(t)
	e := newEnv(t, false, "hop")
	e.host.Alias = "Prod-DB"
	e.write(t)

	e.accepted(t, sshBin, "Prod-DB")
}

// GlobalKnownHostsFile none must mean "no file". If OpenSSH read it as a
// relative path, a file named none in the working directory could vouch for
// an unpinned alias. The control run uses ./none and must succeed, which
// proves the planted file is valid and would have been read.
func TestOpenSSHGlobalKnownHostsFileNoneIsNotAFile(t *testing.T) {
	sshBin := requireSSH(t)
	e := newEnv(t, false, "hop")
	e.extra = []sshconfig.Host{sameEndpoint(e.host, "staging")} // no pins

	e.cwd = t.TempDir()
	planted := fmt.Sprintf("staging %s", ssh.MarshalAuthorizedKey(e.server.hostKey))
	if err := os.WriteFile(filepath.Join(e.cwd, "none"), []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	e.write(t)

	e.refused(t, sshBin, "staging")

	control := e.writeVariant(t, func(cfg, _ string) string {
		return strings.ReplaceAll(cfg, "GlobalKnownHostsFile none", "GlobalKnownHostsFile ./none")
	})
	_, stderr, err := e.sshTo(t, sshBin, control, "staging", "echo", "ok")
	if err != nil {
		t.Fatalf("control: ssh with GlobalKnownHostsFile ./none failed, so the planted file proves nothing: %v\n%s", err, stderr)
	}
}

func requireSSH(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh")
	if err != nil {
		if os.Getenv("HOPKEY_REQUIRE_SSH") != "" {
			t.Fatalf("ssh not found and HOPKEY_REQUIRE_SSH is set: %v", err)
		}
		t.Skip("no ssh binary on PATH")
	}
	return p
}

// env is a running SSH server, a running agent loaded with agentKeys keys,
// and a written config for one host.
type env struct {
	dir    string // config directory
	server *testServer
	opts   sshconfig.Options
	host   sshconfig.Host
	extra  []sshconfig.Host // more aliases written next to host
	cwd    string           // working directory for ssh; empty means the test's
	// sshEnv replaces variables of the environment given to ssh (HOME, and
	// the passwd shim's NSS_WRAPPER_PASSWD): "NAME=value" entries.
	sshEnv []string
}

func newEnv(t *testing.T, rsaKey bool, dirName string) *env {
	t.Helper()
	// Unix socket paths are short-limited, so avoid t.TempDir here.
	base, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	dir := filepath.Join(base, dirName)

	kr := sshagent.NewKeyring()
	var accepted ssh.PublicKey
	for i := range agentKeys {
		var priv any
		if i == agentKeys-1 && rsaKey {
			priv, err = rsa.GenerateKey(rand.Reader, 2048)
		} else {
			_, priv, err = ed25519.GenerateKey(rand.Reader)
		}
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := kr.Add(priv, "key"+strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
		accepted = signer.PublicKey() // the last one wins
	}

	agentSrv, err := sshagent.Listen(filepath.Join(dir, "agent.sock"), kr.Agent())
	if err != nil {
		t.Fatal(err)
	}
	go agentSrv.Serve()
	t.Cleanup(func() { agentSrv.Close() })

	srv := startServer(t, accepted)
	e := &env{
		dir:    dir,
		server: srv,
		opts:   sshconfig.Options{Dir: dir, AgentSocket: agentSrv.Path()},
		host: sshconfig.Host{
			Alias:     alias,
			HostName:  "127.0.0.1",
			Port:      srv.port,
			User:      user,
			PublicKey: accepted,
			HostKeys:  []ssh.PublicKey{srv.hostKey},
		},
	}
	e.write(t)
	return e
}

func (e *env) write(t *testing.T) {
	t.Helper()
	if err := sshconfig.Write(e.opts, append([]sshconfig.Host{e.host}, e.extra...)); err != nil {
		t.Fatal(err)
	}
}

func (e *env) config() string { return filepath.Join(e.dir, "config") }

// pinWrongHostKey regenerates the files with a pin that is not the server's key.
func (e *env) pinWrongHostKey(t *testing.T) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	e.host.HostKeys = []ssh.PublicKey{other}
	e.write(t)
}

// writeVariant saves an edited copy of the generated config next to it.
func (e *env) writeVariant(t *testing.T, edit func(cfg, dir string) string) string {
	t.Helper()
	b, err := os.ReadFile(e.config())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.dir, "config.variant")
	if err := os.WriteFile(path, []byte(edit(string(b), e.dir)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// ssh runs `ssh -F cfg -o BatchMode=yes [flags...] alias command...`. Leading
// args starting with "-" are flags for ssh; the rest is the remote command.
func (e *env) ssh(t *testing.T, sshBin, cfg string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	return e.sshTo(t, sshBin, cfg, alias, args...)
}

// sshTo is ssh for an arbitrary alias.
func (e *env) sshTo(t *testing.T, sshBin, cfg, to string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	argv := []string{"-F", cfg, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"}
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		argv, args = append(argv, args[0]), args[1:]
	}
	argv = append(argv, to)
	argv = append(argv, args...)

	cmd := exec.CommandContext(ctx, sshBin, argv...)
	cmd.Dir = e.cwd
	// The config names its own agent; make sure a developer's agent cannot
	// leak in through the environment.
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if name != "SSH_AUTH_SOCK" && !slices.ContainsFunc(e.sshEnv, func(o string) bool { return strings.HasPrefix(o, name+"=") }) {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, e.sshEnv...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("ssh timed out\nstderr:\n%s", se.String())
	}
	return so.String(), se.String(), err
}

// testServer is an SSH server on 127.0.0.1 that accepts one public key and
// answers exec requests: "true" and "echo ok" succeed, anything else exits 127.
type testServer struct {
	port         int
	hostKey      ssh.PublicKey // the key presented to new connections
	hostSigner   ssh.Signer
	authAttempts atomic.Int32 // public key callbacks, successful or not

	mu       sync.Mutex
	accepted ssh.PublicKey
	offered  [][]byte // every public key a client offered, in order
	cfg      *ssh.ServerConfig
}

// accept makes the server accept key (and only key) from now on.
func (ts *testServer) accept(key ssh.PublicKey) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.accepted = key
}

// offeredKeys returns the keys clients have offered so far.
func (ts *testServer) offeredKeys() [][]byte {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return slices.Clone(ts.offered)
}

func newHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// useHostKey makes the server present signer's key to connections made from
// now on.
func (ts *testServer) useHostKey(signer ssh.Signer) {
	cfg := &ssh.ServerConfig{ // MaxAuthTries left at its default, 6
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			ts.authAttempts.Add(1)
			ts.mu.Lock()
			ts.offered = append(ts.offered, k.Marshal())
			accepted := ts.accepted
			ts.mu.Unlock()
			if c.User() == user && bytes.Equal(k.Marshal(), accepted.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("key not accepted")
		},
	}
	cfg.AddHostKey(signer)

	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.cfg = cfg
	ts.hostSigner = signer
	ts.hostKey = signer.PublicKey()
}

func (ts *testServer) config() *ssh.ServerConfig {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.cfg
}

func startServer(t *testing.T, accepted ssh.PublicKey) *testServer {
	t.Helper()
	ts := &testServer{accepted: accepted}
	ts.useHostKey(newHostSigner(t))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ts.port = ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go ts.serve(c, ts.config())
		}
	}()
	return ts
}

func (ts *testServer) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return // failed handshake or auth: expected in the negative tests
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)

	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for req := range creqs {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				var p struct{ Command string }
				if err := ssh.Unmarshal(req.Payload, &p); err != nil {
					req.Reply(false, nil)
					continue
				}
				req.Reply(true, nil)
				status := uint32(0)
				switch p.Command {
				case "true":
				case "echo ok":
					ch.Write([]byte("ok\n"))
				default:
					status = 127
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
				return
			}
		}()
	}
}

// dropLines removes every line of cfg that contains substr.
func dropLines(cfg, substr string) string {
	var out []string
	for _, l := range strings.Split(cfg, "\n") {
		if !strings.Contains(l, substr) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// replaceLine rewrites each line whose first word is key to "  key value".
func replaceLine(cfg, key, value string) string {
	lines := strings.Split(cfg, "\n")
	for i, l := range lines {
		if f := strings.Fields(l); len(f) > 0 && f[0] == key {
			lines[i] = "  " + key + " " + value
		}
	}
	return strings.Join(lines, "\n")
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

func grepLines(s string, subs ...string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		for _, sub := range subs {
			if strings.Contains(l, sub) {
				out = append(out, "  "+l)
				break
			}
		}
	}
	return strings.Join(out, "\n")
}

// useHome makes ssh take dir for its home directory. ssh does not read $HOME:
// it asks the passwd database, so this needs the passwd shim that
// scripts/with-passwd.sh sets up under a uid with no passwd entry (Kiln). On a
// machine with a real passwd entry there is no way to move the home without
// touching the real one, which a test must not do: the test skips there
// unless HOPKEY_REQUIRE_SSH is set.
func (e *env) useHome(t *testing.T, dir string) {
	t.Helper()
	orig := os.Getenv("NSS_WRAPPER_PASSWD")
	if orig == "" {
		if os.Getenv("HOPKEY_REQUIRE_SSH") != "" {
			t.Fatal("no passwd shim (NSS_WRAPPER_PASSWD) to move ssh's home directory into the test directory")
		}
		t.Skip("cannot give ssh a temporary home without the passwd shim")
	}
	b, err := os.ReadFile(orig)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 6 {
			f[5] = dir
		}
		out = append(out, strings.Join(f, ":"))
	}
	passwd := filepath.Join(filepath.Dir(dir), "passwd")
	if err := os.WriteFile(passwd, []byte(strings.Join(out, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.sshEnv = []string{"HOME=" + dir, "NSS_WRAPPER_PASSWD=" + passwd}
}

// A Tailscale SSH host must never be offered a key, even when the server asks
// for public key authentication and would accept a default key sitting in the
// user's ~/.ssh. The control run drops the two lines that make the block
// keyless and shows the same server and home would have accepted that key.
func TestOpenSSHKeylessHostIsNeverOfferedAKey(t *testing.T) {
	sshBin := requireSSH(t)
	e := newEnv(t, false, "hop")

	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	e.useHome(t, home)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defaultKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	e.server.accept(defaultKey)

	e.host.PublicKey, e.host.Keyless = nil, true
	e.write(t)

	// Control: without the keyless lines, ssh offers the default key and gets in.
	old := e.writeVariant(t, func(cfg, _ string) string {
		return dropLines(dropLines(cfg, "PubkeyAuthentication"), "IdentityFile")
	})
	stdout, stderr, err := e.ssh(t, sshBin, old, "echo", "ok")
	if err != nil || strings.TrimSpace(stdout) != "ok" {
		t.Fatalf("control: the planted default key was not used, so the test proves nothing: %v\n%s", err, stderr)
	}
	if got := e.server.offeredKeys(); len(got) != 1 || !bytes.Equal(got[0], defaultKey.Marshal()) {
		t.Fatalf("control: server saw %d offered keys, want the default key", len(got))
	}

	before := len(e.server.offeredKeys())
	attempts := e.server.authAttempts.Load()
	_, stderr, err = e.ssh(t, sshBin, e.config(), "-v", "echo", "ok")
	if err == nil {
		t.Fatal("ssh got in with a key it should not have offered")
	}
	if got := e.server.offeredKeys(); len(got) != before {
		t.Errorf("the server was offered %d keys by the keyless block", len(got)-before)
	}
	if got := e.server.authAttempts.Load(); got != attempts {
		t.Errorf("the server saw %d authentication attempts", got-attempts)
	}
	if strings.Contains(stderr, "Offering public key") {
		t.Errorf("ssh offered a key:\n%s", grepLines(stderr, "Offering public key", "identity file"))
	}
}
