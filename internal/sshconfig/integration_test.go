package sshconfig_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
		if !strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
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
	cfg      *ssh.ServerConfig
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
			if c.User() == user && bytes.Equal(k.Marshal(), ts.accepted.Marshal()) {
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
