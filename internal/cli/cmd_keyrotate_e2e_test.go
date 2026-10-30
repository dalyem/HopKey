package cli_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/model/modeltest"
)

// The hop key rotate tests run the system ssh client against akServer, an
// in-process SSH server that decides logins as sshd does from the
// ~/.ssh/authorized_keys of a home of its own (from= included) and runs
// every command with the real sh in that home. The check image has no
// sshd, so this is as close to one as the tests get.

type akServer struct {
	ln      net.Listener
	port    int
	home    string
	hostKey ssh.PublicKey
	cfg     *ssh.ServerConfig

	// down makes the server unreachable: every new connection is closed
	// before the handshake.
	down atomic.Bool

	mu sync.Mutex
	// refuse, if set, turns away a key whose authorized_keys line has it
	// in the comment: a server that does not read what hop wrote.
	refuse string
	// onExec, if set, sees each command before it runs. It returns true to
	// have the connection dropped once the command has run, before its exit
	// status is sent: the client cannot tell whether it ran.
	onExec func(command string) (drop bool)
	// onAuth, if set, sees each key a client offers before the server
	// decides on it.
	onAuth func(c ssh.ConnMetadata, k ssh.PublicKey)
	// path, if set, is the PATH commands run with.
	path string
}

func startAKServer(t *testing.T, home string) *akServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &akServer{ln: ln, port: ln.Addr().(*net.TCPAddr).Port, home: home}
	signer := newSigner(t)
	s.hostKey = signer.PublicKey()
	s.cfg = &ssh.ServerConfig{PublicKeyCallback: s.authorize}
	s.cfg.AddHostKey(signer)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *akServer) addr() string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(s.port)) }

func (s *akServer) setRefuse(comment string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuse = comment
}

func (s *akServer) setOnExec(f func(command string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onExec = f
}

func (s *akServer) setOnAuth(f func(c ssh.ConnMetadata, k ssh.PublicKey)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onAuth = f
}

func (s *akServer) setPath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
}

// isAKWrite reports whether a command hop runs is one of its
// authorized_keys edits: the script that writes a temp file in a session
// directory and renames it.
func isAKWrite(command string) bool { return strings.Contains(command, ".hop-s.") }

func (s *akServer) authorize(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
	s.mu.Lock()
	hook := s.onAuth
	s.mu.Unlock()
	if hook != nil {
		hook(c, k)
	}
	data, err := os.ReadFile(filepath.Join(s.home, ".ssh", "authorized_keys"))
	if err != nil {
		return nil, err
	}
	// sshd's default AuthorizedKeysFile also reads authorized_keys2, which
	// hop does not edit.
	if more, err := os.ReadFile(filepath.Join(s.home, ".ssh", "authorized_keys2")); err == nil {
		data = append(append(data, '\n'), more...)
	}
	ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	s.mu.Lock()
	refuse := s.refuse
	s.mu.Unlock()
	for _, line := range strings.Split(string(data), "\n") {
		pub, comment, opts, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil || !bytes.Equal(pub.Marshal(), k.Marshal()) {
			continue
		}
		if refuse != "" && strings.Contains(comment, refuse) {
			continue
		}
		allowed := true
		for _, o := range opts {
			if v, ok := strings.CutPrefix(o, "from="); ok && !fromAllows(strings.Trim(v, `"`), ip) {
				allowed = false
			}
			if strings.EqualFold(o, "cert-authority") {
				allowed = false
			}
		}
		if allowed {
			return nil, nil
		}
	}
	return nil, errors.New("key not in authorized_keys")
}

// fromAllows is sshd's from= pattern list: globs, '!' negates.
func fromAllows(patterns, ip string) bool {
	ok := false
	for _, p := range strings.Split(patterns, ",") {
		neg := strings.HasPrefix(p, "!")
		if m, _ := path.Match(strings.TrimPrefix(p, "!"), ip); m {
			if neg {
				return false
			}
			ok = true
		}
	}
	return ok
}

func (s *akServer) serve(c net.Conn) {
	defer c.Close()
	if s.down.Load() {
		return
	}
	conn, chans, reqs, err := ssh.NewServerConn(c, s.cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			ch, creqs, err := nc.Accept()
			if err != nil {
				return
			}
			go s.session(conn, ch, creqs)
		case "direct-tcpip":
			go forwardTCP(nc)
		default:
			nc.Reject(ssh.UnknownChannelType, "session only")
		}
	}
}

func (s *akServer) session(conn ssh.Conn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
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
		s.mu.Lock()
		hook, path := s.onExec, s.path
		s.mu.Unlock()
		if path == "" {
			path = os.Getenv("PATH")
		}
		drop := hook != nil && hook(p.Command)
		cmd := exec.Command("sh", "-c", p.Command)
		cmd.Dir = s.home
		cmd.Env = []string{"HOME=" + s.home, "PATH=" + path}
		// id -un needs the nss_wrapper of scripts/with-passwd.sh, if any.
		for _, kv := range os.Environ() {
			if strings.HasPrefix(kv, "LD_PRELOAD=") || strings.HasPrefix(kv, "NSS_WRAPPER_") {
				cmd.Env = append(cmd.Env, kv)
			}
		}
		cmd.Stdout, cmd.Stderr = ch, ch.Stderr()
		cmd.WaitDelay = 2 * time.Second
		// As sshd does, the session ends when the command exits, whether
		// or not the client has closed its stdin: the copy into the
		// command is not waited for.
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return
		}
		go func() { io.Copy(stdin, ch); stdin.Close() }()
		status := uint32(0)
		if err := cmd.Run(); err != nil {
			status = 1
			var ee *exec.ExitError
			if errors.As(err, &ee) && ee.ExitCode() >= 0 {
				status = uint32(ee.ExitCode())
			}
		}
		if drop {
			conn.Close()
			return
		}
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
		return
	}
}

// forwardTCP answers ssh -W (ProxyJump) through this server.
func forwardTCP(nc ssh.NewChannel) {
	var p struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
		nc.Reject(ssh.ConnectionFailed, "bad request")
		return
	}
	dst, err := net.Dial("tcp", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		dst.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() { io.Copy(dst, ch); dst.(*net.TCPConn).CloseWrite() }()
	io.Copy(ch, dst)
	ch.CloseWrite()
	ch.Close()
	dst.Close()
}

type rotWorld struct {
	*e2e
	srv    []*akServer
	oldKey ssh.Signer
	hosts  map[string]model.ID
	// original authorized_keys of each server, and its other key lines
	orig []string
}

type rotWorldOpts struct {
	jump     bool // web-2 is reached through web-1
	unpinned bool // also web-3, with no pinned host key
}

func authorizedKeysLine(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

const rotOptions = `from="127.0.0.1,10.1.2.3",no-agent-forwarding`

func newRotWorld(t *testing.T, o rotWorldOpts) *rotWorld {
	t.Helper()
	requireSSH(t)
	base, err := os.MkdirTemp("", "hkr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	// Everything hop and ssh write, temp files included, lands under base,
	// where the tests look for private keys.
	tmp := filepath.Join(base, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	home := filepath.Join(base, "home")
	paths := daemon.Paths{
		RunDir:    filepath.Join(base, "run"),
		ConfigDir: filepath.Join(home, ".ssh", "hop"),
		StateDir:  filepath.Join(base, "state"),
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	st := modeltest.New()
	ctx := context.Background()
	key, err := st.PutKey(ctx, model.Key{
		Name: "deploy-key", KeyType: "ed25519",
		PrivateKey: string(pem.EncodeToMemory(block)), PublicKey: authorizedKeysLine(oldKey.PublicKey()),
	})
	if err != nil {
		t.Fatal(err)
	}

	w := &rotWorld{oldKey: oldKey, hosts: map[string]model.ID{}}
	for i := range 2 {
		rhome := filepath.Join(base, fmt.Sprintf("remote%d", i+1))
		if err := os.MkdirAll(filepath.Join(rhome, ".ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		content := "# hop test\n" +
			authorizedKeysLine(newSigner(t).PublicKey()) + " alice@laptop\n" +
			rotOptions + " " + authorizedKeysLine(oldKey.PublicKey()) + " deploy@old\n" +
			`command="/bin/false",restrict ` + authorizedKeysLine(newSigner(t).PublicKey()) + " backup\n"
		f := filepath.Join(rhome, ".ssh", "authorized_keys")
		if err := os.WriteFile(f, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
		os.Chmod(f, 0o640)
		w.srv = append(w.srv, startAKServer(t, rhome))
		w.orig = append(w.orig, content)
	}

	put := func(h model.Host) model.Host {
		t.Helper()
		saved, err := st.PutHost(ctx, h)
		if err != nil {
			t.Fatal(err)
		}
		w.hosts[h.Name] = saved.ItemID
		return saved
	}
	host := func(name string, s *akServer, pinned bool) model.Host {
		h := model.Host{
			Name: name, Addresses: []string{"127.0.0.1"}, Port: uint32(s.port), User: "deploy",
			KeyID: key.ItemID, Route: "auto", AgentAccess: "allow",
		}
		if pinned {
			h.HostKeys = []string{authorizedKeysLine(s.hostKey)}
		}
		return h
	}
	web1 := put(host("web-1", w.srv[0], true))
	web2 := host("web-2", w.srv[1], true)
	if o.jump {
		web2.JumpHostID = web1.ItemID
	}
	web2.AgentAccess = "deny" // the user may rotate it; only agents are kept away
	put(web2)
	if o.unpinned {
		put(host("web-3", w.srv[1], false))
	}

	d, err := daemon.Start(daemon.Options{Paths: paths, Store: st, Version: "test", Tailscale: noTailscale{}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	w.e2e = &e2e{base: base, home: home, paths: paths, store: st, daemon: d, keyID: key.ItemID}
	return w
}

func (w *rotWorld) authorizedKeys(t *testing.T, i int) (string, os.FileMode) {
	t.Helper()
	f := filepath.Join(w.srv[i].home, ".ssh", "authorized_keys")
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), fi.Mode().Perm()
}

func (w *rotWorld) snapshot(t *testing.T) model.Snapshot {
	t.Helper()
	snap, err := w.store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func (w *rotWorld) hostKeyID(t *testing.T, name string) model.ID {
	t.Helper()
	for _, h := range w.snapshot(t).Hosts {
		if h.Name == name {
			return h.KeyID
		}
	}
	t.Fatalf("no host %s", name)
	return model.ID{}
}

func (w *rotWorld) keyNamed(t *testing.T, name string) *model.Key {
	t.Helper()
	for _, k := range w.snapshot(t).Keys {
		if k.Name == name {
			return &k
		}
	}
	return nil
}

// login tries the server with exactly signer, as a plain client.
func login(s *akServer, signer ssh.Signer) error {
	c, err := ssh.Dial("tcp", s.addr(), &ssh.ClientConfig{
		User: "deploy", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(s.hostKey), Timeout: 5 * time.Second,
	})
	if err != nil {
		return err
	}
	return c.Close()
}

func decodeRotate(t *testing.T, stdout string) cli.RotateResult {
	t.Helper()
	var res cli.RotateResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	return res
}

func hostStatus(res cli.RotateResult) map[string]cli.RotateHost {
	out := map[string]cli.RotateHost{}
	for _, k := range res.Keys {
		for _, h := range k.Hosts {
			out[h.Host] = h
		}
	}
	return out
}

// scanForPrivateKeys reports every regular file under root that holds a
// private key, from now until stop is called.
func scanForPrivateKeys(t *testing.T, root string) (stop func() []string) {
	found := map[string]bool{}
	done := make(chan struct{})
	finished := make(chan struct{})
	scan := func() {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			b, err := os.ReadFile(p)
			if err == nil && bytes.Contains(b, []byte("PRIVATE KEY")) {
				found[p] = true
			}
			return nil
		})
	}
	go func() {
		defer close(finished)
		for {
			scan()
			select {
			case <-done:
				scan()
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	return func() []string {
		close(done)
		<-finished
		var out []string
		for p := range found {
			out = append(out, p)
		}
		return out
	}
}

func TestKeyRotateTwoHosts(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	stop := scanForPrivateKeys(t, w.base)
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--yes", "--json")
	leaked := stop()
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	res := decodeRotate(t, stdout)
	if !res.OK || len(res.Keys) != 1 {
		t.Fatalf("result %+v", res)
	}
	rk := res.Keys[0]
	for _, name := range []string{"web-1", "web-2"} {
		if h := hostStatus(res)[name]; h.Status != "rotated" || h.Reason != "" {
			t.Errorf("%s: %+v", name, h)
		}
	}
	if rk.OldKey != "deleted" || rk.NewKey != "deploy-key-rotated-"+time.Now().UTC().Format("2006-01-02") || rk.NewKeyID == "" {
		t.Errorf("key report %+v", rk)
	}

	// The vault: the new key, both hosts on it, the old key gone.
	newKey := w.keyNamed(t, rk.NewKey)
	if newKey == nil || w.keyNamed(t, "deploy-key") != nil {
		t.Fatalf("vault keys: %+v", w.snapshot(t).Keys)
	}
	for _, name := range []string{"web-1", "web-2"} {
		if w.hostKeyID(t, name) != newKey.ItemID {
			t.Errorf("%s still on key %v", name, w.hostKeyID(t, name))
		}
	}
	newSignerKey, err := ssh.ParsePrivateKey([]byte(newKey.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	stamp := "hop-rotated " + time.Now().UTC().Format("2006-01-02")
	for i, s := range w.srv {
		// Every other line as it was, in order; the old line replaced by
		// the new key with the same options; the file's mode kept.
		got, mode := w.authorizedKeys(t, i)
		lines := strings.Split(w.orig[i], "\n")
		want := strings.Join([]string{lines[0], lines[1], lines[3],
			rotOptions + " " + authorizedKeysLine(newSignerKey.PublicKey()) + " " + stamp}, "\n") + "\n"
		if got != want {
			t.Errorf("server %d authorized_keys:\n%s\nwant:\n%s", i+1, got, want)
		}
		if mode != 0o640 {
			t.Errorf("server %d authorized_keys mode %v, want 0640", i+1, mode)
		}
		if err := login(s, w.oldKey); err == nil {
			t.Errorf("server %d still accepts the old key", i+1)
		}
		if err := login(s, newSignerKey); err != nil {
			t.Errorf("server %d refuses the new key: %v", i+1, err)
		}
		// No temp file is left, and no lock.
		entries, _ := os.ReadDir(filepath.Join(s.home, ".ssh"))
		for _, e := range entries {
			if e.Name() != "authorized_keys" {
				t.Errorf("server %d: left in ~/.ssh: %s", i+1, e.Name())
			}
		}
	}
	// And hop itself now logs in with the new key.
	if code, out, errOut := w.hop(t, "exec", "web-1", "--", "echo", "ok"); code != 0 || out != "ok\n" {
		t.Errorf("hop exec after the rotation: %d %q %q", code, out, errOut)
	}

	// No private key was ever on disk: not during the run, not after.
	if len(leaked) > 0 {
		t.Errorf("files holding a private key during the rotation: %v", leaked)
	}
	body := strings.Split(strings.TrimSpace(newKey.PrivateKey), "\n")
	chunk := body[len(body)/2]
	filepath.WalkDir(w.base, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(chunk)) {
				t.Errorf("%s holds the new private key", p)
			}
		}
		return nil
	})
	// The agent directory is gone.
	if m, _ := filepath.Glob(filepath.Join(w.paths.RunDir, "rotate-*")); len(m) != 0 {
		t.Errorf("left behind: %v", m)
	}
}

func TestKeyRotateVerifyFailureRollsBackThatHostOnly(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	// web-2's server does not take the new line: the new key cannot log in.
	w.srv[1].setRefuse("hop-rotated")
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	if code != 255 {
		t.Errorf("exit %d, want 255", code)
	}
	res := decodeRotate(t, stdout)
	st := hostStatus(res)
	if st["web-1"].Status != "rotated" {
		t.Errorf("web-1: %+v", st["web-1"])
	}
	if h := st["web-2"]; h.Status != "failed" || !strings.Contains(h.Reason, "did not log in (deploy@127.0.0.1: Permission denied (publickey).)") ||
		!strings.Contains(h.Reason, "put back as it was") || strings.Contains(h.Reason, "no such identity") {
		t.Errorf("web-2: %+v", h)
	}
	if res.OK || res.Keys[0].OldKey != "kept" || !strings.Contains(res.Keys[0].OldKeyReason, "web-2") {
		t.Errorf("result %+v", res)
	}

	// web-2: exactly as before, and still on the old key in the vault.
	if got, mode := w.authorizedKeys(t, 1); got != w.orig[1] || mode != 0o640 {
		t.Errorf("web-2 authorized_keys after rollback (mode %v):\n%s\nwant:\n%s", mode, got, w.orig[1])
	}
	if w.hostKeyID(t, "web-2") != w.keyID || w.keyNamed(t, "deploy-key") == nil {
		t.Error("web-2 lost the old key in the vault")
	}
	if err := login(w.srv[1], w.oldKey); err != nil {
		t.Errorf("web-2 refuses the old key after the rollback: %v", err)
	}
	if w.hostKeyID(t, "web-1") == w.keyID {
		t.Error("web-1 still on the old key")
	}
	if code, _, errOut := w.hop(t, "exec", "web-2", "--", "true"); code != 0 {
		t.Errorf("hop exec web-2 after the failure: %d %s", code, errOut)
	}
}

func TestKeyRotateThroughAJumpHost(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{jump: true})
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--yes")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, "rotated") || strings.Contains(stdout, "failed") || strings.Contains(stdout, "needs-attention") {
		t.Errorf("stdout:\n%s", stdout)
	}
	for i, s := range w.srv {
		if err := login(s, w.oldKey); err == nil {
			t.Errorf("server %d still accepts the old key", i+1)
		}
	}
	if code, out, errOut := w.hop(t, "exec", "web-2", "--", "echo", "ok"); code != 0 || out != "ok\n" {
		t.Errorf("hop exec web-2 through the jump host: %d %q %q", code, out, errOut)
	}
}

func TestKeyRotateDryRunChangesNothing(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{unpinned: true})
	before := w.snapshot(t)
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--dry-run")
	t.Logf("hop key rotate --dry-run (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"web-1", "rotate", "web-3", "skip: no host key is pinned", "Dry run: nothing was changed", "the old key stays in the vault"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("plan lacks %q:\n%s", want, stdout)
		}
	}
	code, stdout, _ = w.hop(t, "key", "rotate", "--all", "--dry-run", "--json")
	res := decodeRotate(t, stdout)
	if code != 0 || !res.DryRun || hostStatus(res)["web-1"].Status != "planned" || hostStatus(res)["web-3"].Status != "skipped" {
		t.Errorf("dry run JSON (exit %d): %s", code, stdout)
	}

	// Without a terminal or --yes, the plan is shown and nothing happens.
	code, stdout, stderr = w.hop(t, "key", "rotate", "deploy-key")
	if code != 255 || !strings.Contains(stderr, "--yes") || !strings.Contains(stdout, "web-1") {
		t.Errorf("no --yes: exit %d\n%s\n%s", code, stdout, stderr)
	}

	after := w.snapshot(t)
	if len(after.Keys) != len(before.Keys) || len(after.Hosts) != len(before.Hosts) {
		t.Fatalf("the vault changed: %+v", after)
	}
	for i := range after.Hosts {
		if after.Hosts[i].ItemVersion != before.Hosts[i].ItemVersion || after.Hosts[i].KeyID != before.Hosts[i].KeyID {
			t.Errorf("host %s changed", after.Hosts[i].Name)
		}
	}
	for i := range w.srv {
		if got, _ := w.authorizedKeys(t, i); got != w.orig[i] {
			t.Errorf("server %d authorized_keys changed:\n%s", i+1, got)
		}
	}
}

func TestKeyRotateKeepsTheOldKeyForASkippedHost(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{unpinned: true})
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	res := decodeRotate(t, stdout)
	st := hostStatus(res)
	if code != 0 || st["web-1"].Status != "rotated" || st["web-2"].Status != "rotated" || st["web-3"].Status != "skipped" {
		t.Errorf("exit %d, %+v", code, st)
	}
	if res.Keys[0].OldKey != "kept" || w.hostKeyID(t, "web-3") != w.keyID || w.keyNamed(t, "deploy-key") == nil {
		t.Errorf("the old key should stay for web-3: %+v", res.Keys[0])
	}
}

func TestKeyRotateOfferAfterRevoke(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	var out, errOut bytes.Buffer
	env := w.env(t, strings.NewReader(""), &out, &errOut)
	if err := cli.OfferKeyRotation(context.Background(), env, false); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "these 1 keys: deploy-key") || !strings.Contains(s, "`hop key rotate --all`") {
		t.Errorf("offer:\n%s", s)
	}
	if strings.Contains(errOut.String(), "[y/N]") {
		t.Error("asked without a terminal")
	}
	// --json: the report carries rotate_command; nothing is printed here.
	out.Reset()
	if err := cli.OfferKeyRotation(context.Background(), env, true); err != nil || out.Len() != 0 {
		t.Errorf("with --json: %v %q", err, out.String())
	}

	// On a terminal, yes runs the rotation.
	w.tty = true
	out.Reset()
	errOut.Reset()
	env = w.env(t, strings.NewReader("y\n"), &out, &errOut)
	if err := cli.OfferKeyRotation(context.Background(), env, false); err != nil {
		t.Fatalf("%v\n%s\n%s", err, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "Rotate them now? [y/N]") || strings.Count(out.String(), "rotated") < 2 {
		t.Errorf("stdout:\n%s\nstderr:\n%s", out.String(), errOut.String())
	}
	if w.keyNamed(t, "deploy-key") != nil {
		t.Error("the old key is still in the vault")
	}
}

// rotHostJSON is a host of hop key rotate --json, decoded on its own so
// the tests read every field the command prints.
type rotHostJSON struct {
	Host        string `json:"host"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	RemoteState string `json:"remote_state"`
	Fix         string `json:"fix"`
}

func decodeRotateHosts(t *testing.T, stdout string) map[string]rotHostJSON {
	t.Helper()
	var res struct {
		Keys []struct {
			Hosts []rotHostJSON `json:"hosts"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	out := map[string]rotHostJSON{}
	for _, k := range res.Keys {
		for _, h := range k.Hosts {
			out[h.Host] = h
		}
	}
	return out
}

// identityFile is the IdentityFile of host's block in the generated ssh
// config: the path ssh tries as a private key file before the agent.
func (w *rotWorld) identityFile(t *testing.T, host string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(w.paths.ConfigDir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	in := false
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "Host ") {
			in = strings.TrimSpace(strings.TrimPrefix(l, "Host ")) == host
			continue
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "IdentityFile "); ok && in {
			return strings.Trim(v, `"`)
		}
	}
	t.Fatalf("no IdentityFile for %s in:\n%s", host, b)
	return ""
}

func (w *rotWorld) hostNamed(t *testing.T, name string) model.Host {
	t.Helper()
	for _, h := range w.snapshot(t).Hosts {
		if h.Name == name {
			return h
		}
	}
	t.Fatalf("no host %s", name)
	return model.Host{}
}

// The rename that removes the old key goes through, but the connection
// drops before its exit status arrives, and the host is unreachable after.
// hop cannot know what the server accepts, so both keys stay in the vault,
// the host is reported as needing attention, and the command it names
// finishes the job once the host is back.
func TestKeyRotateUnknownRemoteStateKeepsBothKeys(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	s := w.srv[0]
	var writes atomic.Int32
	s.setOnExec(func(cmd string) bool {
		if isAKWrite(cmd) && writes.Add(1) == 2 { // the write that removes the old key
			s.down.Store(true)
			return true
		}
		return false
	})
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-1", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	if writes.Load() < 2 {
		t.Fatalf("the old key's lines were never removed (%d writes); the test did not drop the connection", writes.Load())
	}
	res := decodeRotate(t, stdout)
	rk := res.Keys[0]

	// The server took the edit: only the new key is in authorized_keys.
	got, _ := w.authorizedKeys(t, 0)
	if strings.Contains(got, authorizedKeysLine(w.oldKey.PublicKey())) || !strings.Contains(got, "hop-rotated") {
		t.Fatalf("the test meant the removal to go through:\n%s", got)
	}
	// So the new key must still be in the vault, and the old one too.
	if rk.NewKeyRemoved || w.keyNamed(t, rk.NewKey) == nil {
		t.Fatalf("the new key %q was deleted from the vault, and the server accepts only it", rk.NewKey)
	}
	if w.keyNamed(t, "deploy-key") == nil || rk.OldKey != "kept" {
		t.Errorf("the old key was deleted: %+v", rk)
	}
	if code == 0 || res.OK {
		t.Errorf("exit %d, ok %v: an unknown host is not a success", code, res.OK)
	}
	h := decodeRotateHosts(t, stdout)["web-1"]
	if h.Status != "needs-attention" || h.RemoteState != "unknown" ||
		!strings.Contains(h.Reason, "deploy-key") || !strings.Contains(h.Reason, rk.NewKey) || !strings.HasPrefix(h.Fix, "hop key rotate ") {
		t.Fatalf("web-1: %+v", h)
	}

	// The host is back: the command hop named finds the old key's lines
	// gone, logs in with the new key, and points web-1 at it.
	s.down.Store(false)
	s.setOnExec(nil)
	args := append(strings.Fields(h.Fix)[1:], "--yes", "--json")
	code, stdout, stderr = w.hop(t, args...)
	t.Logf("hop %s (exit %d)\n%s\nstderr: %s", strings.Join(args, " "), code, stdout, stderr)
	if h := decodeRotateHosts(t, stdout)["web-1"]; code != 0 || h.Status != "already-rotated" {
		t.Fatalf("the fix: exit %d, web-1 %+v", code, h)
	}
	if w.hostKeyID(t, "web-1") != w.keyNamed(t, rk.NewKey).ItemID {
		t.Error("web-1 is not on the new key after the fix")
	}
	if w.keyNamed(t, rk.NewKey) == nil || w.keyNamed(t, "deploy-key") == nil {
		t.Error("the fix deleted a key that web-2 or web-1 uses")
	}
}

// OpenSSH adds up IdentityFile lines, so a check that ran through the
// generated config would also offer the old key from a private key file at
// that config's IdentityFile. The server refuses the new key here: the
// rotation must fail and put the host back, not log in with the old key
// and call it verified.
func TestKeyRotateVerifyOffersOnlyTheNewKey(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	old := w.keyNamed(t, "deploy-key")
	if err := os.WriteFile(w.identityFile(t, "web-1"), []byte(old.PrivateKey), 0o600); err != nil {
		t.Fatal(err)
	}
	w.srv[0].setRefuse("hop-rotated")
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-1", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	res := decodeRotate(t, stdout)
	if h := decodeRotateHosts(t, stdout)["web-1"]; code != 255 || h.Status != "failed" || !strings.Contains(h.Reason, "did not log in") {
		t.Errorf("exit %d, web-1 %+v", code, h)
	}
	if got, _ := w.authorizedKeys(t, 0); got != w.orig[0] {
		t.Errorf("authorized_keys after the failed check:\n%s\nwant:\n%s", got, w.orig[0])
	}
	if err := login(w.srv[0], w.oldKey); err != nil {
		t.Errorf("web-1 refuses the old key: %v", err)
	}
	if w.hostKeyID(t, "web-1") != w.keyID || !res.Keys[0].NewKeyRemoved {
		t.Errorf("vault after the failure: web-1 on %v, %+v", w.hostKeyID(t, "web-1"), res.Keys[0])
	}
}

// Another device moves web-1 to another address while its key is being
// rotated. The vault write then conflicts, and hop must not point the moved
// record, at a server it never checked, at the new key.
func TestKeyRotateConflictDoesNotRepointAMovedHost(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	var writes atomic.Int32
	w.srv[0].setOnExec(func(cmd string) bool {
		if isAKWrite(cmd) && writes.Add(1) == 2 {
			// A Run of its own: w.hop's stdin field belongs to the rotation.
			var out, errOut bytes.Buffer
			env := w.env(t, strings.NewReader(""), &out, &errOut)
			if code := cli.Run(context.Background(), []string{"edit", "web-1", "--address", "127.0.0.9"}, env); code != 0 {
				t.Errorf("hop edit during the rotation: exit %d: %s", code, errOut.String())
			}
		}
		return false
	})
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-1", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	res := decodeRotate(t, stdout)
	h := w.hostNamed(t, "web-1")
	if len(h.Addresses) != 1 || h.Addresses[0] != "127.0.0.9" {
		t.Fatalf("the edit did not land: %v", h.Addresses)
	}
	if h.KeyID != w.keyID {
		t.Errorf("the moved record was pointed at the new key")
	}
	if st := decodeRotateHosts(t, stdout)["web-1"]; code == 0 || st.Status != "needs-attention" || !strings.Contains(st.Reason, "changed") {
		t.Errorf("exit %d, web-1 %+v", code, st)
	}
	if w.keyNamed(t, "deploy-key") == nil || w.keyNamed(t, res.Keys[0].NewKey) == nil {
		t.Errorf("both keys should stay: %+v", res.Keys[0])
	}
	// The server hop checked is put back on the old key, which the record
	// still names.
	if err := login(w.srv[0], w.oldKey); err != nil {
		t.Errorf("web-1's server refuses the old key: %v", err)
	}
}

// Another hop run holds the authorized_keys lock and edits the file while
// it does. hop waits for the lock, finds the file changed from what it
// read, and changes nothing.
func TestKeyRotateWaitsForTheAuthorizedKeysLock(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	s := w.srv[0]
	f := filepath.Join(s.home, ".ssh", "authorized_keys")
	lock := filepath.Join(s.home, ".ssh", ".hop-authorized_keys.lock.d")
	held := filepath.Join(w.base, "held")
	const theirs = "# added by another hop\n"
	var once sync.Once
	other := make(chan string, 1) // what went wrong while the other writer held the lock
	s.setOnExec(func(cmd string) bool {
		if !isAKWrite(cmd) {
			return false
		}
		once.Do(func() {
			// It prints the file as it found it after holding the lock a
			// while, and then adds a line.
			c := exec.Command("sh", "-c", `mkdir "$4" && echo "other-token $$ 2026-10-28T09:15:00Z" > "$4/owner" && : > "$3" && sleep 1.5 && cat "$1" && printf '%s' "$2" >> "$1" && rm -r "$4"`, "sh", f, theirs, held, lock)
			go func() {
				out, err := c.Output()
				switch {
				case err != nil:
					other <- "the other writer: " + err.Error()
				case string(out) != w.orig[0]:
					other <- "authorized_keys changed while another writer held the lock:\n" + string(out)
				default:
					other <- ""
				}
			}()
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				if _, err := os.Stat(held); err == nil {
					return
				}
			}
			other <- "the other writer never took the lock"
		})
		return false
	})
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-1", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	select {
	case msg := <-other:
		if msg != "" {
			t.Error(msg)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the other writer never ran")
	}
	if h := decodeRotateHosts(t, stdout)["web-1"]; code != 255 || h.Status != "failed" || !strings.Contains(h.Reason, "changed") {
		t.Errorf("exit %d, web-1 %+v", code, h)
	}
	if got, _ := w.authorizedKeys(t, 0); got != w.orig[0]+theirs {
		t.Errorf("authorized_keys:\n%s\nwant the original plus the other writer's line", got)
	}
	if _, err := os.Stat(lock); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the lock is still there after the run: %v", err)
	}
	if w.hostKeyID(t, "web-1") != w.keyID {
		t.Error("web-1 moved to the new key")
	}
}

// Two records for the same account: the first rotation removes the old
// key there, so the second record's old-key login fails. hop tries the new
// key, and points that record at it too.
func TestKeyRotateSecondAliasOfTheSameAccount(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	if code, _, errOut := w.hop(t, "add", "web-1-alias", "--address", "127.0.0.1", "--port", strconv.Itoa(w.srv[0].port),
		"--user", "deploy", "--key", "deploy-key", "--host-key", authorizedKeysLine(w.srv[0].hostKey)); code != 0 {
		t.Fatalf("hop add: %d %s", code, errOut)
	}
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	st := decodeRotateHosts(t, stdout)
	if code != 0 || st["web-1"].Status != "rotated" || st["web-2"].Status != "rotated" || st["web-1-alias"].Status != "already-rotated" {
		t.Fatalf("exit %d, %+v", code, st)
	}
	res := decodeRotate(t, stdout)
	newKey := w.keyNamed(t, res.Keys[0].NewKey)
	if newKey == nil || w.hostKeyID(t, "web-1-alias") != newKey.ItemID {
		t.Errorf("web-1-alias is not on the new key")
	}
	if w.keyNamed(t, "deploy-key") != nil || res.Keys[0].OldKey != "deleted" {
		t.Errorf("the old key should go once every record moved: %+v", res.Keys[0])
	}
}
