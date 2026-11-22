//go:build sshdfixture

package cli_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/access"
	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/model/modeltest"
)

// hop access and hop key rotate against a real OpenSSH server, with real
// mounts (spec rev 17, §7.7 Change 2, §8.4). These need root, an sshd, a
// second account to log in to and a hook PATH for that account, which the
// Kiln check image doesn't have. scripts/access-fixtures/run.sh leases a
// VM, sets it up (guest/setup.sh) and runs this file there:
//
//	go test -c -tags sshdfixture ./internal/cli   (on Kiln checks)
//	HOPKEY_SSHD_FIXTURE=1 cli.test -test.run '^TestSSHD'   (as root, on the VM)
//
// Without the tag none of this is compiled; without the variable every
// test skips. The tests share the target account and run one at a time.
//
// The target account's PATH starts with the hook directory of
// guest/hook.sh: cksum, cat, ln, mv and rm there run the real ones, and
// do more only in the modes a test writes to $HKFX_RUN/mode (see
// sshdFix.setMode).

type sshdFix struct {
	user, jumpUser string
	home, jumpHome string
	uid, gid       int
	juid, jgid     int
	port           [3]int           // the target's sshd, jump 1, jump 2
	hostKey        [3]ssh.PublicKey // their ed25519 host keys
	run            string           // the hook's control directory
	out            string           // where recordings are kept for the run's report
}

func loadSSHDFix(t *testing.T) *sshdFix {
	t.Helper()
	if os.Getenv("HOPKEY_SSHD_FIXTURE") != "1" {
		t.Skip("HOPKEY_SSHD_FIXTURE=1 is not set: these run on a leased VM (scripts/access-fixtures/run.sh)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the sshd fixtures run as root")
	}
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	fx := &sshdFix{user: env("HKFX_USER", "hkt"), jumpUser: env("HKFX_JUMP_USER", "hkj"),
		run: env("HKFX_RUN", "/run/hkfx"), out: env("HKFX_OUT", "/var/hkfx/out")}
	lookup := func(name string) (string, int, int) {
		u, err := user.Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		return u.HomeDir, uid, gid
	}
	fx.home, fx.uid, fx.gid = lookup(fx.user)
	fx.jumpHome, fx.juid, fx.jgid = lookup(fx.jumpUser)
	for i, k := range []struct{ port, key string }{
		{"HKFX_PORT", "/etc/ssh/ssh_host_ed25519_key.pub"},
		{"HKFX_J1_PORT", "/etc/hkfx/j1_host_ed25519_key.pub"},
		{"HKFX_J2_PORT", "/etc/hkfx/j2_host_ed25519_key.pub"},
	} {
		fx.port[i], _ = strconv.Atoi(env(k.port, strconv.Itoa([]int{22, 2201, 2202}[i])))
		b, err := os.ReadFile(k.key)
		if err != nil {
			t.Fatal(err)
		}
		if fx.hostKey[i], _, _, _, err = ssh.ParseAuthorizedKey(b); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { fx.unmountAll(t) })
	fx.setMode(t)
	fx.unmountAll(t)
	return fx
}

func (fx *sshdFix) sshDir() string { return filepath.Join(fx.home, ".ssh") }
func (fx *sshdFix) akPath() string { return filepath.Join(fx.sshDir(), "authorized_keys") }

// setMode sets the hook's modes until the test ends, and empties its logs.
func (fx *sshdFix) setMode(t *testing.T, modes ...string) {
	t.Helper()
	write := func(s string) {
		if err := os.WriteFile(filepath.Join(fx.run, "mode"), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(strings.Join(modes, " "))
	os.Remove(filepath.Join(fx.run, "go"))
	logs, _ := filepath.Glob(filepath.Join(fx.run, "log", "*"))
	for _, l := range logs {
		os.Remove(l)
	}
	t.Cleanup(func() { write("") })
}

// hookLog is what the hook wrote to its log name.
func (fx *sshdFix) hookLog(name string) string {
	b, _ := os.ReadFile(filepath.Join(fx.run, "log", name))
	return string(b)
}

// mounts are the mount points at or under ~/.ssh of the target, deepest
// first.
func (fx *sshdFix) mounts(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) > 4 && (f[4] == fx.sshDir() || strings.HasPrefix(f[4], fx.sshDir()+"/")) {
			out = append(out, f[4])
		}
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

func (fx *sshdFix) unmountAll(t *testing.T) {
	t.Helper()
	for range 4 {
		ms := fx.mounts(t)
		if len(ms) == 0 {
			return
		}
		for _, m := range ms {
			exec.Command("umount", "-l", m).Run()
		}
	}
	t.Errorf("mounts left under %s: %v", fx.sshDir(), fx.mounts(t))
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// writeOwned writes a file the target account owns, mode 0600.
func (fx *sshdFix) writeOwned(t *testing.T, path, content string, uid, gid int) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0o600)
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
}

// resetSSH gives the target a fresh ~/.ssh holding authorized_keys with
// content, after the account's processes have ended.
func (fx *sshdFix) resetSSH(t *testing.T, content string) {
	t.Helper()
	fx.waitQuiet(t)
	fx.unmountAll(t)
	if err := os.RemoveAll(fx.sshDir()); err != nil {
		t.Fatal(err)
	}
	fx.mkSSHDir(t)
	fx.writeOwned(t, fx.akPath(), content, fx.uid, fx.gid)
}

func (fx *sshdFix) mkSSHDir(t *testing.T) {
	t.Helper()
	if err := os.Mkdir(fx.sshDir(), 0o700); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	os.Chmod(fx.sshDir(), 0o700)
	if err := os.Chown(fx.sshDir(), fx.uid, fx.gid); err != nil {
		t.Fatal(err)
	}
}

// waitQuiet waits until no process of the target account runs: every
// session script, and sshd's process for it, has ended. The account's
// systemd user manager, which logind keeps for a while after the last
// login, doesn't count.
func (fx *sshdFix) waitQuiet(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		out, _ := exec.Command("pgrep", "-u", fx.user, "-a").Output()
		var busy []string
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Fields(l)
			if len(f) < 2 || strings.HasSuffix(f[1], "systemd") || f[1] == "(sd-pam)" {
				continue
			}
			busy = append(busy, l)
		}
		if len(busy) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the target account still runs:\n%s", out)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (fx *sshdFix) ak(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(fx.akPath())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// leftovers are the entries of ~/.ssh other than authorized_keys: a lock,
// a session directory or a probe link that a session left.
func (fx *sshdFix) leftovers(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(fx.sshDir())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.Name() != "authorized_keys" {
			out = append(out, e.Name())
		}
	}
	return out
}

func (fx *sshdFix) noLeftovers(t *testing.T) {
	t.Helper()
	fx.waitQuiet(t)
	if l := fx.leftovers(t); len(l) != 0 {
		t.Errorf("left in ~/.ssh: %v", l)
	}
}

// login tries the target's sshd with exactly signer.
func (fx *sshdFix) login(signer ssh.Signer) error {
	c, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(fx.port[0])), &ssh.ClientConfig{
		User: fx.user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(fx.hostKey[0]), HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, Timeout: 5 * time.Second,
	})
	if err != nil {
		return err
	}
	return c.Close()
}

// keep copies a recording to the run's output.
func (fx *sshdFix) keep(t *testing.T, name string, data []byte) {
	t.Helper()
	p := filepath.Join(fx.out, name)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// sshdWorld is a vault whose host "web" is the target account on this
// machine's sshd, reached directly or through one or two jump hosts (the
// jump account on two more sshds with host keys of their own).
type sshdWorld struct {
	*e2e
	fx        *sshdFix
	login     ssh.Signer
	colleague ssh.Signer
	pub, fp   string
	orig      string
	argvLog   string // every ssh hop ran: its argv, \x1f-separated, one per line
	elogs     string // a copy of every ssh -E log, numbered in order
}

func newSSHDWorld(t *testing.T, fx *sshdFix, jumps int) *sshdWorld {
	t.Helper()
	cli.SetAKLockWait(t, 1)
	base, err := os.MkdirTemp("", "hkfx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	tmp := filepath.Join(base, "tmp")
	os.Mkdir(tmp, 0o700)
	t.Setenv("TMPDIR", tmp)
	home := filepath.Join(base, "home")
	paths := daemon.Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(home, ".ssh", "hop"), StateDir: filepath.Join(base, "state")}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	login, _ := ssh.NewSignerFromKey(priv)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	st := modeltest.New()
	ctx := context.Background()
	key, err := st.PutKey(ctx, model.Key{Name: "deploy-key", KeyType: "ed25519",
		PrivateKey: string(pem.EncodeToMemory(block)), PublicKey: authorizedKeysLine(login.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	w := &sshdWorld{fx: fx, login: login, colleague: newSigner(t)}
	w.pub = authorizedKeysLine(w.colleague.PublicKey())
	w.fp = ssh.FingerprintSHA256(w.colleague.PublicKey())
	w.orig = "# hop sshd fixture\n" + rotOptions2 + " " + authorizedKeysLine(login.PublicKey()) + " deploy\n" +
		authorizedKeysLine(newSigner(t).PublicKey()) + " other@laptop\n"
	fx.resetSSH(t, w.orig)

	// The jump account lets the same key in.
	jssh := filepath.Join(fx.jumpHome, ".ssh")
	os.MkdirAll(jssh, 0o700)
	os.Chown(jssh, fx.juid, fx.jgid)
	fx.writeOwned(t, filepath.Join(jssh, "authorized_keys"), authorizedKeysLine(login.PublicKey())+" deploy\n", fx.juid, fx.jgid)

	var jump model.ID
	for i := 1; i <= jumps; i++ {
		h, err := st.PutHost(ctx, model.Host{
			Name: fmt.Sprintf("jump-%d", i), Addresses: []string{"127.0.0.1"}, Port: uint32(fx.port[i]), User: fx.jumpUser,
			KeyID: key.ItemID, Route: "auto", AgentAccess: "allow", HostKeys: []string{authorizedKeysLine(fx.hostKey[i])}, JumpHostID: jump,
		})
		if err != nil {
			t.Fatal(err)
		}
		jump = h.ItemID
	}
	if _, err := st.PutHost(ctx, model.Host{
		Name: "web", Addresses: []string{"127.0.0.1"}, Port: uint32(fx.port[0]), User: fx.user,
		KeyID: key.ItemID, Route: "auto", AgentAccess: "allow", HostKeys: []string{authorizedKeysLine(fx.hostKey[0])}, JumpHostID: jump,
	}); err != nil {
		t.Fatal(err)
	}
	d, err := daemon.Start(daemon.Options{Paths: paths, Store: st, Version: "test", Tailscale: noTailscale{}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	w.e2e = &e2e{base: base, home: home, paths: paths, store: st, daemon: d, keyID: key.ItemID}

	// hop runs ssh through this wrapper: it records the argv, and keeps a
	// copy of the -E log of a run that has one (the binding preflight).
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Fatal(err)
	}
	w.argvLog = filepath.Join(base, "ssh-argv")
	w.elogs = filepath.Join(base, "elogs")
	os.Mkdir(w.elogs, 0o700)
	wrapper := filepath.Join(base, "ssh-wrapper")
	script := `#!/bin/sh
{ printf '%s\037' "$@"; echo; } >> '` + w.argvLog + `'
e=; prev=
for a in "$@"; do [ "$prev" = -E ] && e=$a; prev=$a; done
[ -n "$e" ] || exec '` + sshPath + `' "$@"
'` + sshPath + `' "$@"; rc=$?
n=$(ls '` + w.elogs + `' | wc -l)
cp "$e" '` + w.elogs + `'/$(printf %03d "$n").log 2>/dev/null
exit $rc
`
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	w.sshBin = wrapper
	return w
}

// rotOptions2 are the options of the login key's line: rotate copies them
// to the new key's.
const rotOptions2 = `from="127.0.0.1",no-agent-forwarding`

func (w *sshdWorld) run(t *testing.T, args ...string) (int, cli.AccessRunResult, string) {
	t.Helper()
	aw := &accessWorld{e2e: w.e2e}
	return aw.run(t, args...)
}

func (w *sshdWorld) add(t *testing.T, label string) (int, cli.AccessRunResult, string) {
	return w.run(t, "add", label, "web", "--pubkey", w.pub+" colleague@laptop", "--fingerprint", w.fp, "--yes", "--json")
}

func (w *sshdWorld) record(t *testing.T, label string) *model.Access {
	t.Helper()
	return (&accessWorld{e2e: w.e2e}).record(t, label)
}

func (w *sshdWorld) line(t *testing.T, label string) string {
	t.Helper()
	a := w.record(t, label)
	if a == nil {
		t.Fatalf("no record %s", label)
	}
	return w.pub + " hop-access:" + a.RecordID.String()
}

// argvs are the ssh command lines hop ran, without the remote command
// (the last word), split by whether the command was an edit of
// authorized_keys (the session or rotate's write script).
func (w *sshdWorld) argvs(t *testing.T) (edits, others [][]string) {
	t.Helper()
	b, _ := os.ReadFile(w.argvLog)
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if l == "" {
			continue
		}
		argv := strings.Split(strings.TrimSuffix(l, "\x1f"), "\x1f")
		if strings.Contains(argv[len(argv)-1], ".hop-s.") {
			edits = append(edits, argv[:len(argv)-1])
		} else {
			others = append(others, argv)
		}
	}
	return edits, others
}

func hasKeepalive(argv []string) bool {
	for _, o := range []string{"ServerAliveInterval=15", "ServerAliveCountMax=3"} {
		if i := slices.Index(argv, o); i < 1 || argv[i-1] != "-o" {
			return false
		}
	}
	return true
}

// preflightLogs are the -E logs hop's ssh runs wrote, in order.
func (w *sshdWorld) preflightLogs(t *testing.T) [][]byte {
	t.Helper()
	names, _ := filepath.Glob(filepath.Join(w.elogs, "*.log"))
	sort.Strings(names)
	var out [][]byte
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

func (fx *sshdFix) pins() []ssh.PublicKey { return fx.hostKey[:] }

// ------------------------------------------------------------------ tests

// The account's PATH starts with the hook, and the server is the one the
// report names.
func TestSSHD00Setup(t *testing.T) {
	fx := loadSSHDFix(t)
	w := newSSHDWorld(t, fx, 0)
	c, err := ssh.Dial("tcp", "127.0.0.1:"+strconv.Itoa(fx.port[0]), &ssh.ClientConfig{
		User: fx.user, Auth: []ssh.AuthMethod{ssh.PublicKeys(w.login)}, HostKeyCallback: ssh.FixedHostKey(fx.hostKey[0]), HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, _ := c.NewSession()
	out, err := s.Output("command -v cksum; id -un; echo $SHELL")
	if err != nil || !strings.HasPrefix(string(out), "/opt/hkfx/hook/cksum\n"+fx.user+"\n") {
		t.Fatalf("the target's session: %q %v", out, err)
	}
	t.Logf("server: %s; target session: %q", c.ServerVersion(), out)
	v, _ := exec.Command("ssh", "-V").CombinedOutput()
	t.Logf("client: %s", bytes.TrimSpace(v))
	fx.keep(t, "versions.txt", []byte(fmt.Sprintf("client %s\nserver %s\n", bytes.TrimSpace(v), c.ServerVersion())))
}

// Add and rm on a real sshd: the line goes in with the file's mode and
// owner kept, the colleague logs in, rm takes it out with the tombstone,
// and the colleague can't log in; nothing is left in ~/.ssh. Every editing
// ssh carries the keepalives, on hop's argv and on the live process the
// host sees.
func TestSSHDAccessAddRemove(t *testing.T) {
	fx := loadSSHDFix(t)
	w := newSSHDWorld(t, fx, 0)
	fx.setMode(t, "argv", "log")
	code, res, _ := w.add(t, "alice")
	if code != 0 || targetStates(res)["web"] != model.AccessInstalled {
		t.Fatalf("add: %d %+v", code, res)
	}
	line := w.line(t, "alice")
	if got := fx.ak(t); got != w.orig+line+"\n" {
		t.Fatalf("after add: %q", got)
	}
	fi, _ := os.Stat(fx.akPath())
	st := fi.Sys().(*syscall.Stat_t)
	if fi.Mode().Perm() != 0o600 || int(st.Uid) != fx.uid || int(st.Gid) != fx.gid {
		t.Errorf("authorized_keys is %v %d:%d", fi.Mode(), st.Uid, st.Gid)
	}
	if err := fx.login(w.colleague); err != nil {
		t.Fatalf("the colleague can't log in: %v", err)
	}
	fx.noLeftovers(t)
	if !strings.Contains(fx.hookLog("ln.log"), "rc=0") || !strings.Contains(fx.hookLog("mv.log"), "rc=0") {
		t.Errorf("probe or rename not seen: ln %q mv %q", fx.hookLog("ln.log"), fx.hookLog("mv.log"))
	}

	logs := w.preflightLogs(t)
	if len(logs) != 1 {
		t.Fatalf("%d -E logs", len(logs))
	}
	if k, err := access.BoundKey(string(logs[0]), true, fx.pins()); err != nil || ssh.FingerprintSHA256(k) != ssh.FingerprintSHA256(fx.hostKey[0]) {
		t.Fatalf("the preflight log doesn't bind: %v", err)
	}
	fx.keep(t, "binding/hop-direct.log", logs[0])

	code, res, _ = w.run(t, "rm", "alice", "--yes", "--json")
	if code != 0 || !res.Deleted || targetStates(res)["web"] != model.AccessRemoved {
		t.Fatalf("rm: %d %+v", code, res)
	}
	tomb := fmt.Sprintf("# hop-access-removed %s 2\n", strings.TrimPrefix(line, w.pub+" hop-access:"))
	if got := fx.ak(t); got != w.orig+tomb {
		t.Fatalf("after rm: %q, want %q", got, w.orig+tomb)
	}
	if err := fx.login(w.colleague); err == nil {
		t.Fatal("the colleague still logs in")
	}
	fx.noLeftovers(t)

	edits, _ := w.argvs(t)
	if len(edits) != 2 {
		t.Errorf("%d editing ssh runs, want 2", len(edits))
	}
	for _, a := range edits {
		if !hasKeepalive(a) {
			t.Errorf("an editing ssh without the keepalives: %q", a)
		}
	}
	// The host's view: the client process that ran each session, as ps
	// showed it while the script ran.
	ps := fx.hookLog("ssh-argv.log")
	n := 0
	for _, l := range strings.Split(ps, "\n") {
		if strings.Contains(l, ".hop-s.") {
			n++
			if !strings.Contains(l, " -o ServerAliveInterval=15 -o ServerAliveCountMax=3 ") {
				t.Errorf("a live session ssh without the keepalives: %.300s", l)
			}
		}
	}
	if n == 0 {
		t.Errorf("ps never showed a session's ssh:\n%s", ps)
	}
	t.Logf("ps saw %d session ssh lines", n)
}

// A tombstone for the record: the client sends abort under the lock, the
// script exits 87, nothing is renamed, and the lock and directory go.
func TestSSHDAccessAbort(t *testing.T) {
	fx := loadSSHDFix(t)
	w := newSSHDWorld(t, fx, 0)
	if code, _, _ := w.add(t, "alice"); code != 0 {
		t.Fatal("add")
	}
	line := w.line(t, "alice")
	id := strings.TrimPrefix(line, w.pub+" hop-access:")
	want := w.orig + line + "\n" + fmt.Sprintf("# hop-access-removed %s 5\n", id)
	fx.resetSSH(t, want)
	fx.setMode(t, "log")
	code, res, _ := w.run(t, "add", "alice", "web", "--json")
	if code == 0 || targetStates(res)["web"] != model.AccessFailed || !strings.Contains(res.Targets[0].Message, "was removed here (gen 5)") {
		t.Fatalf("add over a tombstone: %d %+v", code, res)
	}
	if fx.ak(t) != want {
		t.Fatal("the file changed")
	}
	if fx.hookLog("mv.log") != "" || fx.hookLog("ln.log") != "" {
		t.Errorf("the session went past the decision: ln %q mv %q", fx.hookLog("ln.log"), fx.hookLog("mv.log"))
	}
	fx.noLeftovers(t)
}

// The client's deadline passes while the host is still sending the file
// (the hook sleeps before the header's cat): hop sends abort and stores
// nothing. With a long grace the script reads the abort and exits 87;
// with a short one hop ends the connection, and the script, which gets
// EOF or SIGPIPE from sshd, still cleans up and releases. Either way the
// file is as it was and nothing is left.
func TestSSHDAccessDeadlineAbort(t *testing.T) {
	for _, c := range []struct {
		name  string
		grace time.Duration
	}{{"script reads the abort", 10 * time.Second}, {"hop ends the connection", 500 * time.Millisecond}} {
		t.Run(c.name, func(t *testing.T) {
			fx := loadSSHDFix(t)
			w := newSSHDWorld(t, fx, 0)
			cli.SetAccessDeadlines(t, 2*time.Second, c.grace)
			fx.setMode(t, "slowheader", "log")
			os.WriteFile(filepath.Join(fx.run, "sleep"), []byte("5"), 0o644)
			start := time.Now()
			code, res, _ := w.add(t, "alice")
			t.Logf("hop returned after %s", time.Since(start).Round(time.Millisecond))
			if code == 0 || len(res.Targets) != 1 || res.Targets[0].Recorded {
				t.Fatalf("add: %d %+v", code, res)
			}
			if a := w.record(t, "alice"); a == nil || a.Targets[0].State != model.AccessPending || a.Targets[0].Gen != 1 {
				t.Fatalf("record %+v", a)
			}
			fx.noLeftovers(t)
			if fx.ak(t) != w.orig || fx.hookLog("mv.log") != "" {
				t.Fatalf("the file changed, or mv ran: %q", fx.hookLog("mv.log"))
			}
			t.Logf("message: %s", res.Targets[0].Message)
		})
	}
}

// The client is killed (SIGKILL to hop's ssh) while the host's script is
// in the middle of reading the payload: the hook passes 16 bytes, waits
// for the kill, then reads the rest. sshd ends the session; whatever the
// script got, it either renames the complete content or refuses (the TO
// check), and releases. hop re-reads; the vault records installed only if
// the line is there. A resume then leaves exactly one line. A small file
// is all in the pipe to the script before the kill; a 256 KiB one is
// not, so there the script gets a cut payload.
func TestSSHDAccessKillClientMidPayload(t *testing.T) {
	for _, pad := range []int{0, 256 << 10} {
		t.Run(fmt.Sprintf("file of %d bytes", pad), func(t *testing.T) { killMidPayload(t, pad) })
	}
}

func killMidPayload(t *testing.T, pad int) {
	fx := loadSSHDFix(t)
	w := newSSHDWorld(t, fx, 0)
	if pad > 0 {
		w.orig += strings.Repeat("# padding: a long authorized_keys file for the fixture ..........\n", pad/64)
		fx.resetSSH(t, w.orig)
	}
	fx.setMode(t, "midpayload", "log")
	killed := make(chan int, 1)
	go func() {
		n := 0
		defer func() { killed <- n }()
		deadline := time.Now().Add(40 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(fx.run, "log", "payload-started")); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		for _, pid := range sessionClients(t) {
			if syscall.Kill(pid, syscall.SIGKILL) == nil {
				n++
			}
		}
		os.WriteFile(filepath.Join(fx.run, "go"), nil, 0o644)
	}()
	code, res, _ := w.add(t, "alice")
	if n := <-killed; n == 0 {
		t.Fatal("no session ssh was killed")
	}
	fx.waitQuiet(t)
	t.Logf("host: payload cat %q; mv %q", fx.hookLog("cat.log"), fx.hookLog("mv.log"))
	line := w.line(t, "alice")
	got := fx.ak(t)
	switch got {
	case w.orig:
		t.Logf("branch: the script refused the cut payload; hop exit %d, %+v", code, res.Targets)
	case w.orig + line + "\n":
		t.Logf("branch: the script renamed the complete payload; hop exit %d, %+v", code, res.Targets)
	default:
		t.Fatalf("the file is neither as it was nor as intended: %q", got)
	}
	a := w.record(t, "alice")
	if st := a.Targets[0].State; (st == model.AccessInstalled) != (code == 0) || (st != model.AccessInstalled && st != model.AccessPending) {
		t.Fatalf("exit %d with the target %s", code, st)
	}
	if a.Targets[0].State == model.AccessInstalled && got == w.orig {
		t.Fatal("installed recorded without the line")
	}
	if l := fx.leftovers(t); len(l) != 0 {
		t.Fatalf("left in ~/.ssh: %v", l)
	}
	fx.setMode(t)
	// A resume: nothing to do if the target is installed already.
	if code, res, _ := w.run(t, "add", "alice", "--json"); code != 0 || (len(res.Targets) > 0 && targetStates(res)["web"] != model.AccessInstalled) {
		t.Fatalf("resume: %d %+v", code, res)
	}
	if a := w.record(t, "alice"); a.Targets[0].State != model.AccessInstalled {
		t.Fatalf("after the resume: %+v", a.Targets[0])
	}
	if fx.ak(t) != w.orig+line+"\n" {
		t.Fatalf("after the resume: %q", fx.ak(t))
	}
	fx.noLeftovers(t)
}

// sessionClients are the PIDs of ssh clients that run a session script.
func sessionClients(t *testing.T) []int {
	var out []int
	dirs, _ := os.ReadDir("/proc")
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join("/proc", d.Name(), "comm"))
		cmdline, _ := os.ReadFile(filepath.Join("/proc", d.Name(), "cmdline"))
		if strings.TrimSpace(string(comm)) == "ssh" && bytes.Contains(cmdline, []byte(".hop-s.")) {
			out = append(out, pid)
		}
	}
	return out
}

// rotate on a real sshd: the write script replaces the old key's line
// with the new key's (same options), sshd lets the new key in and not the
// old, and every write carries the keepalives, with hop's generated config
// and with a check config.
func TestSSHDRotate(t *testing.T) {
	fx := loadSSHDFix(t)
	w := newSSHDWorld(t, fx, 0)
	fx.setMode(t, "argv", "log")
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	if h := decodeRotateHosts(t, stdout)["web"]; code != 0 || h.Status != "rotated" {
		t.Fatalf("exit %d, web %+v", code, h)
	}
	snap, _ := w.store.Snapshot(context.Background())
	var newKey *model.Key
	for i := range snap.Keys {
		if snap.Keys[i].Name != "deploy-key" {
			newKey = &snap.Keys[i]
		}
	}
	if newKey == nil {
		t.Fatal("no new key")
	}
	signer, err := ssh.ParsePrivateKey([]byte(newKey.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	got := fx.ak(t)
	if strings.Contains(got, authorizedKeysLine(w.login.PublicKey())) ||
		!strings.Contains(got, rotOptions2+" "+authorizedKeysLine(signer.PublicKey())+" ") || !strings.HasPrefix(got, "# hop sshd fixture\n") {
		t.Fatalf("after rotate: %q", got)
	}
	if err := fx.login(signer); err != nil {
		t.Errorf("the new key can't log in: %v", err)
	}
	if err := fx.login(w.login); err == nil {
		t.Error("the old key still logs in")
	}
	fx.noLeftovers(t)
	edits, _ := w.argvs(t)
	var generated, check int
	for _, a := range edits {
		if !hasKeepalive(a) {
			t.Errorf("a write without the keepalives: %q", a)
		}
		if slices.Contains(a, "hop-rotate-check") {
			check++
		} else {
			generated++
		}
	}
	if generated == 0 || check == 0 {
		t.Errorf("writes: %d generated config, %d check config", generated, check)
	}
	if !strings.Contains(fx.hookLog("ssh-argv.log"), "-o ServerAliveInterval=15 -o ServerAliveCountMax=3") {
		t.Errorf("ps never showed a write's ssh with the keepalives:\n%s", fx.hookLog("ssh-argv.log"))
	}
}

// §7.7 Change 2, the probe: a tmpfs mounted on the session directory
// after the script made it (the hook mounts it from the first cksum after
// mkdir) puts $s/new on another filesystem than ~/.ssh. The real ln
// fails with EXDEV, the script exits 84 with the probe message, mv never
// runs, and the file is unchanged. The hook takes the mount away when the
// exit trap's rm runs, so the trap can remove the directory.
func TestSSHDProbeRefusesCrossFilesystem(t *testing.T) {
	t.Run("access", func(t *testing.T) {
		fx := loadSSHDFix(t)
		w := newSSHDWorld(t, fx, 0)
		fx.setMode(t, "tmpfs-s", "unmount-at-rm", "log")
		code, res, _ := w.add(t, "alice")
		if code == 0 || targetStates(res)["web"] != model.AccessFailed || !strings.Contains(res.Targets[0].Message, "can't be hard-linked") {
			t.Fatalf("add: %d %+v", code, res)
		}
		fx.crossFSEvidence(t)
		if fx.ak(t) != w.orig {
			t.Fatal("the file changed")
		}
		fx.noLeftovers(t)
	})
	t.Run("rotate", func(t *testing.T) {
		fx := loadSSHDFix(t)
		w := newSSHDWorld(t, fx, 0)
		fx.setMode(t, "tmpfs-s", "unmount-at-rm", "log")
		code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web", "--yes", "--json")
		t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
		h := decodeRotateHosts(t, stdout)["web"]
		if code == 0 || h.Status != "failed" || !strings.Contains(h.Reason, "can't be hard-linked") {
			t.Fatalf("exit %d, web %+v", code, h)
		}
		fx.crossFSEvidence(t)
		if fx.ak(t) != w.orig {
			t.Fatal("the file changed")
		}
		fx.noLeftovers(t)
	})
	// The mount stays: the trap can't remove the session directory (rmdir
	// of a mount point fails), so it keeps the lock and exits 89; hop
	// re-reads, finds the file as it was, and stores nothing.
	t.Run("mount kept", func(t *testing.T) {
		fx := loadSSHDFix(t)
		w := newSSHDWorld(t, fx, 0)
		fx.setMode(t, "tmpfs-s", "log")
		code, res, out := w.add(t, "alice")
		if code == 0 || len(res.Targets) != 1 || res.Targets[0].Recorded || !strings.Contains(out, "could not confirm that it removed its session directory") {
			t.Fatalf("add: %d %+v", code, res)
		}
		if a := w.record(t, "alice"); a.Targets[0].State != model.AccessPending {
			t.Fatalf("target %+v", a.Targets[0])
		}
		fx.crossFSEvidence(t)
		fx.waitQuiet(t)
		if fx.ak(t) != w.orig {
			t.Fatal("the file changed")
		}
		l := fx.leftovers(t)
		if len(l) != 2 || !slices.Contains(l, ".hop-authorized_keys.lock.d") {
			t.Fatalf("left in ~/.ssh: %v (want the lock and the session directory)", l)
		}
		t.Logf("message: %s", res.Targets[0].Message)
	})
}

// crossFSEvidence: the hook mounted the tmpfs, the real ln said EXDEV,
// and mv never ran.
func (fx *sshdFix) crossFSEvidence(t *testing.T) {
	t.Helper()
	ln := fx.hookLog("ln.log")
	t.Logf("mount: %q; ln: %q", fx.hookLog("mount.log"), ln)
	if !strings.Contains(fx.hookLog("mount.log"), "mounted") {
		t.Errorf("the hook mounted nothing: %q", fx.hookLog("mount.log"))
	}
	if !strings.Contains(ln, "Invalid cross-device link") {
		t.Errorf("ln didn't fail with EXDEV: %q", ln)
	}
	if mv := fx.hookLog("mv.log"); mv != "" {
		t.Errorf("mv ran: %q", mv)
	}
}

// §7.7 Change 2, residual: authorized_keys bind-mounted as a file. The
// probe passes (its directory is ~/.ssh's filesystem), rename(2) fails
// with EBUSY, mv doesn't copy, and the script exits 86. hop re-reads,
// finds the file as read under the lock, and stores nothing; rotate
// can't tell, re-reads, and reports the host failed and put back as it
// was, with mv's words. Neither the bind source
// nor the file under the mount changes.
func TestSSHDBindMountedAuthorizedKeys(t *testing.T) {
	setup := func(t *testing.T, fx *sshdFix, w *sshdWorld) (src string) {
		dir := t.TempDir()
		os.Chmod(dir, 0o755)
		src = filepath.Join(dir, "ak")
		fx.writeOwned(t, src, w.orig, fx.uid, fx.gid)
		fx.writeOwned(t, fx.akPath(), "# under the mount\n", fx.uid, fx.gid)
		run(t, "mount", "--bind", src, fx.akPath())
		return src
	}
	after := func(t *testing.T, fx *sshdFix, w *sshdWorld, src string) {
		fx.noLeftovers(t)
		if !strings.Contains(fx.hookLog("ln.log"), "rc=0") {
			t.Errorf("the probe didn't pass: %q", fx.hookLog("ln.log"))
		}
		mv := fx.hookLog("mv.log")
		t.Logf("mv: %q", mv)
		if !strings.Contains(mv, "Device or resource busy") || strings.Contains(mv, "rc=0") {
			t.Errorf("mv didn't fail with EBUSY: %q", mv)
		}
		if b, _ := os.ReadFile(src); string(b) != w.orig {
			t.Errorf("the bind source changed: %q", b)
		}
		fx.unmountAll(t)
		if got := fx.ak(t); got != "# under the mount\n" {
			t.Errorf("the file under the mount changed: %q", got)
		}
	}
	t.Run("access", func(t *testing.T) {
		fx := loadSSHDFix(t)
		w := newSSHDWorld(t, fx, 0)
		src := setup(t, fx, w)
		fx.setMode(t, "log")
		code, res, _ := w.add(t, "alice")
		if code == 0 || len(res.Targets) != 1 || res.Targets[0].Recorded || !strings.Contains(res.Targets[0].Message, "not applied") {
			t.Fatalf("add: %d %+v", code, res)
		}
		if a := w.record(t, "alice"); a.Targets[0].State != model.AccessPending || a.Targets[0].Gen != 1 {
			t.Fatalf("target %+v", a.Targets[0])
		}
		after(t, fx, w, src)
	})
	t.Run("rotate", func(t *testing.T) {
		fx := loadSSHDFix(t)
		w := newSSHDWorld(t, fx, 0)
		src := setup(t, fx, w)
		fx.setMode(t, "log")
		code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web", "--yes", "--json")
		t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
		h := decodeRotateHosts(t, stdout)["web"]
		if code == 0 || h.Status != "failed" || !strings.Contains(h.Reason, "hop could not tell whether it replaced") ||
			!strings.Contains(h.Reason, "Device or resource busy") || !strings.Contains(h.Reason, "put back as it was") {
			t.Fatalf("exit %d, web %+v", code, h)
		}
		after(t, fx, w, src)
	})
}

// ~/.ssh on a filesystem of its own (a tmpfs mount on ~/.ssh): $s, the
// probe link and authorized_keys are all on it, so the probe passes and
// the rename goes through. The probe doesn't refuse a mount as such.
func TestSSHDOwnFilesystemForSSHDir(t *testing.T) {
	fx := loadSSHDFix(t)
	w := newSSHDWorld(t, fx, 0)
	fx.waitQuiet(t)
	run(t, "mount", "-t", "tmpfs", "-o", fmt.Sprintf("size=1m,mode=0700,uid=%d,gid=%d", fx.uid, fx.gid), "hkfx-ssh", fx.sshDir())
	fx.writeOwned(t, fx.akPath(), w.orig, fx.uid, fx.gid)
	fx.setMode(t, "log")
	code, res, _ := w.add(t, "alice")
	if code != 0 || targetStates(res)["web"] != model.AccessInstalled {
		t.Fatalf("add: %d %+v", code, res)
	}
	if got := fx.ak(t); got != w.orig+w.line(t, "alice")+"\n" {
		t.Fatalf("after add: %q", got)
	}
	if err := fx.login(w.colleague); err != nil {
		t.Fatalf("the colleague can't log in: %v", err)
	}
	fx.noLeftovers(t)
}

// §7.7 Change 2, cost: a ~/.ssh on a filesystem without hard links (vfat)
// refuses every edit with the probe message, access and rotate alike, and
// nothing changes.
func TestSSHDNoHardLinks(t *testing.T) {
	if _, err := exec.LookPath("mkfs.vfat"); err != nil {
		t.Skip("no mkfs.vfat on this machine")
	}
	mountVfat := func(t *testing.T, fx *sshdFix, content string) {
		img := filepath.Join(t.TempDir(), "ssh.img")
		run(t, "truncate", "-s", "16M", img)
		run(t, "mkfs.vfat", img)
		fx.waitQuiet(t)
		if out, err := exec.Command("mount", "-o", fmt.Sprintf("loop,uid=%d,gid=%d,umask=077", fx.uid, fx.gid), img, fx.sshDir()).CombinedOutput(); err != nil {
			t.Skipf("can't mount vfat here: %v %s", err, out)
		}
		if err := os.WriteFile(fx.akPath(), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("access", func(t *testing.T) {
		fx := loadSSHDFix(t)
		w := newSSHDWorld(t, fx, 0)
		mountVfat(t, fx, w.orig)
		fx.setMode(t, "log")
		code, res, _ := w.add(t, "alice")
		if code == 0 || targetStates(res)["web"] != model.AccessFailed || !strings.Contains(res.Targets[0].Message, "can't be hard-linked") {
			t.Fatalf("add: %d %+v", code, res)
		}
		t.Logf("ln: %q", fx.hookLog("ln.log"))
		if fx.hookLog("mv.log") != "" || fx.ak(t) != w.orig {
			t.Fatalf("mv ran (%q), or the file changed", fx.hookLog("mv.log"))
		}
		fx.noLeftovers(t)
	})
	t.Run("rotate", func(t *testing.T) {
		fx := loadSSHDFix(t)
		w := newSSHDWorld(t, fx, 0)
		mountVfat(t, fx, w.orig)
		fx.setMode(t, "log")
		code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web", "--yes", "--json")
		t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
		h := decodeRotateHosts(t, stdout)["web"]
		if code == 0 || h.Status != "failed" || !strings.Contains(h.Reason, "can't be hard-linked") {
			t.Fatalf("exit %d, web %+v", code, h)
		}
		if fx.hookLog("mv.log") != "" || fx.ak(t) != w.orig {
			t.Fatalf("mv ran (%q), or the file changed", fx.hookLog("mv.log"))
		}
		fx.noLeftovers(t)
	})
}

// The binding parse (§7.6) against this machine's OpenSSH: hop's own
// preflight logs, direct and through one and two jump hosts (its
// ProxyCommand), and plain OpenSSH logs with ProxyJump chains and a forced
// rekey. Each binds to the target's key, and no jump host's key line is
// in the file: with ProxyJump the jump hosts' ssh logs to stderr, which
// the test checks too. The logs are kept for internal/access/testdata.
func TestSSHDBindingLogs(t *testing.T) {
	fx := loadSSHDFix(t)
	targetFP := ssh.FingerprintSHA256(fx.hostKey[0])
	jumpFP := []string{ssh.FingerprintSHA256(fx.hostKey[1]), ssh.FingerprintSHA256(fx.hostKey[2])}
	var pins strings.Builder
	for i, name := range []string{"target", "jump1", "jump2"} {
		fmt.Fprintf(&pins, "%s %s\n", name, authorizedKeysLine(fx.hostKey[i]))
	}
	fx.keep(t, "binding/pins", []byte(pins.String()))
	check := func(t *testing.T, name string, log []byte) {
		t.Helper()
		k, err := access.BoundKey(string(log), true, fx.pins())
		if err != nil || ssh.FingerprintSHA256(k) != targetFP {
			t.Fatalf("%s doesn't bind to the target: %v", name, err)
		}
		for _, fp := range jumpFP {
			if bytes.Contains(log, []byte(fp)) {
				t.Errorf("%s names a jump host's key %s", name, fp)
			}
		}
		n := bytes.Count(log, []byte("Server host key:"))
		t.Logf("%s: %d bytes, %d key lines", name, len(log), n)
		fx.keep(t, "binding/"+name+".log", log)
	}

	for _, jumps := range []int{1, 2} {
		t.Run(fmt.Sprintf("hop through %d jump hosts", jumps), func(t *testing.T) {
			w := newSSHDWorld(t, fx, jumps)
			code, res, _ := w.add(t, "alice")
			if code != 0 || targetStates(res)["web"] != model.AccessInstalled {
				t.Fatalf("add: %d %+v", code, res)
			}
			logs := w.preflightLogs(t)
			if len(logs) != 1 {
				t.Fatalf("%d -E logs", len(logs))
			}
			check(t, fmt.Sprintf("hop-jump%d", jumps), logs[0])
			fx.noLeftovers(t)
		})
	}

	// Plain OpenSSH: a config of hop's kind, ProxyJump for the chains.
	w := newSSHDWorld(t, fx, 0)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "id")
	block, err := ssh.MarshalPrivateKey(w.loginPriv(t), "")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600)
	var kh strings.Builder
	for i, k := range fx.hostKey {
		host := "127.0.0.1"
		if fx.port[i] != 22 {
			host = fmt.Sprintf("[127.0.0.1]:%d", fx.port[i])
		}
		fmt.Fprintf(&kh, "%s %s", host, ssh.MarshalAuthorizedKey(k))
	}
	os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(kh.String()), 0o600)
	cfg := filepath.Join(dir, "config")
	os.WriteFile(cfg, []byte(fmt.Sprintf(`Host *
  GlobalKnownHostsFile none
  UserKnownHostsFile %s/known_hosts
  StrictHostKeyChecking yes
  UpdateHostKeys no
  FingerprintHash sha256
  IdentityFile %s
  IdentitiesOnly yes
  IdentityAgent none
  BatchMode yes
  ControlMaster no
  ControlPath none
`, dir, keyFile)), 0o600)
	j1 := fmt.Sprintf("%s@127.0.0.1:%d", fx.jumpUser, fx.port[1])
	j2 := fmt.Sprintf("%s@127.0.0.1:%d", fx.jumpUser, fx.port[2])
	for _, c := range []struct {
		name  string
		extra []string
		cmd   string
		jumps int
	}{
		{"openssh-direct", nil, "cat ~/.ssh/authorized_keys", 0},
		{"openssh-proxyjump1", []string{"-J", j1}, "cat ~/.ssh/authorized_keys", 1},
		{"openssh-proxyjump2", []string{"-J", j1 + "," + j2}, "cat ~/.ssh/authorized_keys", 2},
		// 1 KiB of data before rekeying, and 256 KiB of output.
		{"openssh-rekey", []string{"-o", "RekeyLimit=1K"}, "head -c 262144 /dev/zero", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			log := filepath.Join(dir, c.name+".log")
			args := append([]string{"-vv", "-E", log, "-F", cfg, "-p", strconv.Itoa(fx.port[0])}, c.extra...)
			args = append(args, fx.user+"@127.0.0.1", c.cmd)
			cmd := exec.Command("ssh", args...)
			var stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = new(bytes.Buffer), &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("ssh: %v\n%s", err, stderr.String())
			}
			b, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			check(t, c.name, b)
			for i := range c.jumps {
				if !strings.Contains(stderr.String(), "Server host key: ssh-ed25519 "+jumpFP[i]) {
					t.Errorf("jump host %d's key line isn't on stderr:\n%s", i+1, stderr.String())
				}
			}
			if c.name == "openssh-rekey" {
				if n := countLines(b, "SSH2_MSG_NEWKEYS received"); n < 2 {
					t.Errorf("no rekey happened (%d NEWKEYS)", n)
				}
			}
		})
	}
}

func countLines(b []byte, s string) int {
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if strings.Contains(sc.Text(), s) {
			n++
		}
	}
	return n
}

// loginPriv is the private half of the vault's key.
func (w *sshdWorld) loginPriv(t *testing.T) any {
	t.Helper()
	k, err := ssh.ParseRawPrivateKey([]byte(w.keyPEM(t)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (w *sshdWorld) keyPEM(t *testing.T) string {
	t.Helper()
	snap, _ := w.store.Snapshot(context.Background())
	for _, k := range snap.Keys {
		if k.Name == "deploy-key" {
			return k.PrivateKey
		}
	}
	t.Fatal("no deploy-key")
	return ""
}
