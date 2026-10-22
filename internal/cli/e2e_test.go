package cli_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/model/modeltest"
	"github.com/dalyem/hopkey/internal/tailscale"
)

// These tests drive the real CLI code path (cli.Run) against a daemon running
// in this process, a fake store, and the system ssh client talking to an
// in-process x/crypto/ssh server. They fail, not skip, when ssh is missing and
// HOPKEY_REQUIRE_SSH is set, as it is on Kiln.

type e2e struct {
	base   string
	home   string
	paths  daemon.Paths
	store  *modeltest.Store
	server *sshServer
	daemon *daemon.Daemon
	keyID  model.ID

	stdin  string // given to the next hop invocation
	tty    bool   // stdin and stdout are terminals
	sshBin string // overrides the ssh binary hop runs for plain ssh
	// readPassword answers passphrase prompts; nil means no prompting.
	readPassword func(prompt string) ([]byte, error)
}

type noTailscale struct{}

func (noTailscale) Status(context.Context) (*tailscale.Status, error) {
	return tailscale.Unavailable("no tailscale in tests"), nil
}

func requireSSH(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		if os.Getenv("HOPKEY_REQUIRE_SSH") != "" {
			t.Fatalf("ssh not found and HOPKEY_REQUIRE_SSH is set: %v", err)
		}
		t.Skip("no ssh binary on PATH")
	}
}

func newE2E(t *testing.T) *e2e { return newE2EWith(t, noTailscale{}) }

func newE2EWith(t *testing.T, ts daemon.TailscaleSource) *e2e {
	t.Helper()
	requireSSH(t)
	// Unix socket paths are length-limited, so avoid t.TempDir here.
	base, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
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
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}

	srv := startSSHServer(t, signer.PublicKey())
	st := modeltest.New()
	ctx := context.Background()
	key, err := st.PutKey(ctx, model.Key{
		Name: "deploy-key", KeyType: "ed25519",
		PrivateKey: string(pem.EncodeToMemory(block)),
		PublicKey:  strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))),
	})
	if err != nil {
		t.Fatal(err)
	}
	host := func(name string, pins ...string) model.Host {
		return model.Host{
			Name: name, Addresses: []string{"127.0.0.1"}, Port: uint32(srv.port), User: "deploy",
			KeyID: key.ItemID, Route: "auto", AgentAccess: "allow", HostKeys: pins,
		}
	}
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(srv.hostKey)))
	for _, h := range []model.Host{host("web-1", pin), host("web-2")} {
		if _, err := st.PutHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}

	d, err := daemon.Start(daemon.Options{Paths: paths, Store: st, Version: "test", Tailscale: ts, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return &e2e{base: base, home: home, paths: paths, store: st, server: srv, daemon: d, keyID: key.ItemID}
}

// hop runs the CLI with args and returns its exit status and output.
func (e *e2e) configFile(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.paths.ConfigDir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (e *e2e) hop(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var so, se bytes.Buffer
	env := &cli.Env{
		Stdin: strings.NewReader(e.stdin), Stdout: &so, Stderr: &se,
		Getenv: func(string) string { return "" },
		Home:   e.home, Paths: e.paths,
		StdoutTTY: e.tty, StdinTTY: e.tty, SSHBinary: e.sshBin, ReadPassword: e.readPassword,
		StartDaemon: func() error {
			t.Error("the CLI tried to start a daemon, but one is running")
			return errors.New("unexpected daemon start")
		},
		DialTimeout: 5 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	code = cli.Run(ctx, args, env)
	e.stdin = ""
	return code, so.String(), se.String()
}

func TestExecRunsACommandThroughRealSSH(t *testing.T) {
	e := newE2E(t)

	code, stdout, stderr := e.hop(t, "exec", "web-1", "--", "echo", "ok")
	if code != 0 || stdout != "ok\n" {
		t.Fatalf("hop exec: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if got := e.server.commands(); !slices.Equal(got, []string{"echo ok"}) {
		t.Errorf("remote saw %q, want [echo ok]", got)
	}

	// Without a --, the words after the target are the command.
	if code, stdout, _ := e.hop(t, "exec", "web-1", "echo", "ok"); code != 0 || stdout != "ok\n" {
		t.Errorf("hop exec without --: code=%d stdout=%q", code, stdout)
	}
}

func TestExecJSON(t *testing.T) {
	e := newE2E(t)
	code, stdout, stderr := e.hop(t, "exec", "web-1", "--json", "--", "echo", "ok")
	t.Logf("hop exec web-1 --json -- echo ok  (exit %d)\n%s", code, stdout)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var res cli.ExecResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	if res.Host != "web-1" || res.ExitCode != 0 || res.Stdout != "ok\n" || res.Stderr != "" || res.Truncated {
		t.Errorf("result = %+v", res)
	}
	if res.DurationMS < 0 {
		t.Errorf("duration_ms = %d", res.DurationMS)
	}
	// The shape is stable: exactly these keys.
	var raw map[string]json.RawMessage
	json.Unmarshal([]byte(stdout), &raw)
	var keys []string
	for k := range raw {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if want := []string{"duration_ms", "exit_code", "host", "stderr", "stdout", "truncated"}; !slices.Equal(keys, want) {
		t.Errorf("keys = %v, want %v", keys, want)
	}
}

func TestExecPassesTheRemoteExitCodeThrough(t *testing.T) {
	e := newE2E(t)

	if code, _, _ := e.hop(t, "exec", "web-1", "--", "exit 3"); code != 3 {
		t.Errorf("hop exec 'exit 3': exit %d, want 3", code)
	}
	code, stdout, _ := e.hop(t, "exec", "web-1", "--json", "--", "exit 3")
	if code != 3 {
		t.Errorf("hop exec --json 'exit 3': exit %d, want 3", code)
	}
	var res cli.ExecResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil || res.ExitCode != 3 {
		t.Errorf("json = %s (err %v), want exit_code 3", stdout, err)
	}

	// Failure of hop itself is 255, and says so on stderr.
	code, stdout, stderr := e.hop(t, "exec", "no-such-host", "--", "true")
	if code != 255 || stdout != "" || !strings.Contains(stderr, "no host matches") {
		t.Errorf("unknown host: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestExecStreamsStdinAndStderr(t *testing.T) {
	e := newE2E(t)

	e.stdin = "hello from stdin\n"
	if code, stdout, stderr := e.hop(t, "exec", "web-1", "--", "cat"); code != 0 || stdout != "hello from stdin\n" {
		t.Errorf("cat: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	code, stdout, _ := e.hop(t, "exec", "web-1", "--json", "--", "stderr")
	var res cli.ExecResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if code != 1 || res.ExitCode != 1 || res.Stderr != "oops\n" || res.Stdout != "" {
		t.Errorf("stderr cmd: code=%d result=%+v", code, res)
	}
}

func TestExecKeepsTheLast64KBAndSaysSo(t *testing.T) {
	e := newE2E(t)
	code, stdout, stderr := e.hop(t, "exec", "web-1", "--json", "--", "big")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var res cli.ExecResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Stdout) != 64<<10 {
		t.Errorf("truncated=%v len(stdout)=%d, want true and %d", res.Truncated, len(res.Stdout), 64<<10)
	}
	// The kept part is the end: the server wrote 'a'*100000 then 'z'*100000... see sshServer.
	if !strings.HasSuffix(res.Stdout, "END\n") {
		t.Errorf("stdout does not end with the server's last bytes: ...%q", res.Stdout[len(res.Stdout)-10:])
	}
}

func TestExecQuotesWordsAndSudo(t *testing.T) {
	e := newE2E(t)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"echo", "a b", "it's"}, `echo 'a b' 'it'\''s'`},
		{[]string{"cd /srv && ls"}, `cd /srv && ls`}, // one word: a shell command line
		{[]string{"--sudo", "--", "systemctl", "restart", "x"}, `sudo -n systemctl restart x`},
		{[]string{"--sudo", "--", "cd /srv && ls"}, `sudo -n sh -c 'cd /srv && ls'`},
	}
	for _, c := range cases {
		args := []string{"exec", "web-1"}
		if c.args[0] == "--sudo" {
			args = append(args, c.args...)
		} else {
			args = append(args, "--")
			args = append(args, c.args...)
		}
		e.server.reset()
		e.hop(t, args...)
		if got := e.server.commands(); !slices.Equal(got, []string{c.want}) {
			t.Errorf("hop %v: remote saw %q, want %q", args, got, c.want)
		}
	}
}

func TestExecTimeout(t *testing.T) {
	e := newE2E(t)
	start := time.Now()
	code, stdout, stderr := e.hop(t, "exec", "web-1", "--timeout", "1s", "--json", "--", "sleep")
	if code != 255 {
		t.Errorf("exit %d, want 255 (stderr %q)", code, stderr)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %s; --timeout 1s should have cut it off", d)
	}
	var res cli.ExecResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil || !strings.Contains(res.Error, "timed out") {
		t.Errorf("result = %s (err %v), want a timeout error", stdout, err)
	}
}

func TestExecRefusesSeveralHosts(t *testing.T) {
	e := newE2E(t)
	for _, target := range []string{"web-1,web-2", "tag:web"} {
		code, _, stderr := e.hop(t, "exec", target, "--", "true")
		if code != 255 || !strings.Contains(stderr, "one host") {
			t.Errorf("hop exec %s: code=%d stderr=%q", target, code, stderr)
		}
	}
	if n := e.server.connections(); n != 0 {
		t.Errorf("the server saw %d connections; nothing should have run", n)
	}
}

func TestWhich(t *testing.T) {
	e := newE2E(t)

	code, stdout, stderr := e.hop(t, "which", "web-1")
	t.Logf("hop which web-1  (exit %d)\n%s", code, stdout)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	for _, want := range []string{"host:     web-1", `rule:     alias (alias or name "web-1")`, "address:  127.0.0.1:", "via direct", "user:     deploy", "ssh:      ssh web-1"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("hop which output lacks %q:\n%s", want, stdout)
		}
	}
	if n := e.server.connections(); n != 0 {
		t.Errorf("hop which connected to the server %d times", n)
	}

	code, stdout, _ = e.hop(t, "which", "--json", "me@web-1")
	var w cli.WhichResult
	if err := json.Unmarshal([]byte(stdout), &w); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if code != 0 || w.Status != "matched" || w.Rule != "alias" || w.User != "me" || w.Host == nil || w.Host.Name != "web-1" ||
		w.Route == nil || w.Route.Chosen != "direct" || w.SSHAlias != "web-1" {
		t.Errorf("which --json = %+v (exit %d)", w, code)
	}
}

func TestAmbiguousInputIsNotGuessedNonInteractively(t *testing.T) {
	e := newE2E(t)

	// "web" is a prefix of web-1 and web-2. Not a TTY: no fuzzy match, but the
	// candidates come back, and the exit status is 255.
	code, stdout, stderr := e.hop(t, "which", "--json", "web")
	t.Logf("hop which --json web  (exit %d)\n%s", code, stdout)
	var w cli.WhichResult
	if err := json.Unmarshal([]byte(stdout), &w); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	var names []string
	for _, c := range w.Candidates {
		names = append(names, c.Name)
	}
	if code != 255 || w.Status != "no_match" || w.Host != nil || !slices.Equal(names, []string{"web-1", "web-2"}) {
		t.Errorf("code=%d status=%s host=%v candidates=%v", code, w.Status, w.Host, names)
	}
	if stderr == "" {
		t.Error("nothing on stderr for a failed resolution")
	}

	// An exact address shared by two hosts is ambiguous, with both listed.
	code, stdout, _ = e.hop(t, "which", "--json", "127.0.0.1")
	if err := json.Unmarshal([]byte(stdout), &w); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if code != 255 || w.Status != "ambiguous" || w.Rule != "address" || len(w.Candidates) != 2 {
		t.Errorf("shared address: code=%d %+v", code, w)
	}

	// And exec never runs on a guess.
	code, _, stderr = e.hop(t, "exec", "web", "--", "echo", "ok")
	if code != 255 || !strings.Contains(stderr, "web-1") || !strings.Contains(stderr, "web-2") {
		t.Errorf("exec on an ambiguous prefix: code=%d stderr=%q", code, stderr)
	}
	if n := e.server.connections(); n != 0 {
		t.Errorf("the server saw %d connections", n)
	}
}

func decodeCheck(t *testing.T, stdout string) cli.CheckResult {
	t.Helper()
	var res cli.CheckResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	return res
}

func statuses(res cli.CheckResult) map[string]string {
	m := map[string]string{}
	for _, s := range res.Steps {
		m[s.Name] = s.Status
	}
	return m
}

func TestCheckAllStepsPass(t *testing.T) {
	e := newE2E(t)
	code, stdout, stderr := e.hop(t, "check", "--json", "web-1")
	t.Logf("hop check --json web-1  (exit %d)\n%s", code, stdout)
	res := decodeCheck(t, stdout)
	want := map[string]string{
		"resolved": "pass", "route": "pass", "tcp_reachable": "pass",
		"host_key_pinned": "pass", "host_key_matches": "pass", "auth_ok": "pass",
	}
	got := statuses(res)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("step %s = %q, want %q", k, got[k], v)
		}
	}
	if code != 0 || !res.OK {
		t.Errorf("code=%d ok=%v stderr=%q", code, res.OK, stderr)
	}
	var names []string
	for _, s := range res.Steps {
		names = append(names, s.Name)
	}
	if !slices.Equal(names, []string{"resolved", "route", "tcp_reachable", "host_key_pinned", "host_key_matches", "auth_ok"}) {
		t.Errorf("steps = %v", names)
	}
}

func TestCheckReportsAnUnpinnedHostKey(t *testing.T) {
	e := newE2E(t)
	code, stdout, _ := e.hop(t, "check", "--json", "web-2")
	t.Logf("hop check --json web-2  (exit %d)\n%s", code, stdout)
	res := decodeCheck(t, stdout)
	got := statuses(res)
	if code != 255 || res.OK {
		t.Errorf("code=%d ok=%v, want 255 and not ok", code, res.OK)
	}
	for k, v := range map[string]string{
		"resolved": "pass", "route": "pass", "tcp_reachable": "pass",
		"host_key_pinned": "fail", "host_key_matches": "skipped", "auth_ok": "skipped",
	} {
		if got[k] != v {
			t.Errorf("step %s = %q, want %q", k, got[k], v)
		}
	}
	for _, s := range res.Steps {
		if s.Name == "host_key_pinned" && !strings.Contains(s.Detail, "hop trust web-2") {
			t.Errorf("the failure does not say how to fix it: %q", s.Detail)
		}
		if s.Status == "skipped" && !strings.Contains(s.Detail, "did not pass") {
			t.Errorf("skipped step %s has no reason: %q", s.Name, s.Detail)
		}
	}
}

func TestCheckStopsAtAnUnreachableHost(t *testing.T) {
	e := newE2E(t)
	// Stop the ssh server: nothing listens on its port any more.
	e.server.close()
	code, stdout, _ := e.hop(t, "check", "--json", "web-1")
	res := decodeCheck(t, stdout)
	got := statuses(res)
	if code != 255 || got["tcp_reachable"] != "fail" || got["host_key_pinned"] != "pass" ||
		got["host_key_matches"] != "skipped" || got["auth_ok"] != "skipped" {
		t.Errorf("code=%d steps=%v", code, got)
	}
}

func TestCheckCatchesAChangedHostKey(t *testing.T) {
	e := newE2E(t)
	e.server.useNewHostKey(t)
	code, stdout, _ := e.hop(t, "check", "--json", "web-1")
	res := decodeCheck(t, stdout)
	got := statuses(res)
	if code != 255 || got["host_key_pinned"] != "pass" || got["host_key_matches"] != "fail" || got["auth_ok"] != "skipped" {
		t.Errorf("code=%d steps=%v", code, got)
	}
	for _, s := range res.Steps {
		if s.Name == "host_key_matches" && !strings.Contains(s.Detail, "not pinned") {
			t.Errorf("detail = %q", s.Detail)
		}
	}
}

func TestTrustPinsTheServerKeyAndThenCheckPasses(t *testing.T) {
	e := newE2E(t)

	// Without confirmation and without a terminal, nothing is pinned.
	code, _, stderr := e.hop(t, "trust", "web-2")
	if code != 255 || !strings.Contains(stderr, "--yes") {
		t.Errorf("trust without --yes: code=%d stderr=%q", code, stderr)
	}
	// A wrong fingerprint is refused.
	code, _, stderr = e.hop(t, "trust", "web-2", "--fingerprint", "SHA256:nope")
	if code != 255 || !strings.Contains(stderr, "nothing was pinned") {
		t.Errorf("trust with a wrong fingerprint: code=%d stderr=%q", code, stderr)
	}
	fp := ssh.FingerprintSHA256(e.server.hostKey)
	code, stdout, stderr := e.hop(t, "trust", "web-2", "--fingerprint", fp)
	if code != 0 || !strings.Contains(stdout, fp) {
		t.Fatalf("trust: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	// The daemon regenerated the pins file; real ssh now accepts the host.
	code, stdout, _ = e.hop(t, "check", "--json", "web-2")
	if res := decodeCheck(t, stdout); code != 0 || !res.OK {
		t.Errorf("check after trust: code=%d %s", code, stdout)
	}
	if code, out, _ := e.hop(t, "exec", "web-2", "--", "echo", "ok"); code != 0 || out != "ok\n" {
		t.Errorf("exec after trust: code=%d out=%q", code, out)
	}

	// A changed key is not replaced without --replace.
	e.server.useNewHostKey(t)
	code, _, stderr = e.hop(t, "trust", "web-2", "--yes")
	if code != 255 || !strings.Contains(stderr, "--replace") {
		t.Errorf("trust of a changed key: code=%d stderr=%q", code, stderr)
	}
	if code, _, _ := e.hop(t, "trust", "web-2", "--yes", "--replace"); code != 0 {
		t.Errorf("trust --replace: exit %d", code)
	}
	if code, _, _ := e.hop(t, "check", "web-2"); code != 0 {
		t.Errorf("check after --replace: exit %d", code)
	}
}

func TestConnectExecsSSHWithTheGeneratedConfig(t *testing.T) {
	e := newE2E(t)
	var gotPath string
	var gotArgv []string
	var gotEnv []string
	run := func(args ...string) (int, string) {
		var so, se bytes.Buffer
		env := &cli.Env{
			Stdin: strings.NewReader(""), Stdout: &so, Stderr: &se,
			Getenv: func(string) string { return "" }, Home: e.home, Paths: e.paths,
			Environ: []string{"PATH=" + os.Getenv("PATH"), "SSH_AUTH_SOCK=/tmp/leak", "FOO=bar"},
			ExecSSH: func(path string, argv, environ []string) error {
				gotPath, gotArgv, gotEnv = path, argv, environ
				return nil
			},
		}
		code := cli.Run(context.Background(), args, env)
		return code, se.String()
	}

	if code, stderr := run("web-1"); code != 0 {
		t.Fatalf("hop web-1: exit %d, stderr %q", code, stderr)
	}
	cfg := filepath.Join(e.paths.ConfigDir, "config")
	want := []string{"ssh", "-F", cfg, "-o", "HostName=127.0.0.1", "--", "web-1"}
	if !slices.Equal(gotArgv, want) {
		t.Errorf("argv = %q\nwant   %q", gotArgv, want)
	}
	if filepath.Base(gotPath) != "ssh" {
		t.Errorf("path = %q", gotPath)
	}
	if slices.ContainsFunc(gotEnv, func(s string) bool { return strings.HasPrefix(s, "SSH_AUTH_SOCK=") }) || !slices.Contains(gotEnv, "FOO=bar") {
		t.Errorf("environment = %q: SSH_AUTH_SOCK must be dropped and the rest kept", gotEnv)
	}

	// user@target and `hop connect`.
	if code, _ := run("connect", "root@web-1"); code != 0 {
		t.Fatal("hop connect root@web-1 failed")
	}
	want = []string{"ssh", "-F", cfg, "-o", "HostName=127.0.0.1", "-o", "User=root", "--", "web-1"}
	if !slices.Equal(gotArgv, want) {
		t.Errorf("argv = %q\nwant   %q", gotArgv, want)
	}

	// A target that starts with - is never handed to ssh.
	if code, stderr := run("connect", "-oProxyCommand=evil"); code != 255 {
		t.Errorf("an option-looking target: exit %d stderr %q", code, stderr)
	}
}

func TestStatusLsAndInfoShowNoSecrets(t *testing.T) {
	e := newE2E(t)

	code, stdout, stderr := e.hop(t, "ls", "--json")
	if code != 0 {
		t.Fatalf("ls: %d %s", code, stderr)
	}
	var views []cli.HostView
	if err := json.Unmarshal([]byte(stdout), &views); err != nil || len(views) != 2 {
		t.Fatalf("ls --json: %v\n%s", err, stdout)
	}
	if views[0].Name != "web-1" || views[0].Key == nil || views[0].Key.Name != "deploy-key" || len(views[0].HostKeys) != 1 || views[0].SSHAlias != "web-1" {
		t.Errorf("view = %+v", views[0])
	}

	_, keyOut, _ := e.hop(t, "key", "ls", "--json")
	allOutput := stdout + keyOut
	for _, cmd := range [][]string{{"info", "web-1"}, {"info", "--json", "web-1"}, {"ls"}, {"key", "ls"}, {"status", "--json"}} {
		_, out, _ := e.hop(t, cmd...)
		allOutput += out
	}
	for _, secret := range []string{"PRIVATE KEY", "BEGIN OPENSSH"} {
		if strings.Contains(allOutput, secret) {
			t.Errorf("output contains %q", secret)
		}
	}

	// The daemon's control socket never returns private key bytes either.
	c, err := daemon.Dial(context.Background(), e.paths.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, op := range []string{daemon.OpList, daemon.OpStatus} {
		var raw json.RawMessage
		if err := c.Call(context.Background(), op, nil, &raw); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "private_key") {
			t.Errorf("%s response mentions a private key: %s", op, raw)
		}
	}
}

func TestAddEditRemove(t *testing.T) {
	e := newE2E(t)

	code, _, stderr := e.hop(t, "add", "db-1", "--address", "127.0.0.1", "--port", "2222", "--user", "ops", "--key", "deploy-key", "--tag", "db", "--tag", "prod", "--alias", "database")
	if code != 0 {
		t.Fatalf("add: %d %s", code, stderr)
	}
	code, stdout, _ := e.hop(t, "info", "--json", "database")
	var v cli.HostView
	if err := json.Unmarshal([]byte(stdout), &v); err != nil || code != 0 {
		t.Fatalf("info: %v %d\n%s", err, code, stdout)
	}
	if v.Name != "db-1" || v.Port != 2222 || v.User != "ops" || !slices.Equal(v.Tags, []string{"db", "prod"}) || v.Key == nil {
		t.Errorf("view = %+v", v)
	}
	if code, out, _ := e.hop(t, "ls", "prod"); code != 0 || !strings.Contains(out, "db-1") || strings.Contains(out, "web-1") {
		t.Errorf("ls prod: code=%d\n%s", code, out)
	}

	if code, _, stderr := e.hop(t, "edit", "db-1", "--user", "root", "--port", "22", "--key", ""); code != 0 {
		t.Fatalf("edit: %d %s", code, stderr)
	}
	_, stdout, _ = e.hop(t, "info", "--json", "db-1")
	json.Unmarshal([]byte(stdout), &v)
	if v.User != "root" || v.Port != 22 || v.Key != nil || v.SSHProblem == "" {
		t.Errorf("after edit: %+v (a host without a key cannot be in the ssh config)", v)
	}

	// Duplicate names are refused.
	if code, _, stderr := e.hop(t, "add", "web-1", "--address", "10.0.0.1"); code != 255 || !strings.Contains(stderr, "already") {
		t.Errorf("duplicate add: code=%d stderr=%q", code, stderr)
	}

	if code, _, stderr := e.hop(t, "rm", "db-1"); code != 255 || !strings.Contains(stderr, "--yes") {
		t.Errorf("rm without --yes: code=%d stderr=%q", code, stderr)
	}
	if code, _, stderr := e.hop(t, "rm", "db-1", "--yes"); code != 0 {
		t.Fatalf("rm: %d %s", code, stderr)
	}
	if code, _, _ := e.hop(t, "info", "db-1"); code != 255 {
		t.Errorf("info after rm: exit %d, want 255", code)
	}

	// A key in use cannot be removed.
	if code, _, stderr := e.hop(t, "key", "rm", "deploy-key", "--yes"); code != 255 || !strings.Contains(stderr, "web-1") {
		t.Errorf("key rm of a used key: code=%d stderr=%q", code, stderr)
	}
}

func TestKeyAddAndImportSSHConfig(t *testing.T) {
	e := newE2E(t)

	// A throwaway key file in the temp home.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Join(e.home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(sshDir, "id_import")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "Host app app-alias\n  HostName 192.0.2.10\n  User deploy\n  Port 2200\n  IdentityFile ~/.ssh/id_import\n\n" +
		"Host inner\n  HostName 10.0.0.5\n  ProxyJump app\n\n" +
		"Host web-1\n  HostName 192.0.2.99\n\n" +
		"Host *\n  ServerAliveInterval 30\n"
	cfgPath := filepath.Join(sshDir, "config")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// Without --with-keys: the key is referenced, not imported.
	code, stdout, stderr := e.hop(t, "import", "ssh-config", "--json", "--dry-run")
	if code != 0 {
		t.Fatalf("dry run: %d %s", code, stderr)
	}
	var rep cli.ImportReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if !rep.DryRun || e.store.Writes() != 3 { // the key and two hosts from newE2E
		t.Errorf("dry run wrote to the store: dry_run=%v writes=%d", rep.DryRun, e.store.Writes())
	}

	if code, _, stderr := e.hop(t, "import", "ssh-config"); code != 0 {
		t.Fatalf("import: %d %s", code, stderr)
	}
	_, stdout, _ = e.hop(t, "info", "--json", "app-alias")
	var app cli.HostView
	if err := json.Unmarshal([]byte(stdout), &app); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if app.Name != "app" || app.Port != 2200 || app.User != "deploy" || app.Key != nil || !strings.Contains(app.Description, "id_import") {
		t.Errorf("imported without keys: %+v", app)
	}
	_, stdout, _ = e.hop(t, "info", "--json", "inner")
	var inner cli.HostView
	json.Unmarshal([]byte(stdout), &inner)
	if inner.JumpHost != "app" {
		t.Errorf("inner's jump host = %q, want app", inner.JumpHost)
	}
	// web-1 was already in the vault and is left alone.
	_, stdout, _ = e.hop(t, "info", "--json", "web-1")
	var web cli.HostView
	json.Unmarshal([]byte(stdout), &web)
	if web.Addresses[0] != "127.0.0.1" {
		t.Errorf("web-1 was overwritten: %v", web.Addresses)
	}

	// hop key add + edit does what --with-keys does.
	if code, _, stderr := e.hop(t, "key", "add", keyPath, "--name", "imported"); code != 0 {
		t.Fatalf("key add: %d %s", code, stderr)
	}
	if code, _, stderr := e.hop(t, "key", "add", keyPath, "--name", "again"); code != 255 || !strings.Contains(stderr, "already in the vault") {
		t.Errorf("adding the same key twice: code=%d stderr=%q", code, stderr)
	}
	if code, _, stderr := e.hop(t, "edit", "app", "--key", "imported"); code != 0 {
		t.Fatalf("edit --key: %d %s", code, stderr)
	}
	if code, _, stderr := e.hop(t, "edit", "inner", "--key", "imported"); code != 0 {
		t.Fatalf("edit inner --key: %d %s", code, stderr)
	}
	_, stdout, _ = e.hop(t, "info", "--json", "app")
	json.Unmarshal([]byte(stdout), &app)
	if app.Key == nil || app.Key.Name != "imported" || app.SSHAlias != "app" {
		t.Errorf("app = %+v", app)
	}
	// The generated config now has a ProxyJump for inner.
	b, err := os.ReadFile(filepath.Join(e.paths.ConfigDir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "Host inner\n") || !strings.Contains(string(b), "ProxyJump app") {
		t.Errorf("generated config has no jump for inner:\n%s", b)
	}
}

// ---- the in-process ssh server ----

type sshServer struct {
	port int
	ln   net.Listener
	stop chan struct{}

	mu       sync.Mutex
	hostKey  ssh.PublicKey
	cfg      *ssh.ServerConfig
	cmds     []string
	forwards []string
	conns    int
	accepted ssh.PublicKey
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func startSSHServer(t *testing.T, accepted ssh.PublicKey) *sshServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &sshServer{ln: ln, port: ln.Addr().(*net.TCPAddr).Port, stop: make(chan struct{}), accepted: accepted}
	s.setHostKey(newSigner(t))
	t.Cleanup(s.close)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			cfg := s.cfg
			s.conns++
			s.mu.Unlock()
			go s.serve(c, cfg)
		}
	}()
	return s
}

func (s *sshServer) setHostKey(signer ssh.Signer) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == "deploy" || c.User() == "root" || c.User() == "ops" {
				if bytes.Equal(k.Marshal(), s.accepted.Marshal()) {
					return nil, nil
				}
			}
			return nil, errors.New("key not accepted")
		},
	}
	cfg.AddHostKey(signer)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg, s.hostKey = cfg, signer.PublicKey()
}

func (s *sshServer) useNewHostKey(t *testing.T) { s.setHostKey(newSigner(t)) }

func (s *sshServer) close() {
	s.ln.Close()
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}

func (s *sshServer) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.cmds)
}

func (s *sshServer) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cmds = nil
}

// connections counts TCP connections, including the host key probes of
// hop check and hop trust.
func (s *sshServer) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

func (s *sshServer) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() == "direct-tcpip" {
			go s.forward(nc)
			continue
		}
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go s.session(ch, creqs)
	}
}

// session answers exec requests. Commands: "echo ok", "true", "exit N", "cat"
// (echoes stdin), "stderr" (writes to stderr, exits 1), "big" (writes more than
// 64 KB, ending in END), "sleep" (waits). Anything else is recorded and exits 0.
func (s *sshServer) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
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
		s.cmds = append(s.cmds, p.Command)
		s.mu.Unlock()

		status := uint32(0)
		switch {
		case p.Command == "echo ok":
			ch.Write([]byte("ok\n"))
		case p.Command == "cat":
			io.Copy(ch, ch)
		case p.Command == "stderr":
			ch.Stderr().Write([]byte("oops\n"))
			status = 1
		case p.Command == "big":
			ch.Write(bytes.Repeat([]byte("a"), 100000))
			ch.Write(bytes.Repeat([]byte("z"), 100000))
			ch.Write([]byte("END\n"))
		case p.Command == "sleep":
			select {
			case <-s.stop:
			case <-time.After(30 * time.Second):
			}
		case strings.HasPrefix(p.Command, "exit "):
			var n uint32
			for _, r := range strings.TrimPrefix(p.Command, "exit ") {
				n = n*10 + uint32(r-'0')
			}
			status = n
		}
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
		return
	}
}

func TestInteractiveResolutionPicksAndFallsBackToPlainSSH(t *testing.T) {
	e := newE2E(t)
	e.tty = true
	if _, err := e.store.PutHost(context.Background(), model.Host{
		Name: "db-main", Addresses: []string{"10.9.9.9"}, Port: 22, Route: "auto", AgentAccess: "allow", KeyID: e.keyID,
	}); err != nil {
		t.Fatal(err)
	}

	// An ambiguous prefix on a terminal asks which one.
	e.stdin = "2\n"
	code, stdout, stderr := e.hop(t, "info", "web")
	if code != 0 || !strings.Contains(stdout, "name:         web-2") {
		t.Errorf("picker: code=%d stdout=%q", code, stdout)
	}
	for _, want := range []string{"1) web-1", "2) web-2", "pick 1-2"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the picker did not show %q:\n%s", want, stderr)
		}
	}
	e.stdin = "9\n"
	if code, _, stderr := e.hop(t, "info", "web"); code != 255 || !strings.Contains(stderr, "not a valid choice") {
		t.Errorf("a bad choice: code=%d stderr=%q", code, stderr)
	}

	// A unique prefix needs no picker. which explains instead of asking.
	code, stdout, _ = e.hop(t, "which", "db")
	if code != 0 || !strings.Contains(stdout, "rule:     prefix") || !strings.Contains(stdout, "host:     db-main") {
		t.Errorf("which db: code=%d\n%s", code, stdout)
	}
	code, stdout, _ = e.hop(t, "which", "web")
	if code != 255 || !strings.Contains(stdout, "ambiguous") || !strings.Contains(stdout, "candidate: web-1") {
		t.Errorf("which web on a terminal: code=%d\n%s", code, stdout)
	}
	// --json turns the interactive rules off even on a terminal.
	if _, stdout, _ := e.hop(t, "which", "--json", "db"); !strings.Contains(stdout, `"status": "no_match"`) {
		t.Errorf("which --json db on a terminal:\n%s", stdout)
	}

	// Nothing in the vault matches: plain ssh, then the offer to add it.
	e.sshBin = "true"
	code, _, stderr = e.hop(t, "zz/zz")
	if code != 0 || !strings.Contains(stderr, "not in the vault") || !strings.Contains(stderr, "hop add zz-zz") {
		t.Errorf("plain ssh: code=%d stderr=%q", code, stderr)
	}
	// ssh failing is passed through, and no offer is made.
	e.sshBin = "false"
	code, _, stderr = e.hop(t, "zz/zz")
	if code != 1 || strings.Contains(stderr, "hop add") {
		t.Errorf("plain ssh failing: code=%d stderr=%q", code, stderr)
	}
	// Not on a terminal, an unknown target is just an error.
	e.tty = false
	if code, _, stderr := e.hop(t, "zz/zz"); code != 255 || !strings.Contains(stderr, "no host matches") {
		t.Errorf("non-interactive unknown target: code=%d stderr=%q", code, stderr)
	}
}

// forward answers a direct-tcpip request (what ssh -W, and so ProxyJump, asks
// for) by connecting to the destination and copying both ways.
func (s *sshServer) forward(nc ssh.NewChannel) {
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
	s.mu.Lock()
	s.forwards = append(s.forwards, net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
	s.mu.Unlock()
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
	go func() {
		io.Copy(dst, ch)
		dst.Close()
	}()
	io.Copy(ch, dst)
	ch.Close()
}

func (s *sshServer) forwarded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.forwards)
}

func TestHostBehindAJumpHost(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	snap, _ := e.store.Snapshot(ctx)
	var bastion model.Host
	for _, h := range snap.Hosts {
		if h.Name == "web-1" {
			bastion = h
		}
	}
	// inner is the same test server, reached through web-1 as the jump host.
	inner := bastion
	inner.Header, inner.Name, inner.JumpHostID = model.Header{}, "inner", bastion.ItemID
	inner.Addresses = []string{"127.0.0.1"}
	if _, err := e.store.PutHost(ctx, inner); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := e.hop(t, "exec", "inner", "--", "echo", "ok")
	if code != 0 || stdout != "ok\n" {
		t.Fatalf("exec through a jump host: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if len(e.server.forwarded()) == 0 {
		t.Error("the server saw no forwarded connection, so ssh did not go through the jump host")
	}

	// check does not probe the target directly, and says so; ssh still logs in.
	code, stdout, _ = e.hop(t, "check", "--json", "inner")
	t.Logf("hop check --json inner  (exit %d)\n%s", code, stdout)
	res := decodeCheck(t, stdout)
	got := statuses(res)
	if code != 0 || !res.OK || got["tcp_reachable"] != "skipped" || got["host_key_matches"] != "skipped" || got["auth_ok"] != "pass" {
		t.Errorf("code=%d ok=%v steps=%v", code, res.OK, got)
	}

	// trust cannot read the key without a direct route.
	if code, _, stderr := e.hop(t, "trust", "inner", "--yes"); code != 255 || !strings.Contains(stderr, "jump host") {
		t.Errorf("trust behind a jump host: code=%d stderr=%q", code, stderr)
	}

	// An unpinned host behind a jump host still fails the check, at the pin.
	wrong := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newSigner(t).PublicKey())))
	if code, _, stderr := e.hop(t, "edit", "inner", "--host-key", wrong); code != 0 {
		t.Fatalf("edit: %d %s", code, stderr)
	}
	code, stdout, _ = e.hop(t, "check", "--json", "inner")
	res = decodeCheck(t, stdout)
	if code != 255 || res.OK || statuses(res)["auth_ok"] == "pass" {
		t.Errorf("a wrong pin behind a jump host: code=%d %v", code, statuses(res))
	}
}

func writeKey(t *testing.T, path string, passphrase string) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	return signer.PublicKey()
}

func TestKeyAddAsksForAPassphrase(t *testing.T) {
	e := newE2E(t)
	path := filepath.Join(e.home, ".ssh", "id_enc")
	pub := writeKey(t, path, "correct horse")

	// No terminal: nothing to ask on.
	if code, _, stderr := e.hop(t, "key", "add", path); code != 255 || !strings.Contains(stderr, "passphrase-protected") {
		t.Errorf("no tty: code=%d stderr=%q", code, stderr)
	}
	var prompts []string
	e.tty = true
	e.readPassword = func(prompt string) ([]byte, error) {
		prompts = append(prompts, prompt)
		return []byte("wrong"), nil
	}
	if code, _, _ := e.hop(t, "key", "add", path); code != 255 {
		t.Errorf("wrong passphrase: exit %d", code)
	}
	e.readPassword = func(prompt string) ([]byte, error) { return []byte("correct horse"), nil }
	code, stdout, stderr := e.hop(t, "key", "add", path, "--json")
	if code != 0 {
		t.Fatalf("right passphrase: %d %s", code, stderr)
	}
	var info map[string]any
	json.Unmarshal([]byte(stdout), &info)
	if info["fingerprint"] != ssh.FingerprintSHA256(pub) || info["name"] != "id_enc" || info["key_type"] != "ed25519" {
		t.Errorf("key = %v, want fingerprint %s", info, ssh.FingerprintSHA256(pub))
	}
	if len(prompts) != 1 || !strings.Contains(prompts[0], path) {
		t.Errorf("prompts = %q", prompts)
	}
	// What is stored is the key without its passphrase: the agent can use it.
	snap, _ := e.store.Snapshot(context.Background())
	var stored string
	for _, k := range snap.Keys {
		if k.Name == "id_enc" {
			stored = k.PrivateKey
		}
	}
	if _, err := ssh.ParseRawPrivateKey([]byte(stored)); err != nil {
		t.Errorf("the stored key still needs a passphrase: %v", err)
	}
}

func TestImportWithKeys(t *testing.T) {
	e := newE2E(t)
	sshDir := filepath.Join(e.home, ".ssh")
	plain := writeKey(t, filepath.Join(sshDir, "id_plain"), "")
	writeKey(t, filepath.Join(sshDir, "id_enc"), "secret")
	cfg := "Host a\n  IdentityFile ~/.ssh/id_plain\n\nHost b\n  IdentityFile ~/.ssh/id_plain\n\n" +
		"Host c\n  IdentityFile ~/.ssh/id_missing\n\nHost d\n  IdentityFile ~/.ssh/id_enc\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := e.hop(t, "import", "ssh-config", "--with-keys", "--json")
	if code != 0 {
		t.Fatalf("import: %d %s", code, stderr)
	}
	var rep cli.ImportReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	keysImported := 0
	for _, en := range rep.Entries {
		if en.Kind == "key" && en.Status == "imported" {
			keysImported++
		}
	}
	if keysImported != 1 {
		t.Errorf("%d keys imported, want 1 (a and b share one file):\n%s", keysImported, stdout)
	}
	warnings := strings.Join(rep.Warnings, "\n")
	if !strings.Contains(warnings, "id_missing") || !strings.Contains(warnings, "does not exist") || !strings.Contains(warnings, "id_enc") || !strings.Contains(warnings, "passphrase") {
		t.Errorf("warnings = %q", warnings)
	}

	want := map[string]string{"a": "id_plain", "b": "id_plain", "c": "", "d": ""}
	for name, key := range want {
		_, out, _ := e.hop(t, "info", "--json", name)
		var v cli.HostView
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		got := ""
		if v.Key != nil {
			got = v.Key.Name
			if v.Key.Fingerprint != ssh.FingerprintSHA256(plain) {
				t.Errorf("%s: fingerprint %s, want %s", name, v.Key.Fingerprint, ssh.FingerprintSHA256(plain))
			}
		}
		if got != key {
			t.Errorf("host %s has key %q, want %q", name, got, key)
		}
		if key == "" && !strings.Contains(v.Description, "could not be imported") {
			t.Errorf("host %s: the description does not record the unimported IdentityFile: %q", name, v.Description)
		}
	}
}
