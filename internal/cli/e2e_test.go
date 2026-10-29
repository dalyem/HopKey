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
	// passwdHome is what hop takes for the passwd home; empty means e.home.
	passwdHome string
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

// passwdShimEnv is the part of this process's environment that gives ssh a
// passwd entry under a uid that has none (see scripts/with-passwd.sh). The
// ssh -G runs of hop import start from an empty environment, so the tests
// hand it over explicitly.
func passwdShimEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "LD_PRELOAD=") || strings.HasPrefix(kv, "NSS_WRAPPER_") {
			out = append(out, kv)
		}
	}
	return out
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
	env := e.env(t, strings.NewReader(e.stdin), &so, &se)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	code = cli.Run(ctx, args, env)
	e.stdin = ""
	return code, so.String(), se.String()
}

// env is the environment hop runs in against this harness's daemon.
func (e *e2e) env(t *testing.T, stdin io.Reader, stdout, stderr io.Writer) *cli.Env {
	return &cli.Env{
		Stdin: stdin, Stdout: stdout, Stderr: stderr,
		Getenv: func(string) string { return "" },
		Home:   e.home, Paths: e.paths,
		StdoutTTY: e.tty, StdinTTY: e.tty, SSHBinary: e.sshBin, ReadPassword: e.readPassword,
		SSHProbeEnv: passwdShimEnv(),
		PasswdHome: func() (string, error) {
			if e.passwdHome != "" {
				return e.passwdHome, nil
			}
			return e.home, nil
		},
		StartDaemon: func() error {
			t.Error("the CLI tried to start a daemon, but one is running")
			return errors.New("unexpected daemon start")
		},
		DialTimeout: 5 * time.Second,
	}
}

// ssh's own refusal ("Host key verification failed") does not say what to
// do, so hop adds the hop trust hint, as hop check and the MCP server do.
func TestExecOnAnUnpinnedHostSaysToRunHopTrust(t *testing.T) {
	e := newE2E(t)
	code, _, stderr := e.hop(t, "exec", "web-2", "--", "echo", "ok")
	if code != 255 {
		t.Errorf("exit %d, want 255", code)
	}
	if !strings.Contains(stderr, "hop trust web-2") {
		t.Errorf("no hop trust hint in stderr:\n%s", stderr)
	}
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

	// A host with no pinned host key gets the hint that hop check and the
	// MCP server give; a pinned one does not.
	if _, stderr := run("web-2"); !strings.Contains(stderr, "hop trust web-2") {
		t.Errorf("hop web-2 (unpinned): no hop trust hint in %q", stderr)
	}
	if _, stderr := run("web-1"); strings.Contains(stderr, "hop trust") {
		t.Errorf("hop web-1 (pinned): stderr %q", stderr)
	}

	// A target that starts with - is never handed to ssh.
	if code, stderr := run("connect", "-oProxyCommand=evil"); code != 255 {
		t.Errorf("an option-looking target: exit %d stderr %q", code, stderr)
	}
}

func TestPickerKeepsTheUserOverride(t *testing.T) {
	e := newE2E(t)
	var gotArgv []string
	run := func(stdin string, args ...string) (int, string) {
		var so, se bytes.Buffer
		env := &cli.Env{
			Stdin: strings.NewReader(stdin), Stdout: &so, Stderr: &se,
			Getenv: func(string) string { return "" }, Home: e.home, Paths: e.paths,
			StdoutTTY: true, StdinTTY: true,
			Environ: []string{"PATH=" + os.Getenv("PATH")},
			ExecSSH: func(path string, argv, environ []string) error { gotArgv = argv; return nil },
		}
		code := cli.Run(context.Background(), args, env)
		return code, se.String()
	}
	// "web" is a prefix of web-1 and web-2, so the terminal asks which.
	if code, stderr := run("2\n", "root@web"); code != 0 {
		t.Fatalf("hop root@web: exit %d, stderr %q", code, stderr)
	}
	cfg := filepath.Join(e.paths.ConfigDir, "config")
	want := []string{"ssh", "-F", cfg, "-o", "HostName=127.0.0.1", "-o", "User=root", "--", "web-2"}
	if !slices.Equal(gotArgv, want) {
		t.Errorf("argv = %q\nwant   %q (the user typed before the picker must survive it)", gotArgv, want)
	}
	// No user typed, none added.
	if code, stderr := run("1\n", "web"); code != 0 {
		t.Fatalf("hop web: exit %d, stderr %q", code, stderr)
	}
	want = []string{"ssh", "-F", cfg, "-o", "HostName=127.0.0.1", "--", "web-1"}
	if !slices.Equal(gotArgv, want) {
		t.Errorf("argv = %q\nwant   %q", gotArgv, want)
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
	code, stdout, stderr := e.hop(t, "import", "ssh-config", "--yes", "--json", "--dry-run")
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

	if code, _, stderr := e.hop(t, "import", "ssh-config", "--yes"); code != 0 {
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
	leak     string // what the command "leak" prints
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

// allowNone makes the server accept a client that presents no credentials,
// as Tailscale SSH does for an identity it has already checked.
func (s *sshServer) allowNone() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.NoClientAuth = true
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
// 64 KB, ending in END), "sleep" (waits), "leak" (prints s.leak) and "leakerr"
// (prints s.leak to stderr). Anything else is recorded and exits 0. hop mcp's
// mcpEnvPrefix is recorded, then ignored.
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
		leak := s.leak
		s.mu.Unlock()
		// hop mcp puts its pager settings before every command.
		p.Command = strings.TrimPrefix(p.Command, mcpEnvPrefix)

		status := uint32(0)
		switch {
		case p.Command == "leak":
			ch.Write([]byte(leak))
		case p.Command == "leakerr":
			ch.Stderr().Write([]byte(leak))
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

// hop trust cannot read the key of a host behind a jump host, so every hint
// about an unpinned one says to pin it by hand with hop edit.
func TestUnpinnedHostBehindAJumpHostSaysHopEdit(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	snap, _ := e.store.Snapshot(ctx)
	var bastion model.Host
	for _, h := range snap.Hosts {
		if h.Name == "web-1" {
			bastion = h
		}
	}
	inner := bastion
	inner.Header, inner.Name, inner.JumpHostID, inner.HostKeys = model.Header{}, "inner", bastion.ItemID, nil
	inner.Addresses = []string{"127.0.0.1"}
	if _, err := e.store.PutHost(ctx, inner); err != nil {
		t.Fatal(err)
	}
	const fix = "hop edit inner --host-key"
	notTrust := func(what, out string) {
		t.Helper()
		if !strings.Contains(out, fix) || strings.Contains(out, "hop trust inner") {
			t.Errorf("%s: want the hint %q and no hop trust inner in:\n%s", what, fix, out)
		}
	}
	_, stdout, _ := e.hop(t, "check", "--json", "inner")
	for _, s := range decodeCheck(t, stdout).Steps {
		if s.Name == "host_key_pinned" {
			notTrust("hop check", s.Detail)
		}
	}
	_, stdout, _ = e.hop(t, "info", "inner")
	notTrust("hop info", stdout)
	_, _, stderr := e.hop(t, "exec", "inner", "--", "echo", "ok")
	if strings.Contains(stderr, "hop trust inner") {
		t.Errorf("hop exec: hop trust hint behind a jump host:\n%s", stderr)
	}
	_, _, stderr = e.hop(t, "add", "inner2", "--address", "127.0.0.1", "--key", "deploy-key", "--user", "deploy", "--jump", "web-1")
	if !strings.Contains(stderr, "hop edit inner2 --host-key") || strings.Contains(stderr, "hop trust inner2") {
		t.Errorf("hop add: want the hop edit hint in:\n%s", stderr)
	}
	// A host that is not behind a jump host still gets hop trust.
	if _, _, stderr := e.hop(t, "add", "direct2", "--address", "127.0.0.1", "--key", "deploy-key", "--user", "deploy"); !strings.Contains(stderr, "hop trust direct2") {
		t.Errorf("hop add without a jump host: want hop trust in:\n%s", stderr)
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

	code, stdout, stderr := e.hop(t, "import", "ssh-config", "--yes", "--with-keys", "--json")
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

// TestSetupBeatsAnEarlierStrictHostKeyCheckingNo runs the real ssh: a user
// config that starts with "StrictHostKeyChecking no" must not be able to
// switch off the pinning of a hop alias, so setup puts its Include above it.
func TestSetupBeatsAnEarlierStrictHostKeyCheckingNo(t *testing.T) {
	requireSSH(t)
	for _, tc := range []struct{ name, config string }{
		{"no include yet", "StrictHostKeyChecking no\n\nHost *\n  User someone\n"},
		// Where an earlier setup, or the user, put it: after the directive,
		// so ssh has already taken "no".
		{"include already below the directive", "StrictHostKeyChecking no\nInclude @INCLUDE@\n\nHost *\n  User someone\n"},
	} {
		t.Run(tc.name, func(t *testing.T) { setupBeatsStrictNo(t, tc.config) })
	}
}

func setupBeatsStrictNo(t *testing.T, config string) {
	t.Helper()
	base, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	home := filepath.Join(base, "home")
	// Not the default ~/.ssh/hop: ssh expands "~" from the passwd entry, not
	// from this test's home, so the include has to be an absolute path.
	cfgDir := filepath.Join(base, "hopcfg")
	for _, d := range []string{filepath.Join(home, ".ssh"), cfgDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	generated := "Host pinned\n  HostName 192.0.2.1\n  StrictHostKeyChecking yes\n  UpdateHostKeys no\n"
	if err := os.WriteFile(filepath.Join(cfgDir, "config"), []byte(generated), 0o600); err != nil {
		t.Fatal(err)
	}
	userCfg := filepath.Join(home, ".ssh", "config")
	config = strings.ReplaceAll(config, "@INCLUDE@", filepath.Join(cfgDir, "config"))
	if err := os.WriteFile(userCfg, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	effective := func() string {
		out, err := exec.Command("ssh", "-F", userCfg, "-G", "pinned").Output()
		if err != nil {
			t.Fatalf("ssh -G: %v", err)
		}
		for _, l := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(l, "stricthostkeychecking "); ok {
				return v
			}
		}
		t.Fatalf("no stricthostkeychecking in:\n%s", out)
		return ""
	}
	if got := effective(); got != "false" {
		t.Fatalf("before setup the user's config should win (false), got %q: the test would prove nothing", got)
	}

	var so, se bytes.Buffer
	env := &cli.Env{
		Stdin: strings.NewReader(""), Stdout: &so, Stderr: &se, Home: home,
		Getenv: func(string) string { return "" },
		Paths:  daemon.Paths{ConfigDir: cfgDir},
	}
	if code := cli.Run(context.Background(), []string{"setup", "--yes"}, env); code != 0 {
		t.Fatalf("setup: exit %d, %s", code, se.String())
	}
	if got := effective(); got != "true" {
		b, _ := os.ReadFile(userCfg)
		t.Errorf("effective stricthostkeychecking for the hop alias = %q after setup, want true\n%s", got, b)
	}
	// And the user's own settings are all still there.
	b, _ := os.ReadFile(userCfg)
	if !strings.Contains(string(b), "StrictHostKeyChecking no\n") || !strings.Contains(string(b), "Host *\n  User someone\n") ||
		strings.Count(string(b), "hopcfg") != 1 {
		t.Errorf("the user's config was damaged:\n%s", b)
	}
}

// writeSSHFile writes a file under the test home's ~/.ssh and returns its
// absolute path. Include lines in these configs use absolute paths: ssh
// expands "~" and relative paths from the passwd entry, not from the test home.
func (e *e2e) writeSSHFile(t *testing.T, name, body string) string {
	t.Helper()
	sshDir := filepath.Join(e.home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(sshDir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// importConfig writes cfg as the test home's ssh config and imports it.
func (e *e2e) importConfig(t *testing.T, cfg string, args ...string) cli.ImportReport {
	t.Helper()
	e.writeSSHFile(t, "config", cfg)
	code, stdout, stderr := e.hop(t, append([]string{"import", "ssh-config", "--yes", "--json"}, args...)...)
	if code != 0 {
		t.Fatalf("import: %d %s", code, stderr)
	}
	var rep cli.ImportReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	return rep
}

// hostEntries indexes the host lines of a report by name.
func hostEntries(rep cli.ImportReport) map[string]cli.ImportEntry {
	out := map[string]cli.ImportEntry{}
	for _, en := range rep.Entries {
		if en.Kind == "host" {
			out[en.Name] = en
		}
	}
	return out
}

// inVault reports whether hop knows the name.
func (e *e2e) inVault(t *testing.T, name string) bool {
	t.Helper()
	code, _, _ := e.hop(t, "info", name)
	return code == 0
}

// sshDefaultUser is the user ssh falls back to, as the real ssh reports it.
func sshDefaultUser(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("ssh", "-G", "-F", os.DevNull, "x")
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, passwdShimEnv()...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ssh -G: %v", err)
	}
	for _, l := range strings.Split(string(out), "\n") {
		if u, ok := strings.CutPrefix(l, "user "); ok {
			return strings.TrimSpace(u)
		}
	}
	t.Fatalf("no user in:\n%s", out)
	return ""
}

func (e *e2e) view(t *testing.T, name string) cli.HostView {
	t.Helper()
	code, stdout, stderr := e.hop(t, "info", "--json", name)
	if code != 0 {
		t.Fatalf("info %s: %d %s", name, code, stderr)
	}
	var v cli.HostView
	if err := json.Unmarshal([]byte(stdout), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// These tests run the real ssh -G over real configs: hop must import what
// ssh would do, not what a reimplementation of ssh_config thinks it would do.

func TestImportAppliesSettingsFromHostStar(t *testing.T) {
	e := newE2E(t)
	rep := e.importConfig(t, `Host *
  User everyone
  ServerAliveInterval 30

Host a
  HostName 192.0.2.1

Host b
  HostName 192.0.2.2
  Port 2200
  User own
`)
	for name, en := range hostEntries(rep) {
		if en.Status != "imported" {
			t.Errorf("%s: %+v, want imported", name, en)
		}
	}
	// The first value wins, and Host * comes first.
	if a := e.view(t, "a"); a.User != "everyone" || a.Port != 22 {
		t.Errorf("a = user %q port %d", a.User, a.Port)
	}
	if b := e.view(t, "b"); b.User != "everyone" || b.Port != 2200 {
		t.Errorf("b = user %q port %d: Host * sets the user first, the host sets the port", b.User, b.Port)
	}
	if w := strings.Join(rep.Warnings, "\n"); strings.Contains(w, "Host *") {
		t.Errorf("warnings = %q", w)
	}
}

func TestImportNegation(t *testing.T) {
	e := newE2E(t)
	rep := e.importConfig(t, `Host * !prod
  User generic

Host prod
  HostName 192.0.2.3

Host stage
  HostName 192.0.2.4

Host never !never
  HostName 192.0.2.5
`)
	st := hostEntries(rep)
	if st["prod"].Status != "imported" || st["stage"].Status != "imported" {
		t.Errorf("entries = %+v", st)
	}
	if v := e.view(t, "prod"); v.User != "" {
		t.Errorf("prod user = %q: the negated pattern keeps Host * off it", v.User)
	}
	if v := e.view(t, "stage"); v.User != "generic" {
		t.Errorf("stage user = %q", v.User)
	}
	// "never !never" matches nothing, so ssh gives that name no settings.
	if st["never"].Status != "skipped" || !strings.Contains(st["never"].Reason, "no Host line applies") || e.inVault(t, "never") {
		t.Errorf("never = %+v", st["never"])
	}
}

func TestImportIncludeInsideAHostBlock(t *testing.T) {
	e := newE2E(t)
	inc := e.writeSSHFile(t, "inc.conf", "HostName 192.0.2.6\nUser inc\n")
	e.importConfig(t, `Host nested
  Include `+inc+`
  Port 2202
  User outer

Host pre
  User first
  Include `+inc+`
`)
	if v := e.view(t, "nested"); v.User != "inc" || v.Port != 2202 || !slices.Equal(v.Addresses, []string{"192.0.2.6"}) {
		t.Errorf("nested = %+v: the included lines are in the block and come first", v)
	}
	if v := e.view(t, "pre"); v.User != "first" || !slices.Equal(v.Addresses, []string{"192.0.2.6"}) {
		t.Errorf("pre = %+v: its own User comes before the include", v)
	}
}

func TestImportConditionalInclude(t *testing.T) {
	e := newE2E(t)
	cond := e.writeSSHFile(t, "cond.conf", "User condu\nPort 2300\n")
	ghost := e.writeSSHFile(t, "ghost.conf", "Host ghost\n  HostName 192.0.2.99\n")
	rep := e.importConfig(t, `Match originalhost cond
  Include `+cond+`

Match originalhost nobody
  Include `+ghost+`

Host cond
  HostName 192.0.2.7

Host other
  HostName 192.0.2.8
`)
	if v := e.view(t, "cond"); v.User != "condu" || v.Port != 2300 {
		t.Errorf("cond = user %q port %d: the include holds for this name", v.User, v.Port)
	}
	if v := e.view(t, "other"); v.User != "" || v.Port != 22 {
		t.Errorf("other = user %q port %d: the include does not hold", v.User, v.Port)
	}
	// ghost is named by a file ssh never reads for it.
	if g := hostEntries(rep)["ghost"]; g.Status != "skipped" || e.inVault(t, "ghost") {
		t.Errorf("ghost = %+v", g)
	}
}

func TestImportSharedAliases(t *testing.T) {
	e := newE2E(t)
	e.importConfig(t, `Host b
  User only-b

Host a b
  User shared
  HostName 192.0.2.9

Host c d
  HostName 192.0.2.20
`)
	// a and b answer differently, so they are two hosts.
	if v := e.view(t, "a"); v.Name != "a" || v.User != "shared" {
		t.Errorf("a = %+v", v)
	}
	if v := e.view(t, "b"); v.Name != "b" || v.User != "only-b" || !slices.Equal(v.Addresses, []string{"192.0.2.9"}) {
		t.Errorf("b = %+v: the first value, from its own earlier block, wins", v)
	}
	// c and d answer alike, so d is c's alias.
	if v := e.view(t, "d"); v.Name != "c" {
		t.Errorf("d resolves to %q, want c", v.Name)
	}
}

func TestImportSkipsProxyCommand(t *testing.T) {
	e := newE2E(t)
	rep := e.importConfig(t, `Host viacmd
  HostName 192.0.2.10
  ProxyCommand ssh -W %h:%p gw

Host fine
  HostName 192.0.2.11
  ProxyCommand none
`)
	st := hostEntries(rep)
	if st["viacmd"].Status != "skipped" || !strings.Contains(st["viacmd"].Reason, "ProxyCommand") || e.inVault(t, "viacmd") {
		t.Errorf("viacmd = %+v", st["viacmd"])
	}
	if st["fine"].Status != "imported" {
		t.Errorf("fine = %+v", st["fine"])
	}
	if !strings.Contains(strings.Join(rep.Warnings, "\n"), "viacmd") {
		t.Errorf("warnings = %q", rep.Warnings)
	}
}

func TestImportKeepsOnlyIdentityFilesTheConfigNames(t *testing.T) {
	e := newE2E(t)
	e.importConfig(t, `Host explicit
  HostName 192.0.2.12
  IdentityFile ~/.ssh/id_ed25519

Host plain
  HostName 192.0.2.13

Host other
  HostName 192.0.2.14
  IdentityFile ~/.ssh/id_work
  IdentityFile %d/.ssh/%n_key
`)
	// An explicit value equal to ssh's default is not told from the default,
	// so it is not stored. The host behaves the same either way.
	if d := e.view(t, "explicit").Description; strings.Contains(d, "IdentityFile") {
		t.Errorf("explicit: %q: a file ssh tries by default is not stored", d)
	}
	if d := e.view(t, "plain").Description; strings.Contains(d, "IdentityFile") {
		t.Errorf("plain: %q: ssh's default identity files are not the host's", d)
	}
	other := e.view(t, "other").Description
	if !strings.Contains(other, filepath.Join(e.home, ".ssh", "id_work")) || !strings.Contains(other, filepath.Join(e.home, ".ssh", "other_key")) {
		t.Errorf("other: %q: tokens in IdentityFile are expanded", other)
	}
}

// What is a default is decided per host, against this ssh's own answer for an
// empty config: a block that names the default identity files does not make
// them the config's for a host that does not.
func TestImportDefaultIdentitiesAreNotContaminatedByAnotherBlock(t *testing.T) {
	e := newE2E(t)
	var named strings.Builder
	for _, f := range []string{"id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_xmss", "id_dsa"} {
		named.WriteString("  IdentityFile ~/.ssh/" + f + "\n")
	}
	rep := e.importConfig(t, "Host other\n  HostName 192.0.2.14\n"+named.String()+"\nHost plain\n  HostName 192.0.2.13\n", "--with-keys")
	if en := hostEntries(rep)["plain"]; en.Status != "imported" {
		t.Fatalf("plain: %+v", en)
	}
	if d := e.view(t, "plain").Description; strings.Contains(d, "IdentityFile") || e.view(t, "plain").Key != nil {
		t.Errorf("plain: %q: another block naming the default files made them its own", d)
	}
	for _, en := range rep.Entries {
		if en.Kind == "key" {
			t.Errorf("a key was imported for the defaults: %+v", en)
		}
	}
}

// ssh -G prints the local user whether or not the config says so; only a User
// that differs from what an empty config gives is the host's.
func TestImportKeepsOnlyAUserTheConfigNames(t *testing.T) {
	user := sshDefaultUser(t)
	e := newE2E(t)
	e.importConfig(t, "Host plain\n  HostName 192.0.2.13\n")
	if u := e.view(t, "plain").User; u != "" {
		t.Errorf("plain user = %q: ssh's own default is not the config's", u)
	}
	e = newE2E(t)
	e.importConfig(t, "Host sameuser\n  HostName 192.0.2.15\n  User "+user+"\n\nHost differs\n  HostName 192.0.2.16\n  User someone-else\n")
	// The limit: a User equal to the default cannot be told from the default.
	if u := e.view(t, "sameuser").User; u != "" {
		t.Errorf("sameuser user = %q: equal to ssh's default, so not stored", u)
	}
	if u := e.view(t, "differs").User; u != "someone-else" {
		t.Errorf("differs user = %q", u)
	}
}

// One block naming the local user as User does not make it explicit for a host
// of another block.
func TestImportUserOfOneBlockDoesNotLeakToAnother(t *testing.T) {
	user := sshDefaultUser(t)
	e := newE2E(t)
	e.importConfig(t, "Host other\n  HostName 192.0.2.17\n  User "+user+"\n\nHost plain\n  HostName 192.0.2.13\n")
	if u := e.view(t, "plain").User; u != "" {
		t.Errorf("plain user = %q: another block's User made the default explicit", u)
	}
}

// ssh -G runs Match exec commands. hop's scan only lists them: consent, given
// with --yes or at the prompt, is what lets ssh -G run at all.
func TestImportNeedsConsentBeforeRunningSSH(t *testing.T) {
	e := newE2E(t)
	marker := filepath.Join(e.base, "ran")
	included := e.writeSSHFile(t, "exec.conf", "Match originalhost h exec \"touch "+marker+"\"\n  User viaexec\n")
	host := "\n\nHost h\n  HostName 192.0.2.30\n"
	for name, cfg := range map[string]string{
		"in the config":    "Match originalhost h exec \"touch " + marker + "\"\n  User viaexec" + host,
		"in an Include":    "Include " + included + host,
		"after other args": "Match host h exec \"touch " + marker + "\"" + host,
		"negated":          "Match !exec \"touch " + marker + "\"\n  User viaexec" + host,
		"upper case":       "MATCH EXEC \"touch " + marker + "\"" + host,
		"quoted keyword":   "Match \"exec\" \"touch " + marker + "\"" + host,
		"split by quotes":  "Match \"!ex\"\"ec\" \"touch " + marker + "\"" + host,
		"all and exec":     "Match all exec \"touch " + marker + "\"" + host,
	} {
		e.writeSSHFile(t, "config", cfg)
		for _, args := range [][]string{{"import", "ssh-config"}, {"import", "ssh-config", "--dry-run"}, {"import", "ssh-config", "--json"}} {
			code, _, stderr := e.hop(t, args...)
			if code != 255 || !strings.Contains(stderr, "--yes") {
				t.Errorf("%s %v: code=%d stderr=%q, want a refusal that names --yes", name, args, code, stderr)
			}
			if !slices.Contains(args, "--json") && !strings.Contains(stderr, "touch "+marker) {
				t.Errorf("%s %v: the refusal does not show the Match exec line: %q", name, args, stderr)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatalf("%s %v: the Match exec command ran without consent", name, args)
			}
			if e.inVault(t, "h") {
				t.Fatalf("%s %v: something was imported", name, args)
			}
		}
	}

	// --yes is consent: ssh -G runs the command, and the output names the line.
	cfg := "Match originalhost h exec \"touch " + marker + "\"\n  User viaexec" + host
	rep := e.importConfig(t, cfg)
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("--yes: the command did not run, so ssh did not evaluate the Match: %v", err)
	}
	if v := e.view(t, "h"); v.User != "viaexec" {
		t.Errorf("h = %+v: the Match exec held", v)
	}
	cfgPath := filepath.Join(e.home, ".ssh", "config")
	if w := strings.Join(rep.Warnings, "\n"); !strings.Contains(w, "Match exec") || !strings.Contains(w, cfgPath+":1") || !strings.Contains(w, "touch "+marker) {
		t.Errorf("the JSON warnings do not name the Match exec line: %q", rep.Warnings)
	}
}

func TestImportYesPrintsTheFindingsInText(t *testing.T) {
	e := newE2E(t)
	marker := filepath.Join(e.base, "ran")
	cfgPath := e.writeSSHFile(t, "config", "Match originalhost h exec \"touch "+marker+"\"\n  User viaexec\n\nHost h\n  HostName 192.0.2.30\n")
	code, _, stderr := e.hop(t, "import", "ssh-config", "--yes")
	if code != 0 {
		t.Fatalf("import --yes: %d %s", code, stderr)
	}
	if !strings.Contains(stderr, cfgPath+":1: Match originalhost h exec") || strings.Count(stderr, "touch "+marker) != 1 {
		t.Errorf("stderr should list the Match exec line once: %q", stderr)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the command did not run: %v", err)
	}
}

func TestImportPrompt(t *testing.T) {
	e := newE2E(t)
	marker := filepath.Join(e.base, "ran")
	e.writeSSHFile(t, "config", "Match originalhost h exec \"touch "+marker+"\"\n  User viaexec\n\nHost h\n  HostName 192.0.2.30\n")
	before := e.vaultHostCount(t)
	e.tty = true
	defer func() { e.tty = false }()
	for _, answer := range []string{"n\n", "\n", "no\n", "maybe\n", ""} {
		e.stdin = answer
		code, _, stderr := e.hop(t, "import", "ssh-config")
		if code != 255 || !strings.Contains(stderr, "[y/N]") || !strings.Contains(stderr, "touch "+marker) {
			t.Errorf("answer %q: code=%d stderr=%q, want a refusal after showing the prompt and the Match exec line", answer, code, stderr)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("answer %q: the Match exec command ran", answer)
		}
		if e.vaultHostCount(t) != before {
			t.Fatalf("answer %q: something was imported", answer)
		}
	}
	// A terminal does not make --json interactive.
	e.stdin = "y\n"
	if code, _, stderr := e.hop(t, "import", "ssh-config", "--json"); code != 255 || !strings.Contains(stderr, "--yes") {
		t.Errorf("--json on a terminal: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("--json asked nothing and ran the command")
	}

	e.stdin = "y\n"
	code, stdout, stderr := e.hop(t, "import", "ssh-config")
	if code != 0 {
		t.Fatalf("answer y: %d %s", code, stderr)
	}
	if !strings.Contains(stdout, "imported") {
		t.Errorf("stdout = %q", stdout)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("answer y: the command did not run: %v", err)
	}
	if v := e.view(t, "h"); v.User != "viaexec" {
		t.Errorf("h = %+v", v)
	}
}

// A config hop finds nothing in still gets the question: hop's scan is best
// effort, and ssh is what reads the config.
func TestImportAsksEvenWhenTheScanFindsNothing(t *testing.T) {
	e := newE2E(t)
	marker := filepath.Join(e.base, "ssh-ran")
	e.sshBin = e.fakeSSH(t, "touch "+marker)
	e.writeSSHFile(t, "config", "Host a\n  HostName 192.0.2.1\n")
	code, _, stderr := e.hop(t, "import", "ssh-config")
	if code != 255 || !strings.Contains(stderr, "--yes") || !strings.Contains(stderr, "hop's scan is best effort") {
		t.Errorf("non-interactive: code=%d stderr=%q", code, stderr)
	}
	e.tty, e.stdin = true, "n\n"
	code, _, stderr = e.hop(t, "import", "ssh-config", "--dry-run")
	e.tty = false
	if code != 255 || !strings.Contains(stderr, "[y/N]") || !strings.Contains(stderr, "hop's scan is best effort") {
		t.Errorf("interactive n: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("ssh ran before the user agreed")
	}
	if e.inVault(t, "a") {
		t.Error("something was imported")
	}
	e.sshBin = ""
	rep := e.importConfig(t, "Host a\n  HostName 192.0.2.1\n")
	if en := hostEntries(rep)["a"]; en.Status != "imported" {
		t.Errorf("with --yes: a = %+v", en)
	}
}

// ssh -G runs Match exec commands, so they must see only HOME and PATH.
func TestImportRunsSSHWithABareEnvironment(t *testing.T) {
	e := newE2E(t)
	t.Setenv("HOPKEY_PROBE_LEAK", "leaked")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/leaked-agent")
	e.importConfig(t, `Match originalhost h exec "test -z ${HOPKEY_PROBE_LEAK} && test -z ${SSH_AUTH_SOCK}"
  User cleanenv

Host h
  HostName 192.0.2.31
`)
	if v := e.view(t, "h"); v.User != "cleanenv" {
		t.Errorf("h user = %q: the caller's environment reached ssh", v.User)
	}
}

func TestImportNeedsSSH(t *testing.T) {
	e := newE2E(t)
	e.writeSSHFile(t, "config", "Host a\n  HostName 192.0.2.1\n")
	e.sshBin = filepath.Join(e.base, "no-such-ssh")
	code, _, stderr := e.hop(t, "import", "ssh-config")
	if code != 255 || !strings.Contains(stderr, "OpenSSH") || !strings.Contains(stderr, "ssh -G") {
		t.Errorf("import without ssh: code=%d stderr=%q", code, stderr)
	}
	if e.inVault(t, "a") {
		t.Error("something was imported without ssh")
	}
}

func TestImportProxyJump(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	put := func(h model.Host) {
		t.Helper()
		h.Port, h.Route, h.AgentAccess = cmpOr(h.Port, 22), "auto", "allow"
		if _, err := e.store.PutHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	put(model.Host{Name: "gw", Addresses: []string{"198.51.100.1"}, User: "deploy", Port: 2200})
	put(model.Host{Name: "nouser", Addresses: []string{"198.51.100.2"}})
	// Two hosts that both answer to "twin" and to 198.51.100.9.
	put(model.Host{Name: "twin-a", Aliases: []string{"twin"}, Addresses: []string{"198.51.100.9"}})
	put(model.Host{Name: "twin-b", Aliases: []string{"twin"}, Addresses: []string{"198.51.100.9"}})

	rep := e.importConfig(t, `Host via-same
  HostName 192.0.2.11
  ProxyJump deploy@gw:2200

Host via-plain
  HostName 192.0.2.12
  ProxyJump gw

Host via-other-user
  HostName 192.0.2.13
  ProxyJump root@gw

Host via-other-port
  HostName 192.0.2.14
  ProxyJump gw:2222

Host via-user-on-nouser
  HostName 192.0.2.15
  ProxyJump bob@nouser

Host via-port-default
  HostName 192.0.2.16
  ProxyJump nouser:22

Host via-twin-name
  HostName 192.0.2.17
  ProxyJump twin

Host via-twin-address
  HostName 192.0.2.18
  ProxyJump 198.51.100.9

Host via-unknown
  HostName 192.0.2.19
  ProxyJump nowhere

Host via-two-hops
  HostName 192.0.2.21
  ProxyJump gw,nouser

Host via-none
  HostName 192.0.2.22
  ProxyJump none

Host base
  HostName 192.0.2.40
  User deploy

Host via-base
  HostName 192.0.2.41
  ProxyJump base

Host mid
  HostName 192.0.2.42
  ProxyJump nowhere

Host via-mid
  HostName 192.0.2.43
  ProxyJump mid

Host loop
  HostName 192.0.2.44
  ProxyJump loop
`)
	st := hostEntries(rep)
	imported := map[string]string{"via-same": "gw", "via-plain": "gw", "via-port-default": "nouser", "via-none": "", "via-base": "base", "base": ""}
	for name, jump := range imported {
		if st[name].Status != "imported" {
			t.Errorf("%s: %+v, want imported", name, st[name])
			continue
		}
		if got := e.view(t, name).JumpHost; got != jump {
			t.Errorf("%s: jump host = %q, want %q", name, got, jump)
		}
	}
	// A host whose jump cannot be reproduced is left out: imported without
	// it, it would connect where ssh goes through the jump.
	reasons := map[string]string{
		"via-other-user": `ProxyJump "root@gw"`, "via-other-port": `ProxyJump "gw:2222"`, "via-user-on-nouser": `ProxyJump "bob@nouser"`,
		"via-twin-name": "matches several hosts (twin-a, twin-b)", "via-twin-address": "matches several hosts",
		"via-unknown": `"nowhere" is not in the vault`, "via-two-hops": "several hops",
		"mid": `"nowhere" is not in the vault`, "via-mid": `"mid" is not in the vault`, "loop": "the host itself",
	}
	for name, why := range reasons {
		if st[name].Status != "skipped" || !strings.Contains(st[name].Reason, why) {
			t.Errorf("%s: %+v, want skipped for %q", name, st[name], why)
		}
		if e.inVault(t, name) {
			t.Errorf("%s was imported", name)
		}
	}
}

func cmpOr(v, def uint32) uint32 {
	if v == 0 {
		return def
	}
	return v
}

// TestKeylessTailscaleSSHHostOverRealSSH: a host with Tailscale SSH and no key
// is reached over the tailnet only, offers no key, and hop check does not
// probe it directly.
func TestKeylessTailscaleSSHHostOverRealSSH(t *testing.T) {
	// The tailnet address of the node is the loopback address of the test
	// server, so the real ssh gets somewhere.
	st := &tailscale.Status{
		Available: true, MagicDNSSuffix: "tn.ts.net",
		Self: tailscale.Node{ID: "nSELF", HostName: "laptop", DNSName: "laptop.tn.ts.net", Online: true, IPs: []string{"100.64.0.1"}, Self: true},
	}
	e := newE2EWith(t, fixedTS{st})
	e.server.allowNone()
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(e.server.hostKey)))
	st.Peers = []tailscale.Node{{ID: "nTS", HostName: "tshost", DNSName: "tshost.tn.ts.net", Online: true, IPs: []string{"127.0.0.1"}, SSHHostKeys: []string{pin}}}
	if _, err := e.store.PutHost(context.Background(), model.Host{
		Name: "ts-host", Addresses: []string{"203.0.113.77"}, Port: uint32(e.server.port), User: "deploy",
		Route: "auto", AgentAccess: "allow", HostKeys: []string{pin},
		Tailscale: &model.Tailscale{StableNodeID: "nTS", DNSName: "tshost.tn.ts.net", SSH: "yes"},
	}); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := e.hop(t, "which", "ts-host")
	if code != 0 || !strings.Contains(stdout, "127.0.0.1:"+strconv.Itoa(e.server.port)+" via tailnet (Tailscale SSH)") || strings.Contains(stdout, "fallback") {
		t.Errorf("which: code=%d\n%s%s", code, stdout, stderr)
	}
	code, stdout, _ = e.hop(t, "info", "ts-host")
	if code != 0 || !strings.Contains(stdout, "via tailnet (Tailscale SSH)") || !strings.Contains(stdout, "key:          none") {
		t.Errorf("info: code=%d\n%s", code, stdout)
	}
	v := e.view(t, "ts-host")
	if v.ChosenRoute == nil || !v.ChosenRoute.TailscaleSSH || v.ChosenRoute.Chosen != "tailnet" || v.ChosenRoute.Fallback != "" || v.SSHAlias != "ts-host" {
		t.Errorf("view = %+v / %+v", v, v.ChosenRoute)
	}

	// The generated block names no key file, and real ssh agrees.
	cfg := e.configFile(t)
	_, rest, _ := strings.Cut(cfg, "Host ts-host\n")
	block, _, _ := strings.Cut(rest, "\nHost ")
	if strings.Contains(block, "IdentityAgent") || strings.Contains(block, ".pub") || !strings.Contains(block, "IdentityFile none\n") ||
		!strings.Contains(block, "PubkeyAuthentication no\n") || !strings.Contains(block, "IdentitiesOnly yes") {
		t.Errorf("block:\n%s", block)
	}
	out, err := exec.Command("ssh", "-F", filepath.Join(e.paths.ConfigDir, "config"), "-G", "ts-host").Output()
	if err != nil {
		t.Fatalf("ssh -G: %v", err)
	}
	if !strings.Contains(string(out), "\nidentitiesonly yes\n") || !strings.Contains(string(out), "\npubkeyauthentication false\n") ||
		strings.Contains(string(out), filepath.Join(e.paths.ConfigDir, "keys")) {
		t.Errorf("ssh -G offers a hop key:\n%s", out)
	}

	// check: no probe from hop itself, and ssh gets in with no credentials.
	before := e.server.connections()
	code, stdout, stderr = e.hop(t, "check", "ts-host", "--json")
	if code != 0 {
		t.Fatalf("check: %d\n%s%s", code, stdout, stderr)
	}
	var res cli.CheckResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatal(err)
	}
	steps := map[string]cli.Step{}
	for _, s := range res.Steps {
		steps[s.Name] = s
	}
	for name, want := range map[string]string{"route": "pass", "tcp_reachable": "skipped", "host_key_pinned": "pass", "host_key_matches": "skipped", "auth_ok": "pass"} {
		if steps[name].Status != want {
			t.Errorf("step %s = %+v, want %s", name, steps[name], want)
		}
	}
	if !strings.Contains(steps["route"].Detail, "via tailnet (Tailscale SSH)") || !strings.Contains(steps["tcp_reachable"].Detail, "Tailscale SSH") {
		t.Errorf("details: route %q, tcp %q", steps["route"].Detail, steps["tcp_reachable"].Detail)
	}
	if got := e.server.connections() - before; got != 1 {
		t.Errorf("check made %d connections, want only ssh's own", got)
	}

	// And exec works the same way: no key, no direct address.
	if code, stdout, stderr := e.hop(t, "exec", "ts-host", "--", "echo", "ok"); code != 0 || stdout != "ok\n" {
		t.Errorf("exec: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

// ---- import: consent, tracing, provenance, save order ----

// importFails runs the import and returns its stderr; the import must have
// failed with hop's exit status.
func (e *e2e) importFails(t *testing.T, label string, args ...string) string {
	t.Helper()
	code, _, stderr := e.hop(t, append([]string{"import", "ssh-config"}, args...)...)
	if code != 255 {
		t.Fatalf("%s: code=%d stderr=%q, want a failure", label, code, stderr)
	}
	return stderr
}

func (e *e2e) vaultHostCount(t *testing.T) int {
	t.Helper()
	snap, err := e.store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return len(snap.Hosts)
}

// An Include hop cannot resolve or read is listed in the confirmation and in
// the report. ssh -G reads whatever it finds there; the user agreed to that.
func TestImportListsIncludesItCannotCheck(t *testing.T) {
	e := newE2E(t)
	unreadable := e.writeSSHFile(t, "locked.conf", "Host locked\n  User x\n")
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	canRead := false
	if f, err := os.Open(unreadable); err == nil {
		f.Close()
		canRead = true // root, say: the unreadable case proves nothing
	}
	host := "\n\nHost h\n  HostName 192.0.2.30\n"
	cases := map[string]struct{ cfg, want string }{
		"variable":       {"Include ${SITEDIR}/extra.conf" + host, "environment variable"},
		"another user":   {"Include ~bob/.ssh/extra.conf" + host, "~user"},
		"host token":     {"Include /etc/ssh/%h.conf" + host, "token"},
		"bad glob":       {"Include /nowhere/[" + host, "not a usable pattern"},
		"unreadable":     {"Include " + unreadable + host, "cannot be read"},
		"inside a block": {"Host z\n  Include ${SITEDIR}/z.conf" + host, "environment variable"},
	}
	if canRead {
		delete(cases, "unreadable")
	}
	before := e.vaultHostCount(t)
	for name, c := range cases {
		e.writeSSHFile(t, "config", c.cfg)
		stderr := e.importFails(t, name)
		if !strings.Contains(stderr, "Include") || !strings.Contains(stderr, c.want) || !strings.Contains(stderr, "--yes") {
			t.Errorf("%s: stderr = %q, want the Include (%q) listed and --yes named", name, stderr, c.want)
		}
		if e.vaultHostCount(t) != before {
			t.Fatalf("%s: something was imported without consent", name)
		}
		// With --yes the report carries the same list, and says what was not
		// enumerated. Whether ssh -G accepts the line is ssh's business.
		e.writeSSHFile(t, "config", c.cfg)
		code, stdout, stderr := e.hop(t, "import", "ssh-config", "--yes", "--json", "--dry-run")
		if code != 0 {
			t.Fatalf("%s --yes: %d %s", name, code, stderr)
		}
		var rep cli.ImportReport
		if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
			t.Fatalf("%v\n%s", err, stdout)
		}
		w := strings.Join(rep.Warnings, "\n")
		if !strings.Contains(w, "Include hop could not inspect") || !strings.Contains(w, c.want) || !strings.Contains(w, "not enumerated") {
			t.Errorf("%s: warnings = %q", name, rep.Warnings)
		}
	}

	rep := e.importConfig(t, "Include ${SITEDIR}/extra.conf"+host)
	if en := hostEntries(rep)["h"]; en.Status != "imported" {
		t.Errorf("with --yes: h = %+v", en)
	}
}

// A file the safety scan skips for aliases (hop's own generated config) is
// still scanned for what it makes ssh do.
func TestImportListsMatchExecInHopsOwnConfig(t *testing.T) {
	e := newE2E(t)
	marker := filepath.Join(e.base, "ran")
	if err := os.MkdirAll(e.paths.ConfigDir, 0o700); err != nil {
		t.Fatal(err)
	}
	gen := filepath.Join(e.paths.ConfigDir, "config")
	if err := os.WriteFile(gen, []byte("Match originalhost h exec \"touch "+marker+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.writeSSHFile(t, "config", "Include "+gen+"\n\nHost h\n  HostName 192.0.2.30\n")
	stderr := e.importFails(t, "exec in the excluded file")
	if !strings.Contains(stderr, "Match originalhost h exec") || !strings.Contains(stderr, gen+":1") {
		t.Errorf("stderr = %q", stderr)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the Match exec command ran")
	}
	code, stdout, stderr := e.hop(t, "import", "ssh-config", "--yes", "--json")
	if code != 0 {
		t.Fatalf("--yes: %d %s", code, stderr)
	}
	var out cli.ImportReport
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(out.Warnings, "\n"); !strings.Contains(w, gen+":1") {
		t.Errorf("warnings do not list the Match exec in hop's own config: %q", out.Warnings)
	}
}

// ssh expands ~ from the passwd entry. When that is not $HOME, hop says so and
// uses the passwd home for the default config and for the ssh -G child.
func TestImportUsesThePasswdHome(t *testing.T) {
	e := newE2E(t)
	alt := filepath.Join(e.base, "passwd-home")
	if err := os.MkdirAll(filepath.Join(alt, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Match exec sees the HOME of the child: it must be the passwd home.
	cfg := "Match originalhost h exec \"test $HOME = " + alt + "\"\n  User fromaltho\n\nHost h\n  HostName 192.0.2.30\n"
	if err := os.WriteFile(filepath.Join(alt, ".ssh", "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	e.passwdHome = alt
	rep := e.importConfigAt(t, "")
	if w := strings.Join(rep.Warnings, "\n"); !strings.Contains(w, alt) || !strings.Contains(w, "passwd") || !strings.Contains(w, e.home) {
		t.Errorf("no warning that the passwd home differs from $HOME: %q", rep.Warnings)
	}
	if v := e.view(t, "h"); v.User != "fromaltho" {
		t.Errorf("h = %+v: the default config or the child's HOME was not the passwd home", v)
	}
}

// importConfigAt imports without writing a config; with path "" it reads the
// default location.
func (e *e2e) importConfigAt(t *testing.T, path string, args ...string) cli.ImportReport {
	t.Helper()
	all := []string{"import", "ssh-config", "--yes", "--json"}
	if path != "" {
		all = append(all, path)
	}
	code, stdout, stderr := e.hop(t, append(all, args...)...)
	if code != 0 {
		t.Fatalf("import: %d %s", code, stderr)
	}
	var rep cli.ImportReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	return rep
}

// fakeSSH writes an executable that answers ssh -G with fixed settings and the
// debug output the script body adds. cfg holds the -F argument.
func (e *e2e) fakeSSH(t *testing.T, debug string) string {
	t.Helper()
	script := `#!/bin/sh
cfg=""
while [ $# -gt 0 ]; do
	if [ "$1" = "-F" ]; then cfg="$2"; shift; fi
	shift
done
echo "hostname 192.0.2.1"
echo "user fake"
echo "port 22"
` + debug
	p := filepath.Join(e.base, "fake-ssh")
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// If ssh's trace cannot say which Host blocks applied, hop does not guess.
func TestImportFailsClosedWhenTheTraceCannotBeRead(t *testing.T) {
	cfg := "Host a\n  HostName 192.0.2.1\n\nHost b\n  HostName 192.0.2.2\n"
	traced := `case "$cfg" in
*hop-trace*)
	echo "debug1: Reading configuration data $cfg" >&2
	echo "debug1: $cfg line 1: Applying options for hop-trace-probe" >&2
	;;
`
	for name, debug := range map[string]string{
		"no debug lines":            "",
		"unrelated debug lines":     `echo "debug1: nothing to see" >&2`,
		"reading but no apply line": `echo "debug1: Reading configuration data $cfg" >&2`,
		"apply line in a new form":  `echo "debug1: Reading configuration data $cfg" >&2; echo "debug1: Applying options for hop-trace-probe (cfg:1)" >&2`,
		// The test config is traced properly, the real ones are not.
		"only the first probe is traced": traced + `*) echo "debug1: nothing" >&2 ;;
esac`,
		"a real probe is garbled": traced + `*) echo "debug1: Reading configuration data $cfg" >&2; echo "debug1: $cfg Applying options for a" >&2 ;;
esac`,
	} {
		e := newE2E(t)
		e.sshBin = e.fakeSSH(t, debug)
		e.writeSSHFile(t, "config", cfg)
		before := e.vaultHostCount(t)
		for _, args := range [][]string{nil, {"--dry-run"}} {
			stderr := e.importFails(t, name, append([]string{"--yes"}, args...)...)
			if !strings.Contains(stderr, "can't verify which Host blocks applied with this OpenSSH version") {
				t.Errorf("%s %v: stderr = %q", name, args, stderr)
			}
			if e.vaultHostCount(t) != before {
				t.Fatalf("%s %v: something was imported", name, args)
			}
		}
	}
}

// Output hop drops cannot be read, and the line that says which Host blocks
// applied may be in it: a probe whose stderr overflowed stops the import.
func TestImportFailsClosedWhenTheTraceOverflows(t *testing.T) {
	cfg := "Host a\n  HostName 192.0.2.1\n\nHost b\n  HostName 192.0.2.2\n"
	noise := `head -c 1100000 /dev/zero | tr '\0' x >&2`
	applied := func(host string) string {
		return `echo "debug1: Reading configuration data $cfg" >&2; echo "debug1: $cfg line 1: Applying options for ` + host + `" >&2`
	}
	for name, debug := range map[string]string{
		// A valid trace first, then more than hop keeps.
		"the real probe": `case "$cfg" in
*hop-trace*) ` + applied("hop-trace-probe") + ` ;;
/dev/null) ;;
*) ` + applied("a") + `; ` + noise + ` ;;
esac`,
		"the defaults probe": `case "$cfg" in
*hop-trace*) ` + applied("hop-trace-probe") + ` ;;
/dev/null) ` + noise + ` ;;
*) ` + applied("a") + ` ;;
esac`,
		// Settings output that does not fit cannot be parsed as complete.
		"the real probe's stdout": `case "$cfg" in
*hop-trace*) ` + applied("hop-trace-probe") + ` ;;
/dev/null) ;;
*) ` + applied("a") + `; head -c 1100000 /dev/zero | tr '\0' x ;;
esac`,
		"the trace check": `case "$cfg" in
*hop-trace*) ` + applied("hop-trace-probe") + `; ` + noise + ` ;;
*) ` + applied("a") + ` ;;
esac`,
	} {
		e := newE2E(t)
		e.sshBin = e.fakeSSH(t, debug)
		e.writeSSHFile(t, "config", cfg)
		before := e.vaultHostCount(t)
		for _, args := range [][]string{{"--yes"}, {"--yes", "--dry-run"}} {
			stderr := e.importFails(t, name, args...)
			want := "can't verify which Host blocks applied with this OpenSSH version"
			if strings.HasSuffix(name, "stdout") {
				want = "can't read the settings ssh -G printed"
			}
			if !strings.Contains(stderr, want) || !strings.Contains(stderr, "nothing was imported") {
				t.Errorf("%s %v: stderr = %q", name, args, stderr)
			}
			if e.vaultHostCount(t) != before {
				t.Fatalf("%s %v: something was imported", name, args)
			}
		}
	}
}

// A Host line is found by file and line, not by the pattern ssh prints: for
// "Host * prod" ssh says it applied "*".
func TestImportHostLineWithAWildcardAndTheAlias(t *testing.T) {
	e := newE2E(t)
	inc := e.writeSSHFile(t, "inc.conf", "Host * incd\n  Port 2244\n")
	rep := e.importConfig(t, "Include "+inc+"\n\nHost * prod\n  User u\n\nHost other\n  HostName 192.0.2.50\n")
	st := hostEntries(rep)
	for _, n := range []string{"prod", "other", "incd"} {
		if st[n].Status != "imported" {
			t.Errorf("%s: %+v, want imported", n, st[n])
		}
	}
	if v := e.view(t, "prod"); v.User != "u" {
		t.Errorf("prod = %+v: Host * prod gives it User u", v)
	}
	if v := e.view(t, "other"); v.User != "u" {
		t.Errorf("other = %+v: Host * prod applies to every name", v)
	}
	if v := e.view(t, "incd"); v.Port != 2244 || v.User != "u" {
		t.Errorf("incd = %+v: the Host line is in an included file", v)
	}
}

// A wildcard line applies to a name that a different line also names; only the
// line that names it counts as ssh having reached it. Here "never" is named by
// a line that does not hold for it.
func TestImportDoesNotCountALineThatOnlyAppliedByWildcard(t *testing.T) {
	e := newE2E(t)
	rep := e.importConfig(t, "Host *\n  User wide\n\nHost gone !gone\n  HostName 192.0.2.60\n")
	if en := hostEntries(rep)["gone"]; en.Status != "skipped" || !strings.Contains(en.Reason, "no Host line applies") || e.inVault(t, "gone") {
		t.Errorf("gone = %+v: Host * applied, but no line naming it did", en)
	}
}

// Every host is written once, with its jump host already set, jump hosts first.
func TestImportSavesJumpHostsFirstAndWritesEachHostOnce(t *testing.T) {
	e := newE2E(t)
	before := e.store.Writes()
	// The chain is written backwards on purpose.
	rep := e.importConfig(t, `Host leaf
  HostName 192.0.2.71
  ProxyJump mid

Host mid
  HostName 192.0.2.72
  ProxyJump root

Host root
  HostName 192.0.2.73

Host alone
  HostName 192.0.2.74
`)
	for _, n := range []string{"leaf", "mid", "root", "alone"} {
		if en := hostEntries(rep)[n]; en.Status != "imported" {
			t.Errorf("%s: %+v", n, en)
		}
	}
	if got := e.store.Writes() - before; got != 4 {
		t.Errorf("%d store writes for 4 hosts: a host was written before its jump was set", got)
	}
	for n, jump := range map[string]string{"leaf": "mid", "mid": "root", "root": "", "alone": ""} {
		if got := e.view(t, n).JumpHost; got != jump {
			t.Errorf("%s jump host = %q, want %q", n, got, jump)
		}
	}
}

// If a jump host cannot be saved, the hosts behind it are not saved as direct
// ones.
func TestImportSkipsHostsWhoseJumpHostFailedToSave(t *testing.T) {
	e := newE2E(t)
	e.store.Persist = func(s model.Snapshot) error {
		for _, h := range s.Hosts {
			if h.Name == "gateway" {
				return errors.New("disk full")
			}
		}
		return nil
	}
	rep := e.importConfig(t, `Host app
  HostName 192.0.2.81
  ProxyJump gateway

Host app-two
  HostName 192.0.2.82
  ProxyJump gateway

Host gateway
  HostName 192.0.2.80

Host free
  HostName 192.0.2.83
`)
	st := hostEntries(rep)
	if st["gateway"].Status != "failed" || !strings.Contains(st["gateway"].Reason, "disk full") {
		t.Errorf("gateway = %+v", st["gateway"])
	}
	for _, n := range []string{"app", "app-two"} {
		if st[n].Status != "skipped" || !strings.Contains(st[n].Reason, "gateway") {
			t.Errorf("%s = %+v, want skipped for its jump host", n, st[n])
		}
		if e.inVault(t, n) {
			t.Errorf("%s was saved without its jump host", n)
		}
	}
	if st["free"].Status != "imported" || !e.inVault(t, "free") {
		t.Errorf("free = %+v: an unrelated host is unaffected", st["free"])
	}
}

// Hosts that jump through each other cannot be saved in any order.
func TestImportSkipsAJumpLoop(t *testing.T) {
	e := newE2E(t)
	rep := e.importConfig(t, `Host ring-a
  HostName 192.0.2.91
  ProxyJump ring-b

Host ring-b
  HostName 192.0.2.92
  ProxyJump ring-c

Host ring-c
  HostName 192.0.2.93
  ProxyJump ring-a

Host behind
  HostName 192.0.2.94
  ProxyJump ring-a
`)
	for _, n := range []string{"ring-a", "ring-b", "ring-c", "behind"} {
		if en := hostEntries(rep)[n]; en.Status != "skipped" || e.inVault(t, n) {
			t.Errorf("%s = %+v, want skipped", n, en)
		}
	}
}
