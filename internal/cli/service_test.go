package cli_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
)

// hop setup --service never runs systemctl or launchctl here: RunCommand
// records what it would run.

type serviceEnv struct {
	home  string
	paths daemon.Paths
	vars  map[string]string
	goos  string
	exe   string
	stdin string
	tty   bool
	ran   [][]string
	fail  string // a command whose first word and second word match fails
}

func newServiceEnv(t *testing.T, goos string) *serviceEnv {
	t.Helper()
	base, err := os.MkdirTemp("", "hks")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	return &serviceEnv{
		home: home, goos: goos, exe: "/opt/hop tools/hop%h$HOME",
		paths: daemon.Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(home, ".ssh", "hop"), StateDir: filepath.Join(base, "state")},
		vars:  map[string]string{},
	}
}

func (s *serviceEnv) hop(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var so, se bytes.Buffer
	env := &cli.Env{
		Stdin: strings.NewReader(s.stdin), Stdout: &so, Stderr: &se,
		Getenv: func(k string) string { return s.vars[k] },
		Home:   s.home, Paths: s.paths, StdinTTY: s.tty, StdoutTTY: s.tty,
		Executable: s.exe, GOOS: s.goos,
		RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
			argv := append([]string{name}, args...)
			s.ran = append(s.ran, argv)
			if s.fail != "" && strings.Join(argv, " ") == s.fail {
				return []byte("Failed to connect to bus\x1b[2J"), errors.New("exit status 1")
			}
			return nil, nil
		},
		StartDaemon: func() error { return errors.New("no daemon in this test") },
	}
	code = cli.Run(context.Background(), args, env)
	s.stdin = ""
	return code, so.String(), se.String()
}

// files lists every regular file under the home directory.
func (s *serviceEnv) files(t *testing.T) []string {
	t.Helper()
	var out []string
	filepath.WalkDir(s.home, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func TestSetupServiceSystemd(t *testing.T) {
	s := newServiceEnv(t, "linux")
	s.vars["XDG_RUNTIME_DIR"] = "/run/user/1000"
	s.vars["XDG_STATE_HOME"] = "relative/ignored"
	unit := filepath.Join(s.home, ".config", "systemd", "user", "hopkey.service")

	code, out, errOut := s.hop(t, "setup", "--service", "--yes")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "installed the systemd service") {
		t.Errorf("stdout %q", out)
	}
	if got := s.files(t); !slices.Equal(got, []string{unit}) {
		t.Errorf("files written = %q, want only %s", got, unit)
	}
	b, err := os.ReadFile(unit)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, want := range []string{
		"Written by hop setup --service",
		"\nExecStart=\"/opt/hop tools/hop%%h$$HOME\" daemon\n",
		"\nRestart=on-failure\n",
		"\nEnvironment=\"XDG_RUNTIME_DIR=/run/user/1000\"\n",
		"\nWantedBy=default.target\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("unit lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "XDG_STATE_HOME") {
		t.Errorf("a relative XDG_STATE_HOME went into the unit:\n%s", body)
	}
	want := [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "enable", "--now", "hopkey.service"}}
	if !slices.EqualFunc(s.ran, want, slices.Equal) {
		t.Errorf("ran %q, want %q", s.ran, want)
	}

	// Again: nothing to do.
	s.ran = nil
	code, out, _ = s.hop(t, "setup", "--service", "--yes")
	if code != 0 || !strings.Contains(out, "already installed") || len(s.ran) != 0 {
		t.Errorf("second run: exit %d, %q, ran %q", code, out, s.ran)
	}

	// Uninstall.
	s.ran = nil
	code, out, errOut = s.hop(t, "setup", "--service", "--uninstall", "--yes", "--json")
	if code != 0 {
		t.Fatalf("uninstall: exit %d: %s", code, errOut)
	}
	var res cli.ServiceResult
	decodeJSON(t, out, &res)
	if !res.Changed || res.Installed || res.Path != unit {
		t.Errorf("uninstall --json: %+v", res)
	}
	if _, err := os.Lstat(unit); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unit still there: %v", err)
	}
	want = [][]string{{"systemctl", "--user", "disable", "--now", "hopkey.service"}, {"systemctl", "--user", "daemon-reload"}}
	if !slices.EqualFunc(s.ran, want, slices.Equal) {
		t.Errorf("uninstall ran %q, want %q", s.ran, want)
	}
	s.ran = nil
	if code, out, _ := s.hop(t, "setup", "--service", "--uninstall", "--yes"); code != 0 || !strings.Contains(out, "no systemd service is installed") || len(s.ran) != 0 {
		t.Errorf("uninstall again: exit %d, %q, ran %q", code, out, s.ran)
	}
}

func TestSetupServiceUsesXDGConfigHome(t *testing.T) {
	s := newServiceEnv(t, "linux")
	cfg := filepath.Join(s.home, "cfg")
	s.vars["XDG_CONFIG_HOME"] = cfg
	if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if got := s.files(t); !slices.Equal(got, []string{filepath.Join(cfg, "systemd", "user", "hopkey.service")}) {
		t.Errorf("files = %q", got)
	}
}

func TestSetupServiceNeedsConfirmation(t *testing.T) {
	s := newServiceEnv(t, "linux")
	code, _, errOut := s.hop(t, "setup", "--service")
	if code != 255 || !strings.Contains(errOut, "--yes") {
		t.Errorf("no terminal: exit %d, %q", code, errOut)
	}
	s.tty, s.stdin = true, "n\n"
	if code, _, _ := s.hop(t, "setup", "--service"); code != 255 {
		t.Errorf("answered no: exit %d", code)
	}
	if len(s.files(t)) != 0 || len(s.ran) != 0 {
		t.Fatalf("changed something without consent: files %q, ran %q", s.files(t), s.ran)
	}
	s.tty, s.stdin = true, "y\n"
	if code, _, errOut := s.hop(t, "setup", "--service"); code != 0 || len(s.ran) != 2 {
		t.Errorf("answered yes: exit %d, %q, ran %q", code, errOut, s.ran)
	}
	if code, _, errOut := s.hop(t, "setup", "--uninstall"); code != 255 || !strings.Contains(errOut, "--uninstall goes with --service") {
		t.Errorf("--uninstall alone: exit %d, %q", code, errOut)
	}
}

func TestSetupServiceLeavesOtherFilesAlone(t *testing.T) {
	s := newServiceEnv(t, "linux")
	dir := filepath.Join(s.home, ".config", "systemd", "user")
	os.MkdirAll(dir, 0o700)
	unit := filepath.Join(dir, "hopkey.service")

	// A file of the same name that hop did not write.
	os.WriteFile(unit, []byte("[Service]\nExecStart=/bin/true\n"), 0o644)
	for _, args := range [][]string{{"setup", "--service", "--yes"}, {"setup", "--service", "--uninstall", "--yes"}} {
		if code, _, errOut := s.hop(t, args...); code != 255 || !strings.Contains(errOut, "hop") {
			t.Errorf("%q: exit %d, %q", args, code, errOut)
		}
	}
	if b, _ := os.ReadFile(unit); string(b) != "[Service]\nExecStart=/bin/true\n" {
		t.Errorf("the user's file changed: %q", b)
	}

	// A symlink: never written through, never removed.
	os.Remove(unit)
	target := filepath.Join(s.home, "elsewhere")
	os.WriteFile(target, []byte("keep"), 0o644)
	if err := os.Symlink(target, unit); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"setup", "--service", "--yes"}, {"setup", "--service", "--uninstall", "--yes"}} {
		if code, _, errOut := s.hop(t, args...); code != 255 || !strings.Contains(errOut, "not a regular file") {
			t.Errorf("%q: exit %d, %q", args, code, errOut)
		}
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("wrote through the symlink: %q", b)
	}
	if len(s.ran) != 0 {
		t.Errorf("ran %q", s.ran)
	}
}

func TestSetupServiceReportsAFailedCommand(t *testing.T) {
	s := newServiceEnv(t, "linux")
	s.fail = "systemctl --user daemon-reload"
	code, _, errOut := s.hop(t, "setup", "--service", "--yes")
	if code != 255 || !strings.Contains(errOut, "Failed to connect to bus") || !strings.Contains(errOut, "but systemctl --user daemon-reload failed") {
		t.Errorf("exit %d, %q", code, errOut)
	}
	assertNoForgery(t, "stderr", errOut)
	if len(s.ran) != 1 {
		t.Errorf("kept going after a failure: %q", s.ran)
	}
}

func TestSetupServiceLaunchd(t *testing.T) {
	s := newServiceEnv(t, "darwin")
	s.exe = "/Applications/Hop & <Co>/hop"
	s.vars["XDG_DATA_HOME"] = "/Users/me/data"
	plist := filepath.Join(s.home, "Library", "LaunchAgents", "com.github.dalyem.hopkey.plist")
	code, out, errOut := s.hop(t, "setup", "--service", "--yes", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var res cli.ServiceResult
	decodeJSON(t, out, &res)
	if res.Service != "launchd" || res.Path != plist || !res.Changed || !res.Installed {
		t.Errorf("--json: %+v", res)
	}
	if got := s.files(t); !slices.Equal(got, []string{plist}) {
		t.Errorf("files = %q", got)
	}
	b, _ := os.ReadFile(plist)
	body := string(b)
	for _, want := range []string{
		"<string>/Applications/Hop &amp; &lt;Co&gt;/hop</string>\n\t\t<string>daemon</string>",
		"<key>SuccessfulExit</key>\n\t\t<false/>",
		"<key>RunAtLoad</key>\n\t<true/>",
		"<key>XDG_DATA_HOME</key>\n\t\t<string>/Users/me/data</string>",
		"<string>" + s.paths.LogFile() + "</string>",
		"Written by hop setup --service",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("plist lacks %q:\n%s", want, body)
		}
	}
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	if want := [][]string{{"launchctl", "bootstrap", domain, plist}}; !slices.EqualFunc(s.ran, want, slices.Equal) {
		t.Errorf("ran %q, want %q", s.ran, want)
	}
	if fi, err := os.Stat(s.paths.StateDir); err != nil || !fi.IsDir() {
		t.Errorf("the log directory launchd writes to is missing: %v", err)
	}

	s.ran = nil
	if code, _, errOut := s.hop(t, "setup", "--service", "--uninstall", "--yes"); code != 0 {
		t.Fatalf("uninstall: exit %d: %s", code, errOut)
	}
	if want := [][]string{{"launchctl", "bootout", domain, plist}}; !slices.EqualFunc(s.ran, want, slices.Equal) {
		t.Errorf("uninstall ran %q, want %q", s.ran, want)
	}
	if _, err := os.Lstat(plist); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("plist still there: %v", err)
	}
}

func TestSetupServiceElsewhere(t *testing.T) {
	s := newServiceEnv(t, "windows")
	if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 255 || !strings.Contains(errOut, "not windows") {
		t.Errorf("exit %d, %q", code, errOut)
	}
	s = newServiceEnv(t, "linux")
	s.exe = ""
	if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 255 || !strings.Contains(errOut, "where the hop binary is") {
		t.Errorf("no executable: exit %d, %q", code, errOut)
	}
	if len(s.files(t)) != 0 || len(s.ran) != 0 {
		t.Errorf("files %q, ran %q", s.files(t), s.ran)
	}
}
