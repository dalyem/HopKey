package cli_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
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
// records what it would run and answers as a fake service manager.

type serviceEnv struct {
	home  string
	paths daemon.Paths
	vars  map[string]string
	goos  string
	exe   string
	stdin string
	tty   bool
	ran   [][]string
	fail  string // a command that is exactly this fails, and changes nothing
	mgr   fakeManager
}

// fakeManager is systemd --user or launchd for one service, as far as hop
// setup --service can tell: it reads the service file only when real one
// does (daemon-reload; bootstrap), and runs a daemon from what it read.
// A launchd bootstrap does not count as starting the daemon: what
// RunAtLoad starts may exit at once (the old daemon still holds the
// vault), and only kickstart is sure to run one.
type fakeManager struct {
	loaded     bool
	loadedDef  string // the file as the manager read it
	enabled    bool
	running    bool
	runningDef string // what the running daemon was started from
	starts     int
	// notLoadedCode is the exit status of a bootout of an agent launchd
	// does not have: 3 (No such process) or, by default, 113.
	notLoadedCode int
}

// String leaves out the file contents, which only make failures long.
func (m fakeManager) String() string {
	return fmt.Sprintf("{loaded %v, enabled %v, running %v, starts %d}", m.loaded, m.enabled, m.running, m.starts)
}

// exitStatus is a failed command, with its exit status as os/exec has it.
type exitStatus int

func (c exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(c)) }
func (c exitStatus) ExitCode() int { return int(c) }

func (s *serviceEnv) servicePath() string {
	if s.goos == "darwin" {
		return filepath.Join(s.home, "Library", "LaunchAgents", "com.github.dalyem.hopkey.plist")
	}
	cfg := s.vars["XDG_CONFIG_HOME"]
	if cfg == "" {
		cfg = filepath.Join(s.home, ".config")
	}
	return filepath.Join(cfg, "systemd", "user", "hopkey.service")
}

// runsCurrent says the manager runs a daemon from the file as it is now.
func (s *serviceEnv) runsCurrent(t *testing.T) bool {
	t.Helper()
	b, err := os.ReadFile(s.servicePath())
	return err == nil && s.mgr.running && s.mgr.runningDef == string(b)
}

func (s *serviceEnv) manage(argv []string) ([]byte, error) {
	m := &s.mgr
	read := func() (string, bool) {
		b, err := os.ReadFile(s.servicePath())
		return string(b), err == nil
	}
	start := func() { m.running, m.runningDef = true, m.loadedDef; m.starts++ }
	label := fmt.Sprintf("gui/%d/com.github.dalyem.hopkey", os.Getuid())
	switch cmd := strings.Join(argv, " "); cmd {
	case "systemctl --user daemon-reload":
		// A running unit stays loaded when its file goes.
		if def, ok := read(); ok {
			m.loaded, m.loadedDef = true, def
		} else if !m.running {
			m.loaded, m.loadedDef = false, ""
		}
	case "systemctl --user enable hopkey.service":
		if _, ok := read(); !ok {
			return []byte("Failed to enable unit: Unit file hopkey.service does not exist."), exitStatus(1)
		}
		m.enabled = true
	case "systemctl --user enable --now hopkey.service":
		// What 244207f ran: it starts a stopped unit, and leaves a running
		// one on the unit it started from.
		if _, ok := read(); !ok || !m.loaded {
			return []byte("Failed to enable unit: Unit file hopkey.service does not exist."), exitStatus(1)
		}
		m.enabled = true
		if !m.running {
			start()
		}
	case "systemctl --user restart hopkey.service":
		if !m.loaded {
			return []byte("Failed to restart hopkey.service: Unit hopkey.service not found."), exitStatus(5)
		}
		start()
	case "systemctl --user disable --now hopkey.service":
		if _, ok := read(); !ok {
			return []byte("Failed to disable unit: Unit file hopkey.service does not exist."), exitStatus(1)
		}
		m.enabled, m.running = false, false
	case "systemctl --user stop hopkey.service":
		if !m.loaded {
			return []byte("Failed to stop hopkey.service: Unit hopkey.service not loaded."), exitStatus(5)
		}
		m.running = false
	case "launchctl bootout " + label:
		if !m.loaded {
			code := m.notLoadedCode
			if code == 0 {
				code = 113
			}
			return []byte(fmt.Sprintf("Boot-out failed: %d: No such process", code)), exitStatus(code)
		}
		m.loaded, m.running = false, false
	case "launchctl bootstrap " + fmt.Sprintf("gui/%d ", os.Getuid()) + s.servicePath():
		if m.loaded {
			return []byte("Bootstrap failed: 5: Input/output error"), exitStatus(5)
		}
		def, ok := read()
		if !ok {
			return []byte("Bootstrap failed: 2: No such file or directory"), exitStatus(2)
		}
		m.loaded, m.loadedDef = true, def
	case "launchctl kickstart -k " + label:
		if !m.loaded {
			return []byte("Could not find service \"com.github.dalyem.hopkey\" in domain for user gui: 501"), exitStatus(113)
		}
		start()
	default:
		return []byte("fake service manager: unknown command " + cmd), exitStatus(64)
	}
	return nil, nil
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
			return s.manage(argv)
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
	want := [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "enable", "hopkey.service"}, {"systemctl", "--user", "restart", "hopkey.service"}}
	if !slices.EqualFunc(s.ran, want, slices.Equal) {
		t.Errorf("ran %q, want %q", s.ran, want)
	}
	if !s.runsCurrent(t) || !s.mgr.enabled {
		t.Errorf("the service does not run the unit: %+v", s.mgr)
	}

	// Again: the file stays, and systemd is asked again to reload, enable
	// and restart it, since a file in place does not say the service runs.
	s.ran = nil
	code, out, _ = s.hop(t, "setup", "--service", "--yes")
	if code != 0 || !strings.Contains(out, "already installed") || !slices.EqualFunc(s.ran, want, slices.Equal) {
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
	stop := [][]string{{"systemctl", "--user", "disable", "--now", "hopkey.service"}, {"systemctl", "--user", "stop", "hopkey.service"}}
	want = append(slices.Clone(stop), []string{"systemctl", "--user", "daemon-reload"})
	if !slices.EqualFunc(s.ran, want, slices.Equal) {
		t.Errorf("uninstall ran %q, want %q", s.ran, want)
	}
	if s.mgr.running || s.mgr.enabled || res.Active {
		t.Errorf("still running after uninstall: %+v, %+v", s.mgr, res)
	}
	// Again: nothing to remove, but hop still makes sure it is stopped.
	s.ran = nil
	if code, out, _ := s.hop(t, "setup", "--service", "--uninstall", "--yes"); code != 0 || !strings.Contains(out, "no systemd service is installed") || !slices.EqualFunc(s.ran, stop, slices.Equal) {
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
	if code, _, errOut := s.hop(t, "setup", "--service"); code != 0 || len(s.ran) != 3 {
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
	if res.Service != "launchd" || res.Path != plist || !res.Changed || !res.Installed || !res.Active {
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
		"Written by hop setup (service)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("plist lacks %q:\n%s", want, body)
		}
	}
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	target := domain + "/com.github.dalyem.hopkey"
	if want := [][]string{{"launchctl", "bootout", target}, {"launchctl", "bootstrap", domain, plist}, {"launchctl", "kickstart", "-k", target}}; !slices.EqualFunc(s.ran, want, slices.Equal) {
		t.Errorf("ran %q, want %q", s.ran, want)
	}
	if !s.runsCurrent(t) {
		t.Errorf("launchd does not run the plist: %+v", s.mgr)
	}
	if fi, err := os.Stat(s.paths.StateDir); err != nil || !fi.IsDir() {
		t.Errorf("the log directory launchd writes to is missing: %v", err)
	}

	s.ran = nil
	if code, _, errOut := s.hop(t, "setup", "--service", "--uninstall", "--yes"); code != 0 {
		t.Fatalf("uninstall: exit %d: %s", code, errOut)
	}
	if want := [][]string{{"launchctl", "bootout", target}}; !slices.EqualFunc(s.ran, want, slices.Equal) {
		t.Errorf("uninstall ran %q, want %q", s.ran, want)
	}
	if s.mgr.loaded || s.mgr.running {
		t.Errorf("still loaded after uninstall: %+v", s.mgr)
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

// plistValue is one element of a property list, with what it holds.
type plistValue struct {
	XMLName xml.Name
	Text    string       `xml:",chardata"`
	Items   []plistValue `xml:",any"`
}

// parsePlist reads a whole property list with encoding/xml, which, like
// plutil -lint, refuses "--" inside a comment, and returns the top dict:
// each key with the text of its value, a string or a list of strings
// (nil for other values).
func parsePlist(t *testing.T, body string) map[string][]string {
	t.Helper()
	// Every token to the end, so nothing before or after the root escapes
	// the check.
	d := xml.NewDecoder(strings.NewReader(body))
	for {
		_, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("the plist is not XML: %v\n%s", err, body)
		}
	}
	var doc struct {
		XMLName xml.Name   `xml:"plist"`
		Dict    plistValue `xml:"dict"`
	}
	if err := xml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("the plist does not decode: %v\n%s", err, body)
	}
	items := doc.Dict.Items
	if len(items)%2 != 0 {
		t.Fatalf("the top dict has an odd number of elements:\n%s", body)
	}
	top := map[string][]string{}
	for i := 0; i < len(items); i += 2 {
		k, v := items[i], items[i+1]
		if k.XMLName.Local != "key" || v.XMLName.Local == "key" {
			t.Fatalf("element %d of the top dict is %s, then %s; want a key, then a value", i, k.XMLName.Local, v.XMLName.Local)
		}
		if _, dup := top[k.Text]; dup {
			t.Errorf("key %q twice", k.Text)
		}
		top[k.Text] = nil
		switch v.XMLName.Local {
		case "string":
			top[k.Text] = []string{v.Text}
		case "array":
			for _, el := range v.Items {
				top[k.Text] = append(top[k.Text], el.Text)
			}
		}
	}
	return top
}

// parseUnit reads a systemd unit: comments, blank lines, [Section]
// headers and KEY=VALUE lines inside a section, nothing else.
func parseUnit(t *testing.T, body string) map[string]map[string][]string {
	t.Helper()
	if !strings.HasSuffix(body, "\n") {
		t.Errorf("the unit does not end in a newline")
	}
	out := map[string]map[string][]string{}
	section := ""
	sc := bufio.NewScanner(strings.NewReader(body))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = line[1 : len(line)-1]
			if out[section] != nil {
				t.Errorf("line %d: section %s twice", n, section)
			}
			out[section] = map[string][]string{}
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok || section == "" || k == "" || strings.ContainsAny(k, " \t") {
				t.Errorf("line %d is not KEY=VALUE in a section: %q", n, line)
				continue
			}
			out[section][k] = append(out[section][k], v)
		}
	}
	return out
}

// Both generated files parse as what the service manager reads, whatever
// the paths in them hold.
func TestSetupServiceFilesParse(t *testing.T) {
	s := newServiceEnv(t, "darwin")
	s.exe = "/opt/hop--tools/<b>&\"q'/hop"
	s.vars["XDG_RUNTIME_DIR"] = "/run/user/1000--x"
	if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	b, err := os.ReadFile(filepath.Join(s.home, "Library", "LaunchAgents", "com.github.dalyem.hopkey.plist"))
	if err != nil {
		t.Fatal(err)
	}
	top := parsePlist(t, string(b))
	if got := top["Label"]; !slices.Equal(got, []string{"com.github.dalyem.hopkey"}) {
		t.Errorf("Label = %q", got)
	}
	if got := top["ProgramArguments"]; !slices.Equal(got, []string{s.exe, "daemon"}) {
		t.Errorf("ProgramArguments = %q", got)
	}
	for _, k := range []string{"EnvironmentVariables", "RunAtLoad", "KeepAlive", "StandardOutPath", "StandardErrorPath", "ProcessType"} {
		if _, ok := top[k]; !ok {
			t.Errorf("no %s in %v", k, top)
		}
	}
	if !strings.Contains(string(b), "<!-- Written by hop setup (service)") {
		t.Errorf("no ownership comment:\n%s", b)
	}

	s = newServiceEnv(t, "linux")
	s.vars["XDG_RUNTIME_DIR"] = "/run/user/1000"
	if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	b, err = os.ReadFile(filepath.Join(s.home, ".config", "systemd", "user", "hopkey.service"))
	if err != nil {
		t.Fatal(err)
	}
	unit := parseUnit(t, string(b))
	if got := unit["Service"]["ExecStart"]; len(got) != 1 || got[0] != `"/opt/hop tools/hop%%h$$HOME" daemon` {
		t.Errorf("ExecStart = %q", got)
	}
	if got := unit["Install"]["WantedBy"]; !slices.Equal(got, []string{"default.target"}) {
		t.Errorf("WantedBy = %q", got)
	}
	if len(unit) != 3 || unit["Unit"]["Description"] == nil {
		t.Errorf("sections %v", unit)
	}
}

// A run that wrote the file and then failed to start the service is not
// "already installed" when run again: the retry asks the service manager
// again, and succeeds when it does.
func TestSetupServiceRetryAfterAFailure(t *testing.T) {
	s := newServiceEnv(t, "linux")
	enable := []string{"systemctl", "--user", "enable", "hopkey.service"}
	s.fail = strings.Join(enable, " ")
	if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 255 || !strings.Contains(errOut, "enable hopkey.service failed") {
		t.Fatalf("first run: exit %d, %q", code, errOut)
	}
	s.fail, s.ran = "", nil
	code, out, errOut := s.hop(t, "setup", "--service", "--yes", "--json")
	if code != 0 {
		t.Fatalf("retry: exit %d: %s", code, errOut)
	}
	var res cli.ServiceResult
	decodeJSON(t, out, &res)
	if res.Changed || !res.Active || !res.Installed {
		t.Errorf("retry --json: %+v", res)
	}
	want := [][]string{{"systemctl", "--user", "daemon-reload"}, enable, {"systemctl", "--user", "restart", "hopkey.service"}}
	if !slices.EqualFunc(s.ran, want, slices.Equal) || !s.runsCurrent(t) {
		t.Errorf("retry ran %q, want %q; manager %+v", s.ran, want, s.mgr)
	}
	// Still failing: the retry says so, and says the file is in place.
	s.fail = strings.Join(enable, " ")
	if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 255 || !strings.Contains(errOut, "is in place, but") {
		t.Errorf("failing retry: exit %d, %q", code, errOut)
	}
}

// An updated plist whose first bootout fails: the run fails, saying
// which step, and launchd keeps running the old daemon. The retry repeats
// every step and leaves launchd running the new plist.
func TestSetupServiceLaunchdUpdateRetry(t *testing.T) {
	s := newServiceEnv(t, "darwin")
	target := fmt.Sprintf("gui/%d/com.github.dalyem.hopkey", os.Getuid())
	all := [][]string{{"launchctl", "bootout", target}, {"launchctl", "bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), s.servicePath()}, {"launchctl", "kickstart", "-k", target}}
	if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 0 {
		t.Fatalf("install: exit %d: %s", code, errOut)
	}
	oldDef := s.mgr.runningDef
	s.exe = "/opt/hop2/hop"
	s.fail, s.ran = strings.Join(all[0], " "), nil
	code, out, errOut := s.hop(t, "setup", "--service", "--yes", "--json")
	if code != 255 || !strings.Contains(errOut, "launchctl bootout "+target+" failed") || !strings.Contains(errOut, "again to retry") || strings.Contains(out, `"active"`) {
		t.Errorf("failing bootout: exit %d, %q, %q", code, out, errOut)
	}
	if !slices.EqualFunc(s.ran, all[:1], slices.Equal) || s.mgr.runningDef != oldDef || s.runsCurrent(t) {
		t.Errorf("after the failure: ran %q, manager %+v", s.ran, s.mgr)
	}
	s.fail, s.ran = "", nil
	if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 0 || !slices.EqualFunc(s.ran, all, slices.Equal) || !s.runsCurrent(t) {
		t.Errorf("retry: exit %d, %q, ran %q, manager %+v", code, errOut, s.ran, s.mgr)
	}
}

// A loaded agent whose daemon exited: running setup again starts it, from
// the plist as it is.
func TestSetupServiceLaunchdStartsAnExitedDaemon(t *testing.T) {
	for _, code := range []int{3, 113} {
		s := newServiceEnv(t, "darwin")
		s.mgr.notLoadedCode = code // what bootout says on the first install
		if c, _, errOut := s.hop(t, "setup", "--service", "--yes"); c != 0 {
			t.Fatalf("install (bootout exit %d when not loaded): exit %d: %s", code, c, errOut)
		}
		s.mgr.running = false
		if c, out, errOut := s.hop(t, "setup", "--service", "--yes"); c != 0 || !strings.Contains(out, "already installed") || !s.runsCurrent(t) {
			t.Errorf("exited daemon: exit %d, %q %q, manager %+v", c, out, errOut, s.mgr)
		}
	}
}

// Each step failing in turn fails the run, names the step, and stops
// there; the next run repeats every step and succeeds.
func TestSetupServiceEveryStepCanFail(t *testing.T) {
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	target := domain + "/com.github.dalyem.hopkey"
	stepsFor := func(s *serviceEnv) [][]string {
		if s.goos == "darwin" {
			return [][]string{{"launchctl", "bootout", target}, {"launchctl", "bootstrap", domain, s.servicePath()}, {"launchctl", "kickstart", "-k", target}}
		}
		return [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "enable", "hopkey.service"}, {"systemctl", "--user", "restart", "hopkey.service"}}
	}
	for _, goos := range []string{"linux", "darwin"} {
		for i := range 3 {
			for _, fresh := range []bool{true, false} {
				s := newServiceEnv(t, goos)
				steps := stepsFor(s)
				step := steps[i]
				if !fresh {
					if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 0 {
						t.Fatalf("%s install: exit %d: %s", goos, code, errOut)
					}
					s.mgr.running = false // so a run that stops early cannot pass for one that started it
				}
				s.fail, s.ran = strings.Join(step, " "), nil
				code, out, errOut := s.hop(t, "setup", "--service", "--yes", "--json")
				if code != 255 || !strings.Contains(errOut, strings.Join(step, " ")+" failed") || strings.Contains(out, `"active"`) {
					t.Errorf("%s step %d fails (fresh %v): exit %d, %q, %q", goos, i, fresh, code, out, errOut)
				}
				if !slices.EqualFunc(s.ran, steps[:i+1], slices.Equal) || s.runsCurrent(t) {
					t.Errorf("%s step %d fails (fresh %v): ran %q, manager %+v", goos, i, fresh, s.ran, s.mgr)
				}
				s.fail, s.ran = "", nil
				code, out, errOut = s.hop(t, "setup", "--service", "--yes", "--json")
				var res cli.ServiceResult
				if code == 0 {
					decodeJSON(t, out, &res)
				}
				if code != 0 || !res.Active || !slices.EqualFunc(s.ran, steps, slices.Equal) || !s.runsCurrent(t) {
					t.Errorf("%s step %d retry (fresh %v): exit %d, %q, ran %q, manager %+v", goos, i, fresh, code, errOut, s.ran, s.mgr)
				}
			}
		}
	}
}

// A changed unit restarts the daemon systemd is running, so it runs the
// new unit; so does a run with the same unit.
func TestSetupServiceSystemdRestartsOnChange(t *testing.T) {
	s := newServiceEnv(t, "linux")
	if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 0 {
		t.Fatalf("install: exit %d: %s", code, errOut)
	}
	s.exe = "/opt/hop2/hop"
	code, out, errOut := s.hop(t, "setup", "--service", "--yes")
	if code != 0 || !strings.Contains(out, "installed the systemd service") || !s.runsCurrent(t) || s.mgr.starts != 2 {
		t.Errorf("changed unit: exit %d, %q %q, manager %+v", code, out, errOut, s.mgr)
	}
	if !strings.Contains(s.mgr.runningDef, "/opt/hop2/hop") {
		t.Errorf("the daemon runs %q", s.mgr.runningDef)
	}
	if !strings.Contains(errOut, "hop daemon stop, then hop setup --service again") {
		t.Errorf("no note on a daemon started some other way:\n%s", errOut)
	}
	if code, _, _ := s.hop(t, "setup", "--service", "--yes"); code != 0 || s.mgr.starts != 3 {
		t.Errorf("same unit: exit %d, manager %+v", code, s.mgr)
	}
}

// A stop that fails leaves the file and says the service may be running;
// the retry stops it and removes the file.
func TestSetupServiceUninstallStopFails(t *testing.T) {
	target := fmt.Sprintf("gui/%d/com.github.dalyem.hopkey", os.Getuid())
	for goos, stop := range map[string]string{"linux": "systemctl --user disable --now hopkey.service", "darwin": "launchctl bootout " + target} {
		s := newServiceEnv(t, goos)
		if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 0 {
			t.Fatalf("%s install: exit %d: %s", goos, code, errOut)
		}
		s.fail = stop
		code, out, errOut := s.hop(t, "setup", "--service", "--uninstall", "--yes", "--json")
		if code != 255 || strings.Contains(out, `"active"`) || !strings.Contains(errOut, stop+" failed") || !strings.Contains(errOut, "may still be running") {
			t.Errorf("%s failing stop: exit %d, %q, %q", goos, code, out, errOut)
		}
		if _, err := os.Lstat(s.servicePath()); err != nil || !s.runsCurrent(t) {
			t.Errorf("%s failing stop: file %v, manager %+v", goos, err, s.mgr)
		}
		s.fail = ""
		code, out, errOut = s.hop(t, "setup", "--service", "--uninstall", "--yes", "--json")
		var res cli.ServiceResult
		if code == 0 {
			decodeJSON(t, out, &res)
		}
		if code != 0 || !res.Changed || res.Active || s.mgr.running {
			t.Errorf("%s retry: exit %d, %q, %+v, manager %+v", goos, code, errOut, res, s.mgr)
		}
		if _, err := os.Lstat(s.servicePath()); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s retry: file still there: %v", goos, err)
		}
	}
}

// The second systemd uninstall command failing fails the run and keeps
// the file, so a retry runs every stop step again.
func TestSetupServiceUninstallSecondStopFails(t *testing.T) {
	s := newServiceEnv(t, "linux")
	if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 0 {
		t.Fatalf("install: exit %d: %s", code, errOut)
	}
	stop := "systemctl --user stop hopkey.service"
	s.fail = stop
	code, out, errOut := s.hop(t, "setup", "--service", "--uninstall", "--yes", "--json")
	if code != 255 || strings.Contains(out, `"active"`) || !strings.Contains(errOut, stop+" failed") {
		t.Errorf("failing second stop: exit %d, %q, %q", code, out, errOut)
	}
	if _, err := os.Lstat(s.servicePath()); err != nil {
		t.Errorf("failing second stop removed the file: %v", err)
	}
	s.fail = ""
	if code, _, errOut := s.hop(t, "setup", "--service", "--uninstall", "--yes"); code != 0 {
		t.Errorf("retry: exit %d: %s", code, errOut)
	}
	if _, err := os.Lstat(s.servicePath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("retry: file still there: %v", err)
	}
}

// With the file already gone, uninstall still stops what the service
// manager runs.
func TestSetupServiceUninstallWithoutTheFile(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		s := newServiceEnv(t, goos)
		if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 0 {
			t.Fatalf("%s install: exit %d: %s", goos, code, errOut)
		}
		if err := os.Remove(s.servicePath()); err != nil {
			t.Fatal(err)
		}
		code, out, errOut := s.hop(t, "setup", "--service", "--uninstall", "--yes")
		if code != 0 || !strings.Contains(out, "no "+map[string]string{"linux": "systemd", "darwin": "launchd"}[goos]+" service is installed") || s.mgr.running {
			t.Errorf("%s: exit %d, %q %q, manager %+v", goos, code, out, errOut, s.mgr)
		}
	}
}

// A plist from before plistMarker, with the old marker in its comment,
// is still hop's: setup replaces it with one carrying only the new
// marker, and uninstall removes it.
func TestSetupServiceLegacyPlist(t *testing.T) {
	legacy := `<?xml version="1.0" encoding="UTF-8"?>
<!-- Written by hop setup --service: it runs the hop daemon from login. Remove it with hop setup --service --uninstall. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.github.dalyem.hopkey</string>
</dict>
</plist>
`
	for _, args := range [][]string{{"setup", "--service", "--yes"}, {"setup", "--service", "--uninstall", "--yes"}} {
		s := newServiceEnv(t, "darwin")
		if err := os.MkdirAll(filepath.Dir(s.servicePath()), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.servicePath(), []byte(legacy), 0o644); err != nil {
			t.Fatal(err)
		}
		code, _, errOut := s.hop(t, args...)
		if code != 0 {
			t.Errorf("%q on a legacy plist: exit %d: %s", args, code, errOut)
			continue
		}
		b, err := os.ReadFile(s.servicePath())
		if slices.Contains(args, "--uninstall") {
			if !errors.Is(err, os.ErrNotExist) {
				t.Errorf("legacy plist not removed: %v", err)
			}
			continue
		}
		if err != nil || !strings.Contains(string(b), "Written by hop setup (service)") || strings.Contains(string(b), "Written by hop setup --service") || !s.runsCurrent(t) {
			t.Errorf("legacy plist not replaced: %v\n%s", err, b)
		}
	}
}

// Uninstall checks the directory as install does before it removes
// anything: an ancestor someone else could write to is refused, and the
// file and the service are left alone.
func TestSetupServiceUninstallChecksTheDirectory(t *testing.T) {
	s := newServiceEnv(t, "linux")
	if code, _, errOut := s.hop(t, "setup", "--service", "--yes"); code != 0 {
		t.Fatalf("install: exit %d: %s", code, errOut)
	}
	unit := filepath.Join(s.home, ".config", "systemd", "user", "hopkey.service")
	cfg := filepath.Join(s.home, ".config")
	if err := os.Chmod(cfg, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(cfg, 0o700) })
	s.ran = nil
	code, _, errOut := s.hop(t, "setup", "--service", "--uninstall", "--yes")
	if code != 255 {
		t.Errorf("uninstall under a writable ancestor: exit %d, %q", code, errOut)
	}
	if _, err := os.Lstat(unit); err != nil {
		t.Errorf("the unit was removed: %v", err)
	}
	if len(s.ran) != 0 {
		t.Errorf("ran %q", s.ran)
	}

	// No directory at all: nothing is installed, and nothing is created.
	s = newServiceEnv(t, "linux")
	if code, out, _ := s.hop(t, "setup", "--service", "--uninstall", "--yes"); code != 0 || !strings.Contains(out, "no systemd service") {
		t.Errorf("no directory: exit %d, %q", code, out)
	}
	if _, err := os.Lstat(filepath.Join(s.home, ".config")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("uninstall created directories: %v", err)
	}
}

// The output says the service hard-codes this binary's path and that the
// directory was made private.
func TestSetupServiceSaysWhatItFixes(t *testing.T) {
	s := newServiceEnv(t, "linux")
	code, _, errOut := s.hop(t, "setup", "--service", "--yes")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"runs /opt/hop tools/hop%h$HOME by that path", "after moving or upgrading hop", "mode 0700"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	}
	code, _, errOut = s.hop(t, "setup", "-h")
	if code != 0 || !strings.Contains(errOut, "upgrading hop") || !strings.Contains(errOut, "0700") ||
		!strings.Contains(errOut, "run hop daemon stop, then hop setup --service again") || !strings.Contains(errOut, "does not show config_not_written warnings") {
		t.Errorf("help: exit %d, %q", code, errOut)
	}
}
