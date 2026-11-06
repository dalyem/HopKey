package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/daemon"
)

func TestSplitDirective(t *testing.T) {
	tests := []struct {
		in   string
		key  string
		args []string
	}{
		{"Host web-1", "host", []string{"web-1"}},
		{"  HostName   10.0.0.1  ", "hostname", []string{"10.0.0.1"}},
		{"HostName=10.0.0.1", "hostname", []string{"10.0.0.1"}},
		{"HostName = 10.0.0.1", "hostname", []string{"10.0.0.1"}},
		{"HostName =10.0.0.1", "hostname", []string{"10.0.0.1"}},
		{"Host a b c", "host", []string{"a", "b", "c"}},
		{`IdentityFile "~/my keys/id"`, "identityfile", []string{"~/my keys/id"}},
		{"User deploy # the deploy user", "user", []string{"deploy"}},
		{"# Host hidden", "", nil},
		{"", "", nil},
		{"   ", "", nil},
		{"ProxyCommand ssh -o Foo=bar gw", "proxycommand", []string{"ssh", "-o", "Foo=bar", "gw"}},
		{"Port 2222", "port", []string{"2222"}},
		{"Include conf.d/*", "include", []string{"conf.d/*"}},
		{"Host", "host", nil},
		{`Match 'exec' "touch x"`, "match", []string{"exec", "touch x"}},
		{`Match "ex""ec" cmd`, "match", []string{"exec", "cmd"}},
		{`Match !exec "a \" b"`, "match", []string{"!exec", `a " b`}},
		{`IdentityFile my\ key`, "identityfile", []string{"my key"}},
		{`Match user a#b # comment`, "match", []string{"user", "a#b"}},
	}
	for _, tt := range tests {
		key, args := splitDirective(tt.in)
		if key != tt.key || !slices.Equal(args, tt.args) {
			t.Errorf("splitDirective(%q) = %q %q, want %q %q", tt.in, key, args, tt.key, tt.args)
		}
	}
}

func TestConfigScan(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(filepath.Join(sshDir, "conf.d"), 0o700)
	os.MkdirAll(filepath.Join(sshDir, "hop"), 0o700)
	write := func(rel, body string) string {
		p := filepath.Join(sshDir, rel)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("hop/config", "Host from-hop\n  HostName 1.1.1.1\n")
	write("conf.d/extra.conf", "Host extra Dup\n  HostName 192.0.2.77\n  User x\n")
	write("conf.d/second.conf", "Host second\n")
	write("abs.conf", "Host from-abs\n")
	write("rel.conf", "Host from-rel\n")
	main := write("config", `# my config
Include conf.d/*.conf
Include ~/.ssh/hop/config
Include /nonexistent/file
Include `+filepath.Join(sshDir, "abs.conf")+`

Host *
  ServerAliveInterval 30
  User   global

Host web web-alias !bad *.wild prod,comma w?b
  HostName=10.0.0.1
  Include rel.conf
  User deploy
  IdentityFile ~/.ssh/id_web
  IdentityFile "%d/.ssh/id_other"

Match host foo
  User nobody

Host dup web
  Port 22
`)
	s := newConfigScan(home, filepath.Join(sshDir, "hop"))
	if err := s.scan(main); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, a := range s.aliases {
		names = append(names, a.Name)
	}
	want := []string{"extra", "Dup", "second", "from-abs", "web", "web-alias", "prod,comma", "from-rel"}
	if !slices.Equal(names, want) {
		t.Errorf("aliases = %q, want %q (wildcards, negations and hop's own include dropped; duplicates once, whatever their case)", names, want)
	}
	if got := s.aliases[4].Source; got != main+":11" {
		t.Errorf("web's source = %q", got)
	}
	if len(s.matchExec) != 0 {
		t.Errorf("matchExec = %q", s.matchExec)
	}
	if len(s.unscanned) != 0 {
		t.Errorf("unscanned = %q", s.unscanned)
	}
	// Every Host line is kept by file and line, with its literal words only.
	if got := s.hostLines[hostLoc{main, 11}]; !slices.Equal(got, []string{"web", "web-alias", "prod,comma"}) {
		t.Errorf("hostLines[%s:11] = %q", main, got)
	}
	if !s.declares(main, 11, "WEB") || s.declares(main, 11, "bad") || s.declares(main, 7, "web") {
		t.Errorf("declares: web on its own line, bad is negated, line 7 is Host *")
	}

	// Match exec, in a file that is only included.
	write("exec.conf", "Match host a exec \"true\"\n  User q\n")
	main = write("config", "Include exec.conf\nHost h\nMatch Exec \"x\"\n")
	s = newConfigScan(home, "")
	if err := s.scan(main); err != nil {
		t.Fatal(err)
	}
	if want := []string{filepath.Join(sshDir, "exec.conf") + ":1", main + ":3"}; !slices.Equal(execSources(s), want) {
		t.Errorf("matchExec = %q, want %q", s.matchExec, want)
	}

	// Includes nested too deeply stop, as ssh's do, and are not scanned.
	loop := write("loop", "Include loop\nHost looped\n")
	s = newConfigScan(home, "")
	if err := s.scan(loop); err != nil {
		t.Fatal(err)
	}
	if len(s.aliases) != 1 || len(s.unscanned) == 0 || !strings.Contains(s.unscanned[0], "nested too deeply") {
		t.Errorf("a self-including file: aliases %v, unscanned %q", s.aliases, s.unscanned)
	}
}

func TestLimitedBufferRecordsOverflow(t *testing.T) {
	var b bytes.Buffer
	l := &limitedBuffer{buf: &b, max: 4}
	l.Write([]byte("abcd"))
	if l.overflow || b.String() != "abcd" {
		t.Errorf("exactly max: overflow=%v kept=%q", l.overflow, b.String())
	}
	if n, err := l.Write([]byte("ef")); n != 2 || err != nil || !l.overflow || b.String() != "abcd" {
		t.Errorf("past max: n=%d err=%v overflow=%v kept=%q", n, err, l.overflow, b.String())
	}
	b.Reset()
	l = &limitedBuffer{buf: &b, max: 4}
	l.Write([]byte("abcdef"))
	if !l.overflow || b.String() != "abcd" {
		t.Errorf("one write across max: overflow=%v kept=%q", l.overflow, b.String())
	}
}

func execSources(s *configScan) []string {
	var out []string
	for _, m := range s.matchExec {
		out = append(out, m.source)
	}
	return out
}

func TestMatchRunsCommand(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{`Match exec "true"`, true},
		{`Match !exec "true"`, true},
		{`MATCH EXEC "true"`, true},
		{`match Exec true`, true},
		{`Match "exec" "touch x"`, true},
		{`Match 'exec' 'touch x'`, true},
		{`Match "!ex""ec" cmd`, true},
		{`Match host x exec y`, true},
		{`Match host x !exec "y z"`, true},
		{`Match all exec y`, true},
		{`Match canonical final exec y`, true},
		{`Match originalhost h user u localuser l exec c`, true},
		{`Match newcriterion x exec y`, true},
		{`Match newcriterion exec`, true},
		{`Match=exec "true"`, true},
		{`Match host exec`, false}, // a host named exec
		{`Match originalhost exec,other user exec`, false},
		{`Match host h`, false},
		{`Match all`, false},
		{`Match canonical host x`, false},
		{`Match host x # exec y`, false},
		{`Match user "exec"`, false},
		{`Match`, false},
	}
	for _, tt := range tests {
		key, args := splitDirective(tt.line)
		if key != "match" {
			t.Fatalf("%q: key %q", tt.line, key)
		}
		if got := matchRunsCommand(args); got != tt.want {
			t.Errorf("matchRunsCommand(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

func TestConfigScanFlagsMatchExecInAnyForm(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, "config")
	os.WriteFile(cfg, []byte("Match !exec \"x\"\nMatch host h EXEC y\nMatch host exec\n  # Match exec in a comment\n"), 0o600)
	s := newConfigScan(home, "")
	if err := s.scan(cfg); err != nil {
		t.Fatal(err)
	}
	if want := []string{cfg + ":1", cfg + ":2"}; !slices.Equal(execSources(s), want) {
		t.Errorf("matchExec = %q, want %q", s.matchExec, want)
	}
	if got := s.matchExec[0].text; got != `Match !exec "x"` {
		t.Errorf("the line text = %q", got)
	}
}

// Every error reaches the terminal display-safe, and JSON keeps values intact
// while format characters are escaped.
func TestErrorsAndJSONAreDisplaySafe(t *testing.T) {
	var out bytes.Buffer
	e := &Env{Stderr: &out}
	reportError(e, failMsg("open /tmp/x\x1b[2J\u202eevil: no such file\n  next line"), nil)
	got := out.String()
	if strings.ContainsAny(got, "\x1b\u202e") || !strings.Contains(got, "\n  next line") {
		t.Errorf("composed error not display-safe (or lost its layout): %q", got)
	}
	out.Reset()
	reportError(e, errors.New("open /tmp/x\x1b[2J\u202eevil: no such file\n  next line"), nil)
	if got := out.String(); strings.ContainsAny(got, "\x1b\u202e") || strings.Count(got, "\n") != 1 {
		t.Errorf("plain error not flattened to one safe line: %q", got)
	}
	out.Reset()
	reportError(e, errors.New("bad \u202e name"), []string{"--json"})
	if strings.ContainsRune(out.String(), 0x202e) || !strings.Contains(out.String(), `\u202e`) {
		t.Errorf("JSON error = %q, want the bidi override escaped", out.String())
	}
	var js bytes.Buffer
	e.Stdout = &js
	if err := printJSON(e, map[string]string{"name": "a\u202eb\U000e0001c"}); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(js.String(), 0x202e) || strings.ContainsRune(js.String(), 0xe0001) {
		t.Errorf("printJSON left format characters raw: %q", js.String())
	}
	var back map[string]string
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || back["name"] != "a\u202eb\U000e0001c" {
		t.Errorf("escaped JSON does not round-trip: %v, %q", err, back["name"])
	}
}

func TestConsentNoticeAndPrintable(t *testing.T) {
	s := &configScan{}
	notice := consentNotice("/c", s)
	if !strings.Contains(notice, "no `Match exec` lines") || !strings.Contains(notice, "hop's scan is best effort") {
		t.Errorf("empty notice = %q", notice)
	}
	s.matchExec = []execLine{{"/c:3", "Match exec \"touch x\"\x1b[2J"}}
	s.unscanned = []string{"/c:1: Include \"${X}\" uses an environment variable"}
	notice = consentNotice("/c", s)
	for _, want := range []string{"ssh -G", "DNS", "/c:3: Match exec \"touch x\"?[2J", "/c:1: Include", "not imported"} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice lacks %q:\n%s", want, notice)
		}
	}
	if strings.ContainsRune(notice, 0x1b) {
		t.Errorf("a control character reached the terminal: %q", notice)
	}
	// The notice names what is being authorized and does not claim to be
	// equivalent to connecting.
	for _, want := range []string{"with your permissions", "even with --dry-run", "Only continue if you trust this config"} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice lacks %q:\n%s", want, notice)
		}
	}
	if strings.Contains(notice, "exactly as connecting") {
		t.Errorf("notice still claims equivalence with connecting:\n%s", notice)
	}
	// A hostile file name cannot redraw the prompt: escapes, newlines and
	// bidi overrides in the path are neutralized.
	evil := "/tmp/x\x1b[2J\nOK to continue\u202e.conf"
	notice = consentNotice(evil, &configScan{})
	if strings.ContainsAny(notice, "\x1b\u202e") || strings.Contains(notice, "\nOK to continue") {
		t.Errorf("the path reached the terminal unneutralized: %q", notice)
	}
	if got := printable("a\u202eb\u2066c\u200bd"); got != "a?b?c?d" {
		t.Errorf("printable left format characters: %q", got)
	}
	if got := printable(strings.Repeat("x", 500)); len(got) != maxShown+3 {
		t.Errorf("a long line is cut to %d bytes, got %d", maxShown+3, len(got))
	}
}

func TestIncludeResolution(t *testing.T) {
	home := "/home/h"
	s := newConfigScan(home, "")
	tests := []struct {
		in, want, why string
	}{
		{"conf.d/*", "/home/h/.ssh/conf.d/*", ""},
		{"~/x/*.conf", "/home/h/x/*.conf", ""},
		{"/etc/ssh/a", "/etc/ssh/a", ""},
		{"%d/.ssh/a", "/home/h/.ssh/a", ""},
		{"a%%b", "/home/h/.ssh/a%b", ""},
		{"${HOME}/a", "", "environment variable"},
		{"/x/${SITE}/*", "", "environment variable"},
		{"~bob/a", "", "~user"},
		{"/x/%h/a", "", "token"},
		{"%u", "", "token"},
		{"/x/%", "", "token"},
	}
	for _, tt := range tests {
		got, why := s.resolveInclude(tt.in)
		if got != tt.want || (tt.why == "") != (why == "") || !strings.Contains(why, tt.why) {
			t.Errorf("resolveInclude(%q) = %q, %q; want %q, %q", tt.in, got, why, tt.want, tt.why)
		}
	}
}

// Whatever ssh will read and hop cannot check is listed; what ssh skips is not.
func TestConfigScanUnscannedIncludes(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(filepath.Join(sshDir, "dir.d", "sub"), 0o700)
	os.WriteFile(filepath.Join(sshDir, "dir.d", "ok.conf"), []byte("Host ok\n"), 0o600)
	cfg := filepath.Join(sshDir, "config")
	body := "Include ${HOME}/a\nInclude ~bob/b\nInclude /x/%h\nInclude dir.d/*\nInclude missing.conf\nInclude /bad[\nHost last\n"
	os.WriteFile(cfg, []byte(body), 0o600)
	s := newConfigScan(home, "")
	if err := s.scan(cfg); err != nil {
		t.Fatal(err)
	}
	// ${HOME}, ~user, a token and a bad glob; not the missing file, nor the
	// subdirectory the glob matched.
	if len(s.unscanned) != 4 {
		t.Fatalf("unscanned = %q", s.unscanned)
	}
	for i, want := range []string{cfg + ":1", cfg + ":2", cfg + ":3", cfg + ":6"} {
		if !strings.HasPrefix(s.unscanned[i], want+": Include ") {
			t.Errorf("unscanned[%d] = %q, want it to start with %s", i, s.unscanned[i], want)
		}
	}
	if got := len(s.aliases); got != 2 {
		t.Errorf("aliases = %v, want ok and last", s.aliases)
	}

	// A file that exists and cannot be read is listed too.
	s = newConfigScan(home, "")
	s.readFile = func(p string) (io.ReadCloser, error) {
		if strings.HasSuffix(p, "ok.conf") {
			return nil, os.ErrPermission
		}
		return os.Open(p)
	}
	os.WriteFile(cfg, []byte("Include dir.d/*\n"), 0o600)
	if err := s.scan(cfg); err != nil {
		t.Fatal(err)
	}
	if len(s.unscanned) != 1 || !strings.Contains(s.unscanned[0], "ok.conf") || !strings.Contains(s.unscanned[0], "cannot be read") {
		t.Errorf("unreadable include: unscanned = %q", s.unscanned)
	}
}

// hop's own generated config gives no aliases but is still read for what it
// makes ssh do.
func TestConfigScanSafetyScansTheExcludedDir(t *testing.T) {
	home := t.TempDir()
	hopDir := filepath.Join(home, ".ssh", "hop")
	os.MkdirAll(hopDir, 0o700)
	os.WriteFile(filepath.Join(hopDir, "config"), []byte("Host generated\nMatch exec \"x\"\nInclude ${HOME}/y\n"), 0o600)
	cfg := filepath.Join(home, ".ssh", "config")
	os.WriteFile(cfg, []byte("Include "+filepath.Join(hopDir, "config")+"\nHost mine\n"), 0o600)
	s := newConfigScan(home, hopDir)
	if err := s.scan(cfg); err != nil {
		t.Fatal(err)
	}
	if len(s.aliases) != 1 || s.aliases[0].Name != "mine" {
		t.Errorf("aliases = %v: the generated config names nothing to import", s.aliases)
	}
	if len(s.matchExec) != 1 || len(s.unscanned) != 1 {
		t.Errorf("matchExec = %q, unscanned = %q: the excluded file is still checked", s.matchExec, s.unscanned)
	}
}

func TestEnsureInclude(t *testing.T) {
	const inc = "Include ~/.ssh/hop/config"
	same := func(a string) bool { return a == "~/.ssh/hop/config" }
	tests := []struct {
		name        string
		in          string
		wantChanged bool
		want        string
	}{
		{name: "empty file", in: "", wantChanged: true, want: "# Added by hop setup: the hosts in your HopKey vault.\n" + inc + "\n"},
		{name: "existing config", in: "Host a\n  User x\n", wantChanged: true, want: "# Added by hop setup: the hosts in your HopKey vault.\n" + inc + "\n\nHost a\n  User x\n"},
		{name: "already at the top", in: "# c\n" + inc + "\nHost a\n", wantChanged: false},
		{name: "already first, case-insensitive keyword", in: "include ~/.ssh/hop/config\n\nHost a\n", wantChanged: false},
		{name: "after a Host line is too late", in: "Host a\n  User x\n" + inc + "\n", wantChanged: true,
			want: "# Added by hop setup: the hosts in your HopKey vault.\n" + inc + "\n\nHost a\n  User x\n"},
		{name: "after a Match line is too late", in: "Match all\n" + inc + "\n", wantChanged: true,
			want: "# Added by hop setup: the hosts in your HopKey vault.\n" + inc + "\n\nMatch all\n"},
		{name: "other includes are kept", in: "Include other\nHost a\n", wantChanged: true,
			want: "# Added by hop setup: the hosts in your HopKey vault.\n" + inc + "\n\nInclude other\nHost a\n"},
		{name: "a different include is not ours", in: "Include ~/.ssh/hop/other\nHost a\n", wantChanged: true,
			want: "# Added by hop setup: the hosts in your HopKey vault.\n" + inc + "\n\nInclude ~/.ssh/hop/other\nHost a\n"},
		{name: "first directive is another Include: ours still goes first", in: "Include other\nInclude ~/.ssh/hop/config\nHost a\n", wantChanged: true,
			want: "# Added by hop setup: the hosts in your HopKey vault.\n" + inc + "\n\nInclude other\nHost a\n"},
		{name: "after a plain directive is too late", in: "StrictHostKeyChecking no\n" + inc + "\nHost a\n", wantChanged: true,
			want: "# Added by hop setup: the hosts in your HopKey vault.\n" + inc + "\n\nStrictHostKeyChecking no\nHost a\n"},
		{name: "a config that starts with a directive gets the include above it", in: "# mine\nStrictHostKeyChecking no\n\nHost a\n  User x\n", wantChanged: true,
			want: "# Added by hop setup: the hosts in your HopKey vault.\n" + inc + "\n\n# mine\nStrictHostKeyChecking no\n\nHost a\n  User x\n"},
		{name: "ours first on a line shared with other paths is in place", in: "Include ~/.ssh/hop/config other.conf\nHost a\n", wantChanged: false},
		{name: "ours after another path on the first line is too late; the other path stays", in: "Include other.conf ~/.ssh/hop/config\nHost a\n", wantChanged: true,
			want: "# Added by hop setup: the hosts in your HopKey vault.\n" + inc + "\n\nInclude other.conf\nHost a\n"},
		{name: "a shared line further down loses only our path", in: "Host a\n  User x\nInclude conf.d/* ~/.ssh/hop/config \"/with space/x\" # keep\n", wantChanged: true,
			want: "# Added by hop setup: the hosts in your HopKey vault.\n" + inc + "\n\nHost a\n  User x\nInclude conf.d/* \"/with space/x\" # keep\n"},
		{name: "Include=path form", in: "Host a\nInclude=~/.ssh/hop/config\nInclude=other.conf\n", wantChanged: true,
			want: "# Added by hop setup: the hosts in your HopKey vault.\n" + inc + "\n\nHost a\nInclude=other.conf\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := ensureInclude(tt.in, inc, same)
			if changed != tt.wantChanged {
				t.Fatalf("changed = %v, want %v", changed, tt.wantChanged)
			}
			if !changed {
				if got != tt.in {
					t.Errorf("unchanged input was rewritten: %q", got)
				}
				return
			}
			if got != tt.want {
				t.Errorf("got:\n%q\nwant:\n%q", got, tt.want)
			}
			// Idempotent: a second pass changes nothing.
			again, changed2 := ensureInclude(got, inc, same)
			if changed2 || again != got {
				t.Errorf("not idempotent: changed=%v\n%q", changed2, again)
			}
		})
	}
}

func setupEnv(t *testing.T, stdin string, tty bool) (*Env, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	home := t.TempDir()
	var so, se bytes.Buffer
	return &Env{
		Stdin: strings.NewReader(stdin), Stdout: &so, Stderr: &se, Home: home, StdinTTY: tty,
		Getenv: func(string) string { return "" },
		Paths:  daemon.Paths{ConfigDir: filepath.Join(home, ".ssh", "hop")},
	}, &so, &se
}

func TestSetup(t *testing.T) {
	ctx := context.Background()

	t.Run("creates the file, with no backup", func(t *testing.T) {
		e, _, _ := setupEnv(t, "", false)
		if code := Run(ctx, []string{"setup", "--yes"}, e); code != 0 {
			t.Fatalf("exit %d", code)
		}
		b, err := os.ReadFile(filepath.Join(e.Home, ".ssh", "config"))
		if err != nil || !strings.Contains(string(b), "Include ~/.ssh/hop/config\n") {
			t.Fatalf("config = %q, %v", b, err)
		}
		fi, _ := os.Stat(filepath.Join(e.Home, ".ssh", "config"))
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v", fi.Mode().Perm())
		}
		matches, _ := filepath.Glob(filepath.Join(e.Home, ".ssh", "config.hop-backup-*"))
		if len(matches) != 0 {
			t.Errorf("backup of a file that did not exist: %v", matches)
		}
	})

	t.Run("backs up, prepends, keeps the mode, and is idempotent", func(t *testing.T) {
		e, _, _ := setupEnv(t, "", false)
		os.MkdirAll(filepath.Join(e.Home, ".ssh"), 0o700)
		cfg := filepath.Join(e.Home, ".ssh", "config")
		orig := "Host old\n  HostName 1.2.3.4\n"
		os.WriteFile(cfg, []byte(orig), 0o640)
		if code := Run(ctx, []string{"setup", "--yes"}, e); code != 0 {
			t.Fatalf("exit %d", code)
		}
		got, _ := os.ReadFile(cfg)
		if !strings.HasPrefix(string(got), "# Added by hop setup") || !strings.HasSuffix(string(got), "\n"+orig) {
			t.Errorf("config = %q", got)
		}
		if fi, _ := os.Stat(cfg); fi.Mode().Perm() != 0o640 {
			t.Errorf("mode changed to %v", fi.Mode().Perm())
		}
		matches, _ := filepath.Glob(cfg + ".hop-backup-*")
		if len(matches) != 1 {
			t.Fatalf("backups = %v", matches)
		}
		if b, _ := os.ReadFile(matches[0]); string(b) != orig {
			t.Errorf("backup = %q", b)
		}
		// Second run: nothing to do, no new backup.
		var so bytes.Buffer
		e.Stdout = &so
		if code := Run(ctx, []string{"setup", "--yes", "--json"}, e); code != 0 || !strings.Contains(so.String(), `"changed": false`) {
			t.Errorf("second run: %s", so.String())
		}
		if after, _ := os.ReadFile(cfg); !bytes.Equal(after, got) {
			t.Error("the second run rewrote the file")
		}
		if matches, _ := filepath.Glob(cfg + ".hop-backup-*"); len(matches) != 1 {
			t.Errorf("backups after the second run: %v", matches)
		}
	})

	t.Run("edits the target of a symlink and keeps the link", func(t *testing.T) {
		e, _, _ := setupEnv(t, "", false)
		os.MkdirAll(filepath.Join(e.Home, ".ssh"), 0o700)
		real := filepath.Join(e.Home, "dotfiles-ssh-config")
		os.WriteFile(real, []byte("Host a\n"), 0o600)
		link := filepath.Join(e.Home, ".ssh", "config")
		if err := os.Symlink(real, link); err != nil {
			t.Skip("no symlinks here")
		}
		if code := Run(ctx, []string{"setup", "--yes"}, e); code != 0 {
			t.Fatalf("exit %d", code)
		}
		if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("the symlink was replaced: %v %v", fi, err)
		}
		if b, _ := os.ReadFile(real); !strings.Contains(string(b), "Include ~/.ssh/hop/config") {
			t.Errorf("target = %q", b)
		}
	})

	t.Run("asks first", func(t *testing.T) {
		e, _, se := setupEnv(t, "n\n", true)
		if code := Run(ctx, []string{"setup"}, e); code != 255 {
			t.Errorf("declined: exit %d", code)
		}
		if _, err := os.Stat(filepath.Join(e.Home, ".ssh", "config")); err == nil {
			t.Error("the file was written after a no")
		}
		if !strings.Contains(se.String(), "Go ahead?") {
			t.Errorf("no question asked: %q", se.String())
		}
		e, _, _ = setupEnv(t, "y\n", true)
		if code := Run(ctx, []string{"setup"}, e); code != 0 {
			t.Errorf("accepted: exit %d", code)
		}
		// No terminal and no --yes: refuse rather than guess.
		e, _, se = setupEnv(t, "y\n", false)
		if code := Run(ctx, []string{"setup"}, e); code != 255 || !strings.Contains(se.String(), "--yes") {
			t.Errorf("no tty: exit %d %q", code, se.String())
		}
	})

	t.Run("a custom config directory is included by absolute path", func(t *testing.T) {
		e, _, _ := setupEnv(t, "", false)
		e.Paths.ConfigDir = filepath.Join(e.Home, "my hop")
		if code := Run(ctx, []string{"setup", "--yes"}, e); code != 0 {
			t.Fatalf("exit %d", code)
		}
		b, _ := os.ReadFile(filepath.Join(e.Home, ".ssh", "config"))
		if !strings.Contains(string(b), `Include "`+filepath.Join(e.Home, "my hop", "config")+`"`) {
			t.Errorf("config = %q", b)
		}
		var so bytes.Buffer
		e.Stdout = &so
		if code := Run(ctx, []string{"setup", "--yes"}, e); code != 0 || !strings.Contains(so.String(), "already includes") {
			t.Errorf("second run: %q", so.String())
		}
	})
}

func TestRemoteCommand(t *testing.T) {
	tests := []struct {
		words []string
		sudo  bool
		want  string
	}{
		{[]string{"uptime"}, false, "uptime"},
		{[]string{"echo", "ok"}, false, "echo ok"},
		{[]string{"echo", "a b"}, false, "echo 'a b'"},
		{[]string{"echo", ""}, false, "echo ''"},
		{[]string{"echo", "it's"}, false, `echo 'it'\''s'`},
		{[]string{"echo", "$HOME", "`id`", "a;b", "*"}, false, `echo '$HOME' '` + "`id`" + `' 'a;b' '*'`},
		{[]string{"cat", "/etc/hosts"}, false, "cat /etc/hosts"},
		{[]string{"cd /srv && make"}, false, "cd /srv && make"}, // a single word is a command line
		{[]string{"systemctl", "restart", "x"}, true, "sudo -n systemctl restart x"},
		{[]string{"cd /srv && make"}, true, "sudo -n sh -c 'cd /srv && make'"},
		{[]string{"id"}, true, "sudo -n sh -c id"},
	}
	for _, tt := range tests {
		if got := remoteCommand(tt.words, tt.sudo); got != tt.want {
			t.Errorf("remoteCommand(%q, %v) = %q, want %q", tt.words, tt.sudo, got, tt.want)
		}
	}
}

func TestTailBuffer(t *testing.T) {
	tb := &tailBuffer{max: 10}
	io.WriteString(tb, "abc")
	if string(tb.Bytes()) != "abc" || tb.dropped {
		t.Errorf("short write: %q dropped=%v", tb.Bytes(), tb.dropped)
	}
	io.WriteString(tb, "defghijklmno") // 15 bytes total
	if got := string(tb.Bytes()); got != "fghijklmno" || !tb.dropped {
		t.Errorf("after overflow: %q dropped=%v", got, tb.dropped)
	}
	// Many small writes keep memory bounded and the tail right.
	tb = &tailBuffer{max: 10}
	for i := 0; i < 1000; i++ {
		io.WriteString(tb, "0123456789")
		if len(tb.buf) > 3*tb.max {
			t.Fatalf("buffer grew to %d", len(tb.buf))
		}
	}
	io.WriteString(tb, "XY")
	if got := string(tb.Bytes()); got != "23456789XY" || !tb.dropped {
		t.Errorf("tail = %q dropped=%v", got, tb.dropped)
	}
	// Exactly max bytes is not truncation.
	tb = &tailBuffer{max: 4}
	io.WriteString(tb, "abcd")
	if tb.Bytes(); tb.dropped {
		t.Error("exactly max bytes marked as truncated")
	}
}

func TestSuggestName(t *testing.T) {
	for in, want := range map[string]string{
		"web-1":                 "web-1",
		"Web_1":                 "web_1",
		"203.0.113.5":           "203-0-113-5",
		"fd7a::1":               "fd7a-1",
		"Daly's iPhone":         "dalys-iphone",
		"  --x--  ":             "x",
		"":                      "host",
		"???":                   "host",
		"_x":                    "host",
		strings.Repeat("a", 80): strings.Repeat("a", 64),
	} {
		if got := suggestName(in); got != want {
			t.Errorf("suggestName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseFlagsAllowsInterleavingAndStopsAtDashDash(t *testing.T) {
	var buf bytes.Buffer
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(&buf)
	name := fs.String("name", "", "")
	var tags stringList
	fs.Var(&tags, "tag", "")
	json := fs.Bool("json", false, "")

	pos, rest, err := parseFlags(fs, []string{"a", "--name", "n", "b", "--tag=x", "--tag", "y", "--json", "--", "--name", "z", "-q"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pos, []string{"a", "b"}) || !slices.Equal(rest, []string{"--name", "z", "-q"}) ||
		*name != "n" || !slices.Equal(tags.vals, []string{"x", "y"}) || !*json {
		t.Errorf("pos=%q rest=%q name=%q tags=%q json=%v", pos, rest, *name, tags.vals, *json)
	}
	if !wasSet(fs, "tag") || wasSet(fs, "nothing") {
		t.Error("wasSet is wrong")
	}

	// No -- means rest is nil, which hop exec uses to tell the forms apart.
	fs2 := flag.NewFlagSet("t", flag.ContinueOnError)
	fs2.SetOutput(&buf)
	_, rest, _ = parseFlags(fs2, []string{"a", "b"})
	if rest != nil {
		t.Errorf("rest = %q, want nil", rest)
	}
	// An unknown flag is an error that has been reported already.
	if _, _, err := parseFlags(fs2, []string{"--bogus"}); err == nil {
		t.Error("an unknown flag was accepted")
	}
	// -h is not a failure.
	if _, _, err := parseFlags(fs2, []string{"-h"}); err != flag.ErrHelp {
		t.Errorf("-h: %v", err)
	}
}

func TestRunUsageAndVersion(t *testing.T) {
	ctx := context.Background()
	e, so, se := setupEnv(t, "", false)
	if code := Run(ctx, nil, e); code != 255 || !strings.Contains(se.String(), "usage: hop") {
		t.Errorf("no args: %d %q", code, se.String())
	}
	if code := Run(ctx, []string{"--version"}, e); code != 0 || !strings.HasPrefix(so.String(), "hop ") {
		t.Errorf("--version: %d %q", code, so.String())
	}
	so.Reset()
	if code := Run(ctx, []string{"help"}, e); code != 0 || !strings.Contains(so.String(), "hop exec") {
		t.Errorf("help: %d", code)
	}
	if code := Run(ctx, []string{"--bogus"}, e); code != 255 {
		t.Errorf("--bogus: %d", code)
	}
	if code := Run(ctx, []string{"ls", "-h"}, e); code != 0 {
		t.Errorf("ls -h: %d", code)
	}
	// --json errors are JSON on stderr.
	se.Reset()
	if code := Run(ctx, []string{"key", "bogus", "--json"}, e); code != 255 || !strings.HasPrefix(se.String(), `{"error":`) {
		t.Errorf("json error: %d %q", code, se.String())
	}
}
