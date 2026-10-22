package cli

import (
	"bytes"
	"context"
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
	}
	for _, tt := range tests {
		key, args := splitDirective(tt.in)
		if key != tt.key || !slices.Equal(args, tt.args) {
			t.Errorf("splitDirective(%q) = %q %q, want %q %q", tt.in, key, args, tt.key, tt.args)
		}
	}
}

func TestParseSSHConfig(t *testing.T) {
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
	write("conf.d/extra.conf", "Host extra\n  HostName 192.0.2.77\n  User x\n")
	main := write("config", `# my config
Include conf.d/*.conf
Include ~/.ssh/hop/config
Include /nonexistent/file

Host *
  ServerAliveInterval 30

Host web web-alias !bad *.wild
  HostName=10.0.0.1
  User deploy
  Port 2222
  IdentityFile ~/.ssh/id_web
  IdentityFile "%d/.ssh/id_other"
  ProxyJump jump@gw:2200

Match host foo
  User nobody

Host db
  Port nonsense
  HostName db.example.com

Host *.example.com
  User wild
`)
	p := newSSHConfigParser(home, filepath.Join(sshDir, "hop"))
	if err := p.parseFile(main, 0); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, b := range p.blocks {
		names = append(names, strings.Join(b.concrete(), ","))
	}
	if want := []string{"extra", "web,web-alias", "db"}; !slices.Equal(names, want) {
		t.Fatalf("blocks = %q, want %q (hop's own include must be skipped, wildcards dropped)", names, want)
	}
	web := p.blocks[1]
	if web.HostName != "10.0.0.1" || web.User != "deploy" || web.Port != 2222 || web.ProxyJump != "jump@gw:2200" ||
		!slices.Equal(web.IdentityFiles, []string{"~/.ssh/id_web", "%d/.ssh/id_other"}) {
		t.Errorf("web = %+v", web)
	}
	if got := p.expand(web.IdentityFiles[0]); got != filepath.Join(home, ".ssh", "id_web") {
		t.Errorf("expand ~ = %q", got)
	}
	if got := p.expand(web.IdentityFiles[1]); got != filepath.Join(home, ".ssh", "id_other") {
		t.Errorf("expand %%d = %q", got)
	}
	if p.blocks[2].Port != 0 {
		t.Errorf("a bad Port was kept: %d", p.blocks[2].Port)
	}
	if !p.defaults {
		t.Error("Host * and Match were not noticed")
	}
	if len(p.warnings) == 0 || !strings.Contains(strings.Join(p.warnings, "\n"), "Port") {
		t.Errorf("warnings = %q", p.warnings)
	}
	// Includes nested too deeply stop.
	loop := write("loop", "Include loop\nHost looped\n")
	q := newSSHConfigParser(home, "")
	if err := q.parseFile(loop, 0); err != nil {
		t.Fatal(err)
	}
	if len(q.blocks) == 0 || len(q.warnings) == 0 {
		t.Errorf("a self-including file: %d blocks, warnings %q", len(q.blocks), q.warnings)
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
