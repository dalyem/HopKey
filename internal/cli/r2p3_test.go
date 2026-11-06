package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/store"
)

// An unknown first word with more words after it is not a target: hop says
// so, and names the nearest command.
func TestUnknownCommandIsNotATarget(t *testing.T) {
	run := func(args ...string) (int, string) {
		var so, se bytes.Buffer
		env := &cli.Env{Stdout: &so, Stderr: &se, Getenv: func(string) string { return "" }, Home: t.TempDir()}
		return cli.Run(context.Background(), args, env), se.String()
	}
	code, stderr := run("ssh-command", "t2inner")
	if code != 255 || !strings.Contains(stderr, `unknown command "ssh-command"`) || !strings.Contains(stderr, "exactly one target") || strings.Contains(stderr, "did you mean") {
		t.Errorf("hop ssh-command t2inner: exit %d, %q", code, stderr)
	}
	code, stderr = run("lst", "x")
	if code != 255 || !strings.Contains(stderr, `did you mean "ls"`) {
		t.Errorf("hop lst x: exit %d, %q", code, stderr)
	}
}

// hop status does not start the daemon; it says what does.
func TestStatusWithoutADaemonNamesTheWaysToStartIt(t *testing.T) {
	base := shortTemp(t)
	paths := daemon.Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg"), StateDir: filepath.Join(base, "state")}
	var so, se bytes.Buffer
	env := &cli.Env{
		Stdout: &so, Stderr: &se, Getenv: func(string) string { return "" },
		Home: filepath.Join(base, "home"), Paths: paths, GOOS: "linux",
		StartDaemon: func() error { t.Error("hop status started a daemon"); return nil },
	}
	if code := cli.Run(context.Background(), []string{"status"}, env); code != 255 {
		t.Errorf("exit %d", code)
	}
	out := so.String()
	for _, want := range []string{"hop daemon", "hop ls", "daemon.log"} {
		if !strings.Contains(out, want) {
			t.Errorf("hop status does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "journalctl") {
		t.Errorf("no login service is installed, so no journal hint:\n%s", out)
	}
}

// The login service's daemon logs to the journal, not to daemon.log, so a
// message that points to the log says where else to look.
func TestDaemonLogNoteMentionsTheJournalForTheLoginService(t *testing.T) {
	base := shortTemp(t)
	home := filepath.Join(base, "home")
	paths := daemon.Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg"), StateDir: filepath.Join(base, "state")}
	statusOut := func(goos string) string {
		var so, se bytes.Buffer
		env := &cli.Env{Stdout: &so, Stderr: &se, Getenv: func(string) string { return "" }, Home: home, Paths: paths, GOOS: goos}
		cli.Run(context.Background(), []string{"status"}, env)
		return so.String()
	}
	if strings.Contains(statusOut("linux"), "journalctl") {
		t.Fatal("a journal hint without a service")
	}
	unit := filepath.Join(home, ".config", "systemd", "user", "hopkey.service")
	if err := os.MkdirAll(filepath.Dir(unit), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte("[Service]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := statusOut("linux"); !strings.Contains(out, "journalctl --user -u hopkey") || !strings.Contains(out, "daemon.log") {
		t.Errorf("with the service installed, hop status says:\n%s", out)
	}
	// launchd writes daemon.log itself.
	if out := statusOut("darwin"); strings.Contains(out, "journalctl") {
		t.Errorf("macOS has no journal:\n%s", out)
	}

	// An autostart failure says the same.
	fake := filepath.Join(base, "fake-hop")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho 'hop: no vault' >&2\nexit 255\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var so, se bytes.Buffer
	env := &cli.Env{
		Stdout: &so, Stderr: &se, Getenv: func(string) string { return "" },
		Home: home, DataDir: filepath.Join(base, "data"), Paths: paths, GOOS: "linux",
		Executable: fake, Environ: os.Environ(),
	}
	if code := cli.Run(context.Background(), []string{"ls"}, env); code == 0 || !strings.Contains(se.String(), "journalctl --user -u hopkey") {
		t.Errorf("autostart failure: exit %d, %q", code, se.String())
	}
}

// An interrupted approval login leaves its enrollment behind, and it blocks
// every other login. hop auth login --discard removes it.
func TestLoginDiscardClearsAnInterruptedEnrollment(t *testing.T) {
	w := newAuthWorld(t)
	m1, m2 := newMachine(t, w, "m1"), newMachine(t, w, "m2")
	initS := &session{secrets: map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}}
	if code := m1.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	sk, _ := kitKeys(t, initS.stdout.String())
	m1.must(t, nil, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t), "--json")

	// m2 starts an approval login, shows its routing code, and is killed.
	ctx, interrupt := context.WithCancelCause(context.Background())
	newcomer := &session{tty: true, ctx: ctx}
	done := make(chan int, 1)
	go func() { done <- m2.hop(t, newcomer, "login", "--server", w.origin, "--name", "m2") }()
	waitFor(t, 30*time.Second, "the routing code", func() bool { return routingLine.MatchString(newcomer.stderr.String()) })
	interrupt(cli.ErrInterrupted)
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the interrupted login did not return")
	}

	pw := map[string]string{"HOP_PASSWORD": resolvePassword, "HOP_SECRET_KEY": sk}
	pwLogin := []string{"auth", "login", "--method", "password", "--server", w.origin, "--email", authEmail, "--name", "m2"}
	s := &session{env: pw}
	code := m2.hop(t, s, pwLogin...)
	if code != 255 || !strings.Contains(s.stderr.String(), "hop auth login --discard") {
		t.Fatalf("password login behind an unfinished enrollment: exit %d, stderr %q (want a pointer to hop auth login --discard)", code, s.stderr.String())
	}

	// Without a terminal it asks for --yes, and discards nothing.
	s = &session{}
	if code := m2.hop(t, s, "auth", "login", "--discard"); code != 255 || !strings.Contains(s.stderr.String(), "--yes") {
		t.Errorf("--discard without --yes or a terminal: exit %d, %q", code, s.stderr.String())
	}
	// On a terminal, anything but yes keeps it.
	s = &session{tty: true, answer: func(string) string { return "n" }}
	if code := m2.hop(t, s, "auth", "login", "--discard"); code != 255 || !strings.Contains(s.stderr.String(), "not discarded") {
		t.Errorf("--discard answered no: exit %d, %q", code, s.stderr.String())
	}
	// Both leave the enrollment in place.
	if code := m2.hop(t, &session{env: pw}, pwLogin...); code != 255 {
		t.Fatalf("the enrollment was discarded without consent: exit %d", code)
	}

	var rep struct {
		Discarded bool `json:"discarded"`
	}
	decodeJSON(t, m2.must(t, nil, "auth", "login", "--discard", "--yes", "--json"), &rep)
	if !rep.Discarded {
		t.Errorf("report = %+v", rep)
	}
	s = &session{}
	if code := m2.hop(t, s, "auth", "login", "--discard", "--yes"); code != 255 || !strings.Contains(s.stderr.String(), "nothing to discard") {
		t.Errorf("a second --discard: exit %d, %q", code, s.stderr.String())
	}

	// The password login now goes through.
	s = &session{env: pw}
	if code := m2.hop(t, s, pwLogin...); code != 0 {
		t.Fatalf("password login after the discard: exit %d: %s", code, s.stderr.String())
	}
	if ok, _ := store.Exists(m2.data); !ok {
		t.Error("no vault after the password login")
	}
}
