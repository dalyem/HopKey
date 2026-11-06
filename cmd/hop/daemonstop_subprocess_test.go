//go:build linux && !hopdev

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/store"
)

// hop daemon stop returns once the daemon's sockets are gone, and the next
// command starts a daemon at once. The old daemon closes its store only
// after its sockets are gone, so a daemon started in between found the
// vault busy and exited, and the command waited out its whole start
// timeout and failed. These run the real binary: stop, then the next
// command, again and again.
const stopStartRounds = 60

func TestSubprocessDaemonStopThenNextCommand(t *testing.T) {
	bins := t.TempDir()
	hopBin, serverBin := filepath.Join(bins, "hop"), filepath.Join(bins, "hop-server")
	for _, b := range []struct{ out, pkg string }{
		{hopBin, "github.com/dalyem/hopkey/cmd/hop"},
		{serverBin, "github.com/dalyem/hopkey/cmd/hop-server"},
	} {
		build := exec.Command(goTool(t), "build", "-o", b.out, b.pkg)
		build.Dir = "../.."
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", b.pkg, err, out)
		}
	}
	// On a disk, as a user's vault is: closing the store then takes real
	// time, which a tmpfs does not (the window this test is about is the
	// old daemon's close, after its sockets are gone).
	tmp := "/var/tmp"
	if fi, err := os.Stat(tmp); err != nil || !fi.IsDir() {
		tmp = ""
	}
	base, err := os.MkdirTemp(tmp, "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	certFile, keyFile, pool := writeTestCert(t, base)
	origin := startServer(t, serverBin, base, certFile, keyFile, pool)
	invite := strings.TrimSpace(mustRun(t, serverBin, "invite", subEmail, "--data", filepath.Join(base, "server")))
	a := newSubHome(t, hopBin, base, "a", certFile)
	// The device key in a sealed file, opened by the variable each command
	// is given: every daemon a command starts opens the vault itself.
	env := []string{store.PassphraseEnv + "=a long enough device passphrase"}

	p := a.startPTY(t, env, "init", "--device-key-store", "file")
	p.expect(t, "Master password: ")
	p.send(subPassword)
	p.expect(t, "Repeat it: ")
	p.send(subPassword)
	out := p.expect(t, "Type the last group of your Secret Key: ")
	sk, rk := subKitKeys(t, out)
	p.send(store.LastGroup(sk))
	p.expect(t, "Type the last group of your Recovery Key: ")
	p.send(store.LastGroup(rk))
	if code := p.wait(t, 60*time.Second); code != 0 {
		t.Fatalf("hop init: exit %d\n%s", code, p.output())
	}
	a.must(t, env, "add", "web", "--address", "203.0.113.10", "--user", "deploy")
	// Signed in, the daemon syncs, which it must finish before it lets go
	// of the vault.
	a.must(t, append(slices.Clone(env), "HOP_PASSWORD="+subPassword, "HOP_SECRET_KEY="+sk), "auth", "signup",
		"--server", origin, "--email", subEmail, "--code", invite, "--json")

	dataDir := filepath.Join(base, "a", "data", "hop")
	var slowest time.Duration
	var busyAfterStop int
	for i := range stopStartRounds {
		a.must(t, env, "daemon", "stop")
		// What the next command's daemon runs into: the old one's sockets
		// are gone, so stop has returned, but does it still own the vault?
		if busy, err := store.Busy(dataDir); err != nil {
			t.Fatal(err)
		} else if busy {
			busyAfterStop++
		}
		start := time.Now()
		code, _, stderr := a.hop(t, env, "ls", "--json")
		took := time.Since(start)
		slowest = max(slowest, took)
		if code != 0 {
			t.Fatalf("round %d: the command right after hop daemon stop failed after %s: exit %d: %s", i, took, code, stderr)
		}
		if took > 5*time.Second {
			t.Errorf("round %d: the command right after hop daemon stop took %s", i, took)
		}
	}
	t.Logf("%d rounds, slowest %s, vault still owned when stop returned in %d", stopStartRounds, slowest, busyAfterStop)
	if busyAfterStop != 0 {
		t.Errorf("hop daemon stop returned while the daemon still owned the vault in %d of %d rounds", busyAfterStop, stopStartRounds)
	}
}
