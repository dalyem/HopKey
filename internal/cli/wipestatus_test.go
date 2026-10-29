package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/sshconfig"
	"github.com/dalyem/hopkey/internal/store"
)

// hop auth status calls a verified revocation wiped only once the ssh
// files hop wrote are gone too: while the logout's cleanup mark is there,
// or ~/.ssh/hop still holds what the vault decrypted, it says the wipe is
// pending. With the daemon stopped it decides that itself
// (daemon.CleanupLeft); with it running it goes by the daemon's sync
// status, which decides it the same way, so its text, its JSON, the JSON's
// sync block and hop status all agree.
func TestAuthStatusWipedOnlyOnceTheSSHFilesAreGone(t *testing.T) {
	f := newFakeDaemon(t)
	data := filepath.Join(f.base, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := canonjson.Marshal(store.RevocationRecord{V: 1, How: "revoked", Seq: 9, At: model.TimestampOf(f.now)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "revocation.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	mark := filepath.Join(data, "logout-cleanup")
	setMark := func(on bool) {
		t.Helper()
		if !on {
			if err := os.Remove(mark); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			return
		}
		if err := os.WriteFile(mark, []byte("pending\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	setFiles := func(on bool) {
		t.Helper()
		if on {
			plantHopSSH(t, f.paths.ConfigDir, f.home)
			return
		}
		if err := sshconfig.Wipe(sshconfig.Options{Dir: f.paths.ConfigDir, AgentSocket: filepath.Join(f.paths.ConfigDir, "agent.sock")}); err != nil {
			t.Fatal(err)
		}
	}
	// What the daemon answers when the files are gone, or not.
	daemonSays := func(left bool) {
		r := &daemon.ServerRetirement{How: "revoked", Seq: 9, Wiped: !left, SSHFilesLeft: left}
		if left {
			r.WipeError = "the ssh files hop wrote are not removed yet: " + f.paths.ConfigDir + " still holds what the vault decrypted"
		}
		f.reply(daemon.OpStatus, daemon.StatusResult{
			Version: "test", PID: 1, StartedAt: f.now,
			Sync: &daemon.SyncStatusResult{State: daemon.SyncRevoked, ServerRetirement: r},
		})
	}
	stopped := func(e *cli.Env) { e.DataDir, e.Paths.RunDir = data, filepath.Join(f.base, "no-daemon") }
	running := func(e *cli.Env) { e.DataDir = data }
	const pending = "verified; wipe pending (ssh files remain under ~/.ssh/hop; any hop command or the daemon retries)"

	for _, c := range []struct {
		name        string
		mark, files bool
	}{
		{"the mark and the files", true, true},
		{"the mark alone", true, false},
		{"the files alone", false, true},
		{"neither", false, false},
	} {
		setMark(c.mark)
		setFiles(c.files)
		want := c.mark || c.files
		daemonSays(want)
		for daemonName, adjust := range map[string]func(*cli.Env){"stopped": stopped, "running": running} {
			name := c.name + ", daemon " + daemonName
			code, out, errOut := f.hopWith(t, adjust, "auth", "status")
			if code != 0 {
				t.Fatalf("%s: exit %d: %s", name, code, errOut)
			}
			if got := strings.Contains(out, pending); got != want {
				t.Errorf("%s: says the wipe is pending: %v, want %v:\n%s", name, got, want, out)
			}
			if got := strings.Contains(out, "wiped:        this device's copy"); got == want {
				t.Errorf("%s: says it was wiped: %v, want %v:\n%s", name, got, !want, out)
			}
			code, out, errOut = f.hopWith(t, adjust, "auth", "status", "--json")
			if code != 0 {
				t.Fatalf("%s: --json: exit %d: %s", name, code, errOut)
			}
			var a cli.AuthStatus
			if err := json.Unmarshal([]byte(out), &a); err != nil {
				t.Fatalf("%s: --json: %v: %s", name, err, out)
			}
			if !a.Revoked || a.Wiped == want || a.WipePending != want || a.Revocation == nil || a.Vault {
				t.Errorf("%s: --json: revoked %v, wiped %v, wipe pending %v (want %v), revocation %v, vault %v",
					name, a.Revoked, a.Wiped, a.WipePending, want, a.Revocation, a.Vault)
			}
			if daemonName == "stopped" {
				continue
			}
			if r := a.Sync.ServerRetirement; r == nil || r.Wiped != a.Wiped || r.SSHFilesLeft != a.WipePending {
				t.Errorf("%s: --json: the sync block disagrees: %+v", name, r)
			}
			code, out, errOut = f.hopWith(t, adjust, "status")
			if code != 0 {
				t.Fatalf("%s: hop status: exit %d: %s", name, code, errOut)
			}
			if got := strings.Contains(out, "its copy of the vault was wiped"); got == want {
				t.Errorf("%s: hop status says wiped: %v, want %v:\n%s", name, got, !want, out)
			}
			if got := strings.Contains(out, "the wipe has not finished"); got != want {
				t.Errorf("%s: hop status says the wipe is pending: %v, want %v:\n%s", name, got, want, out)
			}
		}
	}
}

// With no daemon, the next hop command that finds no vault removes the
// ssh files a wiped device still has, mark or not, as hop auth status
// says it does: here hop daemon, which finds none to serve.
func TestSSHFilesLeftAfterAWipeAreRemovedWithNoMark(t *testing.T) {
	f := newFakeDaemon(t)
	data := filepath.Join(f.base, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := canonjson.Marshal(store.RevocationRecord{V: 1, How: "revoked", Seq: 9, At: model.TimestampOf(f.now)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "revocation.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	check := plantHopSSH(t, f.paths.ConfigDir, f.home)
	stopped := func(e *cli.Env) {
		e.DataDir, e.Paths.RunDir = data, filepath.Join(f.base, "no-daemon")
		e.OpenStore = func() (model.Store, error) { return nil, store.ErrNoVault }
	}
	if code, _, errOut := f.hopWith(t, stopped, "daemon"); code == 0 {
		t.Fatalf("hop daemon with no vault: exit 0: %s", errOut)
	}
	check()
	if pending, err := store.LogoutCleanupPending(data); pending || err != nil {
		t.Errorf("the cleanup mark is left: %v, %v", pending, err)
	}
	code, out, errOut := f.hopWith(t, stopped, "auth", "status")
	if code != 0 || !strings.Contains(out, "wiped:        this device's copy") {
		t.Errorf("auth status after the cleanup: exit %d: %s%s", code, out, errOut)
	}
}
