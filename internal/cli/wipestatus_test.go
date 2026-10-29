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
// pending, with the daemon stopped and with it running (and calling the
// device wiped).
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
	f.reply(daemon.OpStatus, daemon.StatusResult{
		Version: "test", PID: 1, StartedAt: f.now,
		Sync: &daemon.SyncStatusResult{State: daemon.SyncRevoked, ServerRetirement: &daemon.ServerRetirement{How: "revoked", Seq: 9, Wiped: true}},
	})
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
			if !a.Revoked || a.Wiped == want || a.WipePending != want || a.Revocation == nil {
				t.Errorf("%s: --json: revoked %v, wiped %v, wipe pending %v (want %v), revocation %v", name, a.Revoked, a.Wiped, a.WipePending, want, a.Revocation)
			}
		}
	}
}
