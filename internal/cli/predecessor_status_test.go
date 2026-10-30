package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

type failingStdout struct{}

func (failingStdout) Write([]byte) (int, error) { return 0, os.ErrClosed }

// hop auth status consumes the advice about an earlier identity only if
// it was written: with a stdout that fails it exits non-zero and leaves
// the entry as it was; the next status, with a working stdout, shows the
// advice and marks the kind shown, and the one after forgets the entry.
func TestAuthStatusDoesNotConsumeAdviceItCouldNotWrite(t *testing.T) {
	f := newFakeDaemon(t)
	dir := t.TempDir()
	acct := model.ID{1}
	retired := store.Predecessor{AccountID: acct, DeviceID: model.ID{2, 1}, Server: "https://hop.example", Email: "a@example.com",
		Outcome: store.OutcomeCommitted, Why: store.AdminDeviceBlocked}
	b, err := canonjson.Marshal(struct {
		V       int                 `json:"v"`
		Entries []store.Predecessor `json:"entries"`
	}{1, []store.Predecessor{retired}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "predecessor.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	f.reply(daemon.OpStatus, daemon.StatusResult{
		Version: "test", PID: 1, StartedAt: f.now,
		Vault: &store.Info{DeviceID: "0123456789abcdef0123456789abcdef", DeviceStore: "file", AccountID: acct.String()},
	})
	f.reply(daemon.OpDevicesList, daemon.DevicesResult{Devices: []store.DeviceListing{{ID: model.ID{7}, This: true, Name: "laptop"}}})
	withDir := func(stdout *failingStdout) func(*cli.Env) {
		return func(e *cli.Env) {
			e.DataDir = dir
			if stdout != nil {
				e.Stdout = stdout
			}
		}
	}

	for _, args := range [][]string{{"auth", "status"}, {"auth", "status", "--json"}} {
		code, _, errOut := f.hopWith(t, withDir(&failingStdout{}), args...)
		if code == 0 {
			t.Errorf("%v with a stdout that fails exited 0; stderr %q", args, errOut)
		}
		if got, _ := store.ReadPredecessors(dir); len(got) != 1 || got[0].Reported != "" {
			t.Fatalf("%v consumed the advice it could not write: %+v", args, got)
		}
	}

	code, out, errOut := f.hopWith(t, withDir(nil), "auth", "status")
	if code != 0 || !strings.Contains(out, "hop auth rotate") || !strings.Contains(out, retired.DeviceID.String()) {
		t.Fatalf("status: exit %d, stderr %q:\n%s", code, errOut, out)
	}
	if got, _ := store.ReadPredecessors(dir); len(got) != 1 || got[0].Reported != store.AdviceRotate {
		t.Fatalf("after the advice was written: %+v", got)
	}
	code, out, _ = f.hopWith(t, withDir(nil), "auth", "status")
	if code != 0 || strings.Contains(out, "old device:") {
		t.Errorf("the advice is shown twice (exit %d):\n%s", code, out)
	}
	if got, _ := store.ReadPredecessors(dir); len(got) != 0 {
		t.Errorf("the shown entry was not forgotten: %+v", got)
	}
}
