package cli_test

import (
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/store"
)

// On a revoked device, hop unlock says so and never suggests itself.
func TestUnlockOnARevokedDeviceSaysSo(t *testing.T) {
	f := newFakeDaemon(t)
	f.fail(daemon.OpUnlock, daemon.CodeRevoked, "vault is locked: the server reports that this device was revoked")
	code, _, errOut := f.hop(t, "unlock")
	if code == 0 {
		t.Fatal("hop unlock succeeded on a revoked device")
	}
	for _, want := range []string{"revoked", "hop auth logout", "hop auth login"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q: %s", want, errOut)
		}
	}
	if strings.Contains(errOut, "run hop unlock") {
		t.Errorf("stderr suggests hop unlock: %s", errOut)
	}
	if n := len(f.called(daemon.OpUnlock)); n != 1 {
		t.Errorf("hop unlock asked the daemon %d times", n)
	}

	f.fail(daemon.OpUnlock, daemon.CodeOffline, "vault is locked: offline too long; connect to the server (the last server contact was 2h0m0s ago)")
	if code, _, errOut = f.hop(t, "unlock"); code == 0 || !strings.Contains(errOut, "offline too long; connect to the server") {
		t.Errorf("offline too long: exit %d, %s", code, errOut)
	}
}

// hop status and hop auth status on a device the server reports revoked
// say what happened, and hop auth devices says why it lists nothing.
func TestStatusOnAReportedRevocation(t *testing.T) {
	f := newFakeDaemon(t)
	st := daemon.StatusResult{
		Version: "test", PID: 1, StartedAt: f.now,
		Vault: &store.Info{Locked: true, DeviceStore: "keychain", ServerReport: &store.ServerReport{How: "revoked", Seq: 12}},
		Sync: &daemon.SyncStatusResult{
			State: daemon.SyncRevoked, Server: "https://hop.example", Email: "me@example.com",
			ServerRetirement: &daemon.ServerRetirement{How: "revoked", Seq: 12, Unverified: true},
		},
	}
	f.reply(daemon.OpStatus, st)
	_, out, _ := f.hop(t, "status")
	if !strings.Contains(out, "the server reports this device was revoked") || strings.Contains(out, "run hop unlock") {
		t.Errorf("hop status:\n%s", out)
	}
	_, out, _ = f.hop(t, "auth", "status")
	for _, want := range []string{"signed in:    no; the server reports that this device was revoked from the account at seq 12", "hop auth logout", "hop unlock refuses"} {
		if !strings.Contains(out, want) {
			t.Errorf("hop auth status lacks %q:\n%s", want, out)
		}
	}
	f.fail(daemon.OpDevicesList, daemon.CodeRevoked, "revoked")
	code, _, errOut := f.hop(t, "auth", "devices")
	if code == 0 || !strings.Contains(errOut, "this device was revoked from the account") || strings.Contains(errOut, "run hop unlock") {
		t.Errorf("hop auth devices: exit %d, %s", code, errOut)
	}
}

// hop auth policy reads and sets the account's max-offline time.
func TestAuthPolicy(t *testing.T) {
	f := newFakeDaemon(t)
	f.reply(daemon.OpPolicy, daemon.PolicyResult{MaxOffline: 7 * 86400})
	_, out, _ := f.hop(t, "auth", "policy")
	if !strings.Contains(out, "max offline:  7d") {
		t.Errorf("hop auth policy:\n%s", out)
	}
	if code, _, errOut := f.hop(t, "auth", "policy", "--max-offline", "7d"); code != 0 {
		t.Fatalf("set: exit %d: %s", code, errOut)
	}
	calls := f.called(daemon.OpPolicy)
	if got := string(calls[len(calls)-1]); got != `{"max_offline":604800}` {
		t.Errorf("params %s", got)
	}
	f.hop(t, "auth", "policy", "--max-offline", "off")
	calls = f.called(daemon.OpPolicy)
	if got := string(calls[len(calls)-1]); got != `{"max_offline":0}` {
		t.Errorf("off: params %s", got)
	}
	for _, bad := range []string{"10s", "soon", "-1h", "4000d"} {
		if code, _, _ := f.hop(t, "auth", "policy", "--max-offline", bad); code == 0 {
			t.Errorf("--max-offline %s was accepted", bad)
		}
	}
	f.fail(daemon.OpPolicy, daemon.CodeLocalOnly, "local")
	if code, _, errOut := f.hop(t, "auth", "policy"); code == 0 || !strings.Contains(errOut, "local-only") {
		t.Errorf("local-only: exit %d, %s", code, errOut)
	}
}
