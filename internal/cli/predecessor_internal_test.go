package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

// hop status under an operator's lock says how to get back in as a new
// device: the steps in order, with this device's own ID in the revoke
// command, and what each costs. A vault that is locked for another
// reason, or unlocked, gets none of it.
func TestAdminLockHelpSteps(t *testing.T) {
	blocked := &store.Info{Locked: true, ServerUnconfirmed: true, DeviceID: "0123456789abcdef0123456789abcdef",
		AdminLock: &store.AdminRefusal{Code: store.AdminDeviceBlocked}}
	got := strings.Join(adminLockHelp(blocked), "\n")
	for _, w := range []string{
		"hop auth logout --discard-pending", "queued changes on this device are lost", "hop auth logout --local-only --discard-pending",
		"hop auth login", "master password and the current Secret Key",
		"hop auth devices revoke 0123456789abcdef0123456789abcdef", "hop auth rotate", "hop key rotate",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("the steps for a blocked device lack %q:\n%s", w, got)
		}
	}
	if i, j := strings.Index(got, "hop auth logout"), strings.Index(got, "hop auth login"); i < 0 || j < i {
		t.Errorf("the logout does not come before the login:\n%s", got)
	}
	disabled := &store.Info{Locked: true, DeviceID: "ab", AdminLock: &store.AdminRefusal{Code: store.AdminAccountDisabled}}
	if got := strings.Join(adminLockHelp(disabled), "\n"); !strings.Contains(got, "while the account is disabled") || !strings.Contains(got, "hop auth logout") {
		t.Errorf("the steps for a disabled account:\n%s", got)
	}
	for name, v := range map[string]*store.Info{
		"unlocked":       {AdminLock: blocked.AdminLock},
		"no lock":        {Locked: true, ServerUnconfirmed: true},
		"revoked":        {Locked: true, Revoked: true, AdminLock: blocked.AdminLock},
		"server report":  {Locked: true, ServerReport: &store.ServerReport{}, AdminLock: blocked.AdminLock},
		"nothing at all": nil,
	} {
		if h := adminLockHelp(v); h != nil {
			t.Errorf("%s: steps %q", name, h)
		}
	}
	// The steps are part of hop status, under the vault line.
	var out strings.Builder
	printVaultStatus(&Env{Stdout: &out}, blocked)
	if s := out.String(); !strings.Contains(s, "vault:        locked") || strings.Index(s, "hop auth logout") < strings.Index(s, "vault:") ||
		strings.Index(s, "hop auth logout") > strings.Index(s, "device key:") {
		t.Errorf("hop status:\n%s", s)
	}
}

func predecessorOf(dev byte, outcome, why string, queued, held int) store.Predecessor {
	return store.Predecessor{AccountID: model.ID{1}, DeviceID: model.ID{2, dev}, Server: "https://hop.example", Email: "a@example.com",
		Outcome: outcome, Why: why, Queued: queued, Held: held}
}

// The sign-in after a logout reports each old identity once, with the
// exact command and nothing run: still in the account (revoke it), gone
// after the server took the retirement (rotate, when the device was
// locked out), a --local-only logout whose device left meanwhile
// (nothing to do). Another account's entry is not reported.
func TestOldDeviceReports(t *testing.T) {
	acct := model.ID{1}.String()
	still, retired, left := predecessorOf(1, store.OutcomeUnknown, store.AdminDeviceBlocked, 3, 1), predecessorOf(2, store.OutcomeCommitted, store.AdminAccountDisabled, 0, 0),
		predecessorOf(3, store.OutcomeUnknown, "", 0, 0)
	other := predecessorOf(4, store.OutcomeUnknown, "", 0, 0)
	other.AccountID = model.ID{9}
	entries := []store.Predecessor{still, retired, left, other}
	active := []store.DeviceListing{{ID: still.DeviceID}, {ID: model.ID{7}, This: true}}

	rs := oldDevices(entries, acct, active, true)
	if len(rs) != 3 {
		t.Fatalf("reports %+v; want the three of this account", rs)
	}
	if r := rs[0]; !r.StillInAccount || r.Command != "hop auth devices revoke "+still.DeviceID.String() || r.DiscardedChanges != 3 || r.HeldChanges != 1 || r.Why != store.AdminDeviceBlocked {
		t.Errorf("still in the account: %+v", r)
	}
	if r := rs[1]; r.StillInAccount || r.Command != "hop auth rotate" {
		t.Errorf("retired after a lock: %+v", r)
	}
	if r := rs[2]; r.StillInAccount || r.Command != "" {
		t.Errorf("gone meanwhile: %+v", r)
	}
	// Without the device list, a logout that did not tell the server is
	// taken to have left the identity in the account.
	rs = oldDevices(entries, acct, nil, false)
	if !rs[0].StillInAccount || rs[1].StillInAccount || !rs[2].StillInAccount {
		t.Errorf("no device list: %+v", rs)
	}

	var out strings.Builder
	printOldDevices(&Env{Stdout: &out}, oldDevices(entries, acct, active, true))
	got := out.String()
	for _, w := range []string{
		"was blocked by the server's operator when you logged it out of the account",
		"The 3 change(s) it had queued, 1 of them held for your decision, were discarded",
		"is still in the account. Nothing was changed for you.",
		"    hop auth devices revoke " + still.DeviceID.String() + "\n",
		"the operator's disabling of the account had locked when you logged it out of the account",
		"That logout removed it from the account.",
		"    hop auth rotate\n",
		"is not in the account now: nothing is left to cut off",
		"hop key rotate",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("the report lacks %q:\n%s", w, got)
		}
	}
	if strings.Contains(got, other.DeviceID.String()) {
		t.Errorf("another account's identity is reported:\n%s", got)
	}
	if n := strings.Count(got, "hop auth devices revoke"); n != 1 {
		t.Errorf("%d revoke commands:\n%s", n, got)
	}
}

// Only an identity that is not still in the account is forgotten, and
// only when the device list could be read.
func TestSettleOldDevices(t *testing.T) {
	dir := t.TempDir()
	still, gone := predecessorOf(1, store.OutcomeUnknown, "", 0, 0), predecessorOf(2, store.OutcomeCommitted, store.AdminDeviceBlocked, 0, 0)
	other := predecessorOf(3, store.OutcomeUnknown, "", 0, 0)
	other.AccountID = model.ID{9}
	writePredecessorFile(t, dir, still, gone, other)
	entries, _ := store.ReadPredecessors(dir)
	active := []store.DeviceListing{{ID: still.DeviceID}}
	if err := settleOldDevices(dir, entries, model.ID{1}.String(), active, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.ReadPredecessors(dir); len(got) != 3 {
		t.Fatalf("settled without a device list: %+v", got)
	}
	if err := settleOldDevices(dir, entries, model.ID{1}.String(), active, true); err != nil {
		t.Fatal(err)
	}
	got, _ := store.ReadPredecessors(dir)
	if len(got) != 2 || got[0].DeviceID != still.DeviceID || got[1].DeviceID != other.DeviceID {
		t.Fatalf("after settling: %+v", got)
	}
	// What stays has been reported; another account's entry was not.
	if !got[0].IsReported() || got[1].IsReported() {
		t.Errorf("reported marks after settling: %+v", got)
	}
}

func writePredecessorFile(t *testing.T, dir string, entries ...store.Predecessor) {
	t.Helper()
	b, err := canonjson.Marshal(struct {
		V       int                 `json:"v"`
		Entries []store.Predecessor `json:"entries"`
	}{1, entries})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "predecessor.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The server committed the old device's retirement but the answer was
// lost, and the logout was finished with --local-only: the outcome is
// unknown, the device is gone from the account, and the operator had
// locked it out. The sign-in still says to rotate, in text and in JSON,
// and does not claim nothing is left to do.
func TestOldDeviceGoneAfterALostAnswerStillAdvisesRotate(t *testing.T) {
	acct := model.ID{1}.String()
	p := predecessorOf(1, store.OutcomeUnknown, store.AdminDeviceBlocked, 2, 0)
	rs := oldDevices([]store.Predecessor{p}, acct, []store.DeviceListing{{ID: model.ID{7}, This: true}}, true)
	if len(rs) != 1 || rs[0].StillInAccount || rs[0].Command != "hop auth rotate" || rs[0].Outcome != store.OutcomeUnknown || rs[0].Why != store.AdminDeviceBlocked {
		t.Fatalf("report %+v", rs)
	}
	var out strings.Builder
	printOldDevices(&Env{Stdout: &out}, rs)
	got := out.String()
	for _, w := range []string{"is not in the account now", "    hop auth rotate\n", "keep only the devices you trust", "hop key rotate", "The 2 change(s) it had queued"} {
		if !strings.Contains(got, w) {
			t.Errorf("the text lacks %q:\n%s", w, got)
		}
	}
	if strings.Contains(got, "nothing is left to cut off") {
		t.Errorf("the text says nothing is left to do:\n%s", got)
	}
	b, err := json.Marshal(loginReport{OldDevices: rs})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{`"outcome":"unknown"`, `"why":"device_blocked"`, `"still_in_account":false`, `"command":"hop auth rotate"`} {
		if !strings.Contains(string(b), w) {
			t.Errorf("the JSON lacks %s: %s", w, b)
		}
	}
	// With no reason on record the same absent device needs nothing.
	q := predecessorOf(2, store.OutcomeUnknown, "", 0, 0)
	if rs := oldDevices([]store.Predecessor{q}, acct, nil, true); len(rs) != 1 || rs[0].Command != "" {
		t.Errorf("an absent device with no reason: %+v", rs)
	}
}

// hop auth status shows the advice for a retired old device before it
// consumes the entry: a sign-in that installed the new identity and
// stopped before it printed leaves the entry unreported, and the status
// that follows shows it, once. Entries with nothing to say, or already
// shown, are forgotten once the device list is known; nothing is
// forgotten without it.
func TestStatusShowsUnreportedAdviceBeforeConsumingIt(t *testing.T) {
	dir := t.TempDir()
	acct := model.ID{1}.String()
	active := []store.DeviceListing{{ID: model.ID{7}, This: true}}
	retired := predecessorOf(1, store.OutcomeUnknown, store.AdminDeviceBlocked, 0, 0)
	writePredecessorFile(t, dir, retired)
	entries, _ := store.ReadPredecessors(dir)

	// Without the device list nothing is forgotten (the entry shows,
	// because the logout did not tell the server).
	if _, done := reportOldDevices(dir, entries, acct, nil, false); done == nil {
		t.Fatal("no settle function")
	}
	if got, _ := store.ReadPredecessors(dir); len(got) != 1 {
		t.Fatalf("an entry was forgotten without a device list: %+v", got)
	}

	// The sign-in was interrupted before it reported: status shows it and
	// still keeps it until the output is out.
	shown, done := reportOldDevices(dir, entries, acct, active, true)
	if len(shown) != 1 || shown[0].Command != "hop auth rotate" || shown[0].StillInAccount {
		t.Fatalf("status shows %+v; want the rotate advice", shown)
	}
	if lines := strings.Join(oldDeviceLines(shown), "\n"); !strings.Contains(lines, "hop auth rotate") || !strings.Contains(lines, retired.DeviceID.String()) {
		t.Errorf("status lines:\n%s", lines)
	}
	if got, _ := store.ReadPredecessors(dir); len(got) != 1 || got[0].IsReported() {
		t.Fatalf("status consumed the entry before showing it: %+v", got)
	}
	// If the output never made it, the next status shows it again.
	if again, _ := reportOldDevices(dir, entries, acct, active, true); len(again) != 1 {
		t.Fatalf("a status that never printed consumed the advice: %+v", again)
	}
	done()
	if got, _ := store.ReadPredecessors(dir); len(got) != 1 || !got[0].IsReported() {
		t.Fatalf("after printing: %+v", got)
	}
	// Shown once: the next status forgets it without showing it.
	entries, _ = store.ReadPredecessors(dir)
	if again, _ := reportOldDevices(dir, entries, acct, active, true); len(again) != 0 {
		t.Errorf("the advice is shown twice: %+v", again)
	}
	if got, _ := store.ReadPredecessors(dir); len(got) != 0 {
		t.Errorf("the reported entry was not forgotten: %+v", got)
	}

	// An absent identity with nothing to say is forgotten at once; one
	// still in the account is shown every time and kept.
	plain, still := predecessorOf(2, store.OutcomeUnknown, "", 0, 0), predecessorOf(3, store.OutcomeUnknown, store.AdminDeviceBlocked, 0, 0)
	writePredecessorFile(t, dir, plain, still)
	entries, _ = store.ReadPredecessors(dir)
	for i := 0; i < 2; i++ {
		shown, done := reportOldDevices(dir, entries, acct, append(active, store.DeviceListing{ID: still.DeviceID}), true)
		if len(shown) != 1 || !shown[0].StillInAccount || shown[0].DeviceID != still.DeviceID.String() {
			t.Fatalf("round %d: status shows %+v", i, shown)
		}
		done()
		entries, _ = store.ReadPredecessors(dir)
		if len(entries) != 1 || entries[0].DeviceID != still.DeviceID {
			t.Fatalf("round %d: kept %+v", i, entries)
		}
	}
}

// The sign-in's own settling marks what it printed reported and forgets
// the identities that are out of the account, so the status that follows
// does not repeat the advice.
func TestLoginSettlingMarksWhatItPrinted(t *testing.T) {
	dir := t.TempDir()
	acct := model.ID{1}.String()
	retired := predecessorOf(1, store.OutcomeUnknown, store.AdminDeviceBlocked, 0, 0)
	still := predecessorOf(2, store.OutcomeUnknown, "", 0, 0)
	writePredecessorFile(t, dir, retired, still)
	entries, _ := store.ReadPredecessors(dir)
	active := []store.DeviceListing{{ID: still.DeviceID}}
	if err := settleOldDevices(dir, entries, acct, active, true); err != nil {
		t.Fatal(err)
	}
	got, _ := store.ReadPredecessors(dir)
	if len(got) != 1 || got[0].DeviceID != still.DeviceID || !got[0].IsReported() {
		t.Fatalf("after the login: %+v", got)
	}
	if shown, _ := reportOldDevices(dir, got, acct, active, true); len(shown) != 1 || !shown[0].StillInAccount {
		t.Errorf("status after the login shows %+v", shown)
	}
}
