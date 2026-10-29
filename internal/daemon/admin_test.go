package daemon

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/server"
	"github.com/dalyem/hopkey/internal/store"
)

// Tests for the server's operator refusing this device (hop-server
// accounts disable, devices block): on every path a refusal can arrive
// by, background pull, push, hop sync and session renewal, daemon start
// and hop unlock, the vault locks in memory, the agent empties and the
// ssh sessions hop started end, nothing is recorded or deleted, and the
// vault unlocks once the operator lets the device in. A server that can't
// be reached still lets keys load at start, as before, but does not undo
// a lock the refusal made.

func adminOp() server.Operator { return server.Operator{Actor: "test", Now: time.Now().UTC()} }

// disableAccount disables the account with reason, sanitized as
// hop-server accounts disable does.
func disableAccount(t *testing.T, w *syncWorld, reason string) {
	t.Helper()
	ctx := context.Background()
	reason, err := server.SanitizeReason(reason)
	if err != nil {
		t.Fatal(err)
	}
	p, err := server.PlanDisable(ctx, w.st, syncEmail, adminOp())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.DisableAccount(ctx, w.st, adminOp(), syncEmail, reason, p); err != nil {
		t.Fatal(err)
	}
}

func enableAccount(t *testing.T, w *syncWorld) {
	t.Helper()
	ctx := context.Background()
	p, err := server.PlanEnable(ctx, w.st, syncEmail, adminOp())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.EnableAccount(ctx, w.st, adminOp(), syncEmail, p); err != nil {
		t.Fatal(err)
	}
}

func blockDevice(t *testing.T, w *syncWorld, dev model.ID, reason string) {
	t.Helper()
	ctx := context.Background()
	sel := server.DeviceSelection{IDs: []string{dev.String()}}
	p, err := server.PlanBlockDevices(ctx, w.st, syncEmail, sel, adminOp())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.BlockDevices(ctx, w.st, adminOp(), syncEmail, sel, reason, p); err != nil {
		t.Fatal(err)
	}
}

func unblockDevice(t *testing.T, w *syncWorld, dev model.ID) {
	t.Helper()
	ctx := context.Background()
	sel := server.DeviceSelection{IDs: []string{dev.String()}}
	p, err := server.PlanUnblockDevices(ctx, w.st, syncEmail, sel, adminOp())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.UnblockDevices(ctx, w.st, adminOp(), syncEmail, sel, p); err != nil {
		t.Fatal(err)
	}
}

// adminLocked checks that the operator's refusal (code, reason) keeps n
// locked: the agent empty, the vault locked in memory and labelled, in
// the store and in the daemon's status, and nothing recorded or deleted.
func adminLocked(t *testing.T, n *node, code, reason string) {
	t.Helper()
	if k := n.agentKeys(); k != 0 {
		t.Errorf("%s: the agent serves %d key(s)", n.name, k)
	}
	info := n.st.Info()
	if !info.Locked || !info.ServerUnconfirmed || info.AdminLock == nil || info.AdminLock.Code != code || info.AdminLock.Reason != reason {
		t.Errorf("%s: the vault is not locked by the operator's %s (%q): %+v, %+v", n.name, code, reason, info, info.AdminLock)
	}
	var st StatusResult
	n.must(OpStatus, nil, &st)
	if st.Vault == nil || st.Vault.AdminLock == nil || st.Vault.AdminLock.Code != code {
		t.Errorf("%s: status does not say the operator locked it: %+v", n.name, st.Vault)
	}
	if st.Sync == nil || st.Sync.State == SyncRevoked || st.Sync.ServerRetirement != nil {
		t.Errorf("%s: a refusal counted as a revocation: %+v", n.name, st.Sync)
	}
	data := n.cfg.DataDir
	if exists(t, filepath.Join(data, "vault", "server-revoked.json")) {
		t.Errorf("%s: a report was recorded", n.name)
	}
	if !exists(t, filepath.Join(data, "device.json")) || !exists(t, filepath.Join(data, "vault", "state.json")) {
		t.Fatalf("%s: the vault was deleted", n.name)
	}
}

// A disable reaches a running daemon through its long-poll, with no hop
// command run: the poll's session is gone, the renewal is refused with
// account_disabled, and both devices lock and end their watched ssh
// sessions; a session started meanwhile ends at once. The loop asks again
// and stays locked; once the account is enabled, it unlocks by itself.
func TestDisableLocksTheBackgroundPull(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{Wait: time.Second})
	x.w.start(x.n2, x.n2.st, SyncOptions{Wait: time.Second})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 10*time.Second, "web1 reaches the laptop", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })
	if k := x.n2.agentKeys(); k != 1 {
		t.Fatalf("setup: the agent serves %d key(s)", k)
	}
	session := watchAt(t, x.n2.d.ControlSocket(), "web1", "")

	disableAccount(t, x.w, "billing \x1b[2Joverdue")
	eventually(t, 15*time.Second, "the laptop locks", func() bool { return x.n2.agentKeys() == 0 })
	eventually(t, 15*time.Second, "the desk locks", func() bool { return x.n1.agentKeys() == 0 })
	session.ended(t, 5*time.Second, whyDisabled)
	for _, n := range []*node{x.n1, x.n2} {
		adminLocked(t, n, store.AdminAccountDisabled, "billing [2Joverdue")
	}
	if e := endedStatus(t, x.n2); e == nil || e.Why != whyDisabled || e.TerminationRequests != 1 {
		t.Errorf("ended sessions in status: %+v", e)
	}
	watchAt(t, x.n2.d.ControlSocket(), "web2", whyDisabled)

	// The loop asks again: still refused, still locked.
	if x.n2.d.retryUnconfirmed(context.Background()) {
		t.Fatal("the retry unlocked a disabled account's vault")
	}
	adminLocked(t, x.n2, store.AdminAccountDisabled, "billing [2Joverdue")

	enableAccount(t, x.w)
	x.n2.d.sync.wake()
	eventually(t, 10*time.Second, "the laptop's key is back after the enable", func() bool { return x.n2.agentKeys() == 1 })
	if info := x.n2.st.Info(); info.Locked || info.AdminLock != nil {
		t.Errorf("after the enable: %+v", info)
	}
	watchAt(t, x.n2.d.ControlSocket(), "web1", "")
}

// A change queued while the account was disabled is pushed by the loop,
// which is refused and locks; the change stays queued, and reaches the
// server after the enable.
func TestDisableLocksAPush(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n2, x.n2.st, SyncOptions{noPoll: true})
	if k := x.n2.agentKeys(); k != 1 {
		t.Fatalf("setup: the agent serves %d key(s)", k)
	}
	x.n2.pause(true)
	x.n2.putHost(webHost("web2", x.keyID, "203.0.113.17"))
	if p := x.n2.status().Pending; p != 1 {
		t.Fatalf("setup: %d pending", p)
	}
	var refused atomic.Int32
	x.w.setIntercept(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		if req.URL.Path == "/v1/auth/session" {
			refused.Add(1)
		}
		return false
	})
	disableAccount(t, x.w, "")
	x.n2.pause(false)
	eventually(t, 15*time.Second, "the push is refused and the laptop locks", func() bool { return x.n2.agentKeys() == 0 })
	if refused.Load() == 0 {
		t.Fatal("setup: no session was asked for")
	}
	adminLocked(t, x.n2, store.AdminAccountDisabled, "")

	enableAccount(t, x.w)
	x.n2.d.sync.wake()
	eventually(t, 10*time.Second, "the queued change is pushed after the enable", func() bool {
		return x.n2.agentKeys() == 1 && x.n2.status().Pending == 0
	})
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	eventually(t, 10*time.Second, "the change reaches the desk", func() bool { return x.n1.host("web2") != nil })
}

// hop sync on a blocked device is refused with device_blocked and locks
// that device only: the account's other device syncs on, and the session
// renewal of the blocked one stays refused until the unblock.
func TestBlockLocksHopSyncOnThatDeviceOnly(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{noPoll: true})
	x.w.start(x.n2, x.n2.st, SyncOptions{noPoll: true})
	x.n1.must(OpSyncNow, nil, nil)
	x.n2.must(OpSyncNow, nil, nil)
	laptop := laptopID(t, x.n2)

	blockDevice(t, x.w, laptop, "lost on a train")
	err := x.n2.call(OpSyncNow, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "operator blocked this device") || !strings.Contains(err.Error(), "lost on a train") {
		t.Errorf("hop sync on a blocked device: %v", err)
	}
	adminLocked(t, x.n2, store.AdminDeviceBlocked, "lost on a train")
	x.n1.must(OpSyncNow, nil, nil)
	if k := x.n1.agentKeys(); k != 1 {
		t.Errorf("the desk serves %d key(s) after the laptop's block", k)
	}
	if err := x.n2.call(OpUnlock, nil, nil); err == nil {
		t.Error("hop unlock on a blocked device unlocked it")
	}
	adminLocked(t, x.n2, store.AdminDeviceBlocked, "lost on a train")

	unblockDevice(t, x.w, laptop)
	x.n2.d.sync.wake()
	eventually(t, 10*time.Second, "the laptop's key is back after the unblock", func() bool { return x.n2.agentKeys() == 1 })
}

// A daemon that starts for a disabled account locks before any key loads.
func TestDisableLocksAtStart(t *testing.T) {
	x := newSyncSetup(t)
	disableAccount(t, x.w, "")
	x.w.startWatched(x.n2, x.n2.st) // fails if the agent ever served a key
	adminLocked(t, x.n2, store.AdminAccountDisabled, "")
}

// hop unlock of a disabled account's vault is refused before any key
// loads, with the operator's word; after the enable it unlocks.
func TestDisableRefusesUnlock(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n2, x.n2.st, SyncOptions{noPoll: true})
	x.n2.must(OpLock, nil, nil)
	disableAccount(t, x.w, "audit")
	err := x.n2.call(OpUnlock, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "operator disabled this account") {
		t.Errorf("hop unlock of a disabled account: %v", err)
	}
	adminLocked(t, x.n2, store.AdminAccountDisabled, "audit")

	enableAccount(t, x.w)
	x.n2.must(OpUnlock, nil, nil)
	if k := x.n2.agentKeys(); k != 1 {
		t.Errorf("after the enable, hop unlock loaded %d key(s)", k)
	}
}

// A server that can't be reached still lets keys load at start, as for
// any device offline, even for a disabled account: the device can't know.
// Once it reaches the server, the first refusal locks; and from then on an
// unreachable server does not undo the lock, neither at the loop's retry
// nor at hop unlock.
func TestUnreachableFailsOpenButKeepsAnAdminLock(t *testing.T) {
	x := newSyncSetup(t)
	disableAccount(t, x.w, "")
	x.w.down.Store(true)
	x.w.start(x.n2, x.n2.st, SyncOptions{noPoll: true})
	if k := x.n2.agentKeys(); k != 1 {
		t.Fatalf("an unreachable server at start: the agent serves %d key(s), want the keys loaded", k)
	}
	if s := x.n2.status(); s.CheckSkipped == "" {
		t.Errorf("status does not say the check was skipped: %+v", s)
	}

	x.w.down.Store(false)
	if err := x.n2.call(OpSyncNow, nil, nil); err == nil {
		t.Fatal("hop sync of a disabled account worked")
	}
	adminLocked(t, x.n2, store.AdminAccountDisabled, "")

	x.w.down.Store(true)
	if x.n2.d.retryUnconfirmed(context.Background()) {
		t.Error("the retry unlocked with the server unreachable")
	}
	adminLocked(t, x.n2, store.AdminAccountDisabled, "")
	err := x.n2.call(OpUnlock, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "could not be asked again") {
		t.Errorf("hop unlock with the server unreachable: %v", err)
	}
	adminLocked(t, x.n2, store.AdminAccountDisabled, "")

	// Reachable and enabled again: hop unlock opens it.
	x.w.down.Store(false)
	enableAccount(t, x.w)
	x.n2.must(OpUnlock, nil, nil)
	if k := x.n2.agentKeys(); k != 1 {
		t.Errorf("after the enable, the agent serves %d key(s)", k)
	}
}

// A device key sealed with a device passphrase: the daemon has none to
// ask the server with, so after the enable its retry can't unlock, and
// the lock keeps its reason rather than turning into a device-key error;
// hop unlock with the passphrase opens it.
func TestAdminLockWithASealedDeviceKey(t *testing.T) {
	x := newSyncSetup(t)
	cfg := syncStoreConfig(t, "sealed")
	cfg.Getenv = func(k string) string {
		if k == store.PassphraseEnv {
			return sealedPassphrase
		}
		return ""
	}
	n := &node{t: t, name: "sealed", cfg: cfg, st: signInSealed(t, x.w.client(t), cfg, x.kit, x.pub)}
	x.w.start(n, n.st, SyncOptions{noPoll: true})
	n.must(OpSyncNow, nil, nil)
	// As a service starts it: no passphrase.
	n.cfg.Getenv = func(string) string { return "" }
	x.w.restart(n)
	if err := n.call(OpUnlock, UnlockParams{DevicePassphrase: sealedPassphrase}, nil); err != nil {
		t.Fatalf("setup: hop unlock with the passphrase: %v", err)
	}

	disableAccount(t, x.w, "")
	if err := n.call(OpSyncNow, nil, nil); err == nil {
		t.Fatal("hop sync of a disabled account worked")
	}
	adminLocked(t, n, store.AdminAccountDisabled, "")
	enableAccount(t, x.w)
	if n.d.retryUnconfirmed(context.Background()) {
		t.Fatal("the retry unlocked a sealed device key without its passphrase")
	}
	adminLocked(t, n, store.AdminAccountDisabled, "")
	if err := n.call(OpUnlock, UnlockParams{DevicePassphrase: sealedPassphrase}, nil); err != nil {
		t.Fatalf("hop unlock with the passphrase after the enable: %v", err)
	}
	if k := n.agentKeys(); k != 1 {
		t.Errorf("after hop unlock, the agent serves %d key(s)", k)
	}
}

// A device of a disabled account can still log out: with no session, the
// retirement goes through retire-status and retire-post, and the device
// is wiped as a logout does; the server records it retired.
func TestLogoutWhileDisabled(t *testing.T) {
	x := newSyncSetup(t)
	ctx := context.Background()
	laptop := laptopID(t, x.n2)
	disableAccount(t, x.w, "")
	res, err := x.n2.st.Logout(ctx, x.w.client(t).Retirer(x.pub.VaultID), store.LogoutOptions{})
	if err != nil || !res.Done {
		t.Fatalf("logout of a disabled account's device: %+v, %v", res, err)
	}
	var dev *server.Device
	if err := x.w.st.View(ctx, func(tx server.Tx) (err error) {
		dev, err = tx.Device(x.pub.AccountID, laptop)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if dev.Active {
		t.Error("the server still has the laptop active")
	}
	if exists(t, filepath.Join(x.n2.cfg.DataDir, "device.json")) {
		t.Error("the logout left device.json")
	}
}
