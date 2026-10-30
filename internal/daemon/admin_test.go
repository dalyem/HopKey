package daemon

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/server"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
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
	// The session's end and status carry the operator's message.
	const why = whyDisabled + `: "billing [2Joverdue" (the server's word)`
	session.ended(t, 5*time.Second, why)
	for _, n := range []*node{x.n1, x.n2} {
		adminLocked(t, n, store.AdminAccountDisabled, "billing [2Joverdue")
	}
	if e := endedStatus(t, x.n2); e == nil || e.Why != why || e.TerminationRequests != 1 {
		t.Errorf("ended sessions in status: %+v", e)
	}
	watchAt(t, x.n2.d.ControlSocket(), "web2", why)

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

// The operator's message goes into why the ssh sessions end, attributed
// to the server, escaped and bounded: a server need not have stripped it.
func TestWhyAdminCarriesTheReason(t *testing.T) {
	for _, c := range []struct {
		refusal store.AdminRefusal
		want    string
	}{
		{store.AdminRefusal{Code: store.AdminAccountDisabled}, whyDisabled},
		{store.AdminRefusal{Code: store.AdminDeviceBlocked}, whyBlocked},
		{store.AdminRefusal{Code: store.AdminDeviceBlocked, Reason: "lost on a train"}, whyBlocked + `: "lost on a train" (the server's word)`},
		{store.AdminRefusal{Code: store.AdminAccountDisabled, Reason: "a\x1b[2J\u202eb\n"},
			whyDisabled + `: "a\x1b[2J\u202eb\x0a" (the server's word)`},
	} {
		if got := whyAdmin(&c.refusal); got != c.want {
			t.Errorf("whyAdmin(%+v) = %q, want %q", c.refusal, got, c.want)
		}
	}
	long := whyAdmin(&store.AdminRefusal{Code: store.AdminAccountDisabled, Reason: strings.Repeat("x", 5000)})
	if len(long) > 600 || !strings.Contains(long, "...") {
		t.Errorf("a long reason is not bounded: %d bytes", len(long))
	}
}

// adminHeld checks that the operator's refusal (code) still keeps n
// locked after another lock or error replaced the store's lock reason:
// the agent is empty, the vault locked, and status says the operator
// locked it.
func adminHeld(t *testing.T, n *node, code string) {
	t.Helper()
	if k := n.agentKeys(); k != 0 {
		t.Errorf("%s: the agent serves %d key(s)", n.name, k)
	}
	if info := n.st.Info(); !info.Locked {
		t.Errorf("%s: the vault is unlocked: %+v", n.name, info)
	}
	var st StatusResult
	n.must(OpStatus, nil, &st)
	if st.Vault == nil || st.Vault.AdminLock == nil || st.Vault.AdminLock.Code != code {
		t.Errorf("%s: status does not say the operator locked it: %+v", n.name, st.Vault)
	}
}

// hop unlock of a sealed device key asks the daemon first without the
// passphrase, which fails on the device key and replaces the lock's
// reason, and then with it. With the server unreachable, that second
// request must not load keys: the operator's refusal still holds.
func TestAdminLockSurvivesThePassphraseRetry(t *testing.T) {
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
	n.cfg.Getenv = func(string) string { return "" }
	x.w.restart(n)
	if err := n.call(OpUnlock, UnlockParams{DevicePassphrase: sealedPassphrase}, nil); err != nil {
		t.Fatalf("setup: hop unlock with the passphrase: %v", err)
	}

	disableAccount(t, x.w, "audit")
	if err := n.call(OpSyncNow, nil, nil); err == nil {
		t.Fatal("hop sync of a disabled account worked")
	}
	adminLocked(t, n, store.AdminAccountDisabled, "audit")

	x.w.down.Store(true)
	if err := n.call(OpUnlock, nil, nil); err == nil {
		t.Fatal("hop unlock without the passphrase unlocked a sealed device key")
	}
	if info := n.st.Info(); info.AdminLock != nil {
		t.Fatalf("setup: the device-key error did not replace the store's lock reason: %+v", info)
	}
	adminHeld(t, n, store.AdminAccountDisabled)
	err := n.call(OpUnlock, UnlockParams{DevicePassphrase: sealedPassphrase}, nil)
	if err == nil || !strings.Contains(err.Error(), "operator disabled this account") || !strings.Contains(err.Error(), "could not be asked again") {
		t.Errorf("hop unlock with the passphrase and the server unreachable: %v", err)
	}
	adminLocked(t, n, store.AdminAccountDisabled, "audit")

	x.w.down.Store(false)
	enableAccount(t, x.w)
	if err := n.call(OpUnlock, UnlockParams{DevicePassphrase: sealedPassphrase}, nil); err != nil {
		t.Fatalf("hop unlock after the enable: %v", err)
	}
	if k := n.agentKeys(); k != 1 {
		t.Errorf("after the enable, the agent serves %d key(s)", k)
	}
}

// A later answer that is not the operator's (here a plain 401) replaces
// the lock's reason, but not the operator's refusal: an unlock with the
// server unreachable after it still loads no key.
func TestAdminLockSurvivesAGenericRefusal(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n2, x.n2.st, SyncOptions{noPoll: true})
	x.n2.must(OpSyncNow, nil, nil)
	disableAccount(t, x.w, "")
	if err := x.n2.call(OpSyncNow, nil, nil); err == nil {
		t.Fatal("hop sync of a disabled account worked")
	}
	adminLocked(t, x.n2, store.AdminAccountDisabled, "")

	x.w.setIntercept(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool { return unauthorized(rw) })
	if err := x.n2.call(OpUnlock, nil, nil); err == nil {
		t.Fatal("hop unlock against a refusing server unlocked")
	}
	if info := x.n2.st.Info(); !info.ServerUnconfirmed || info.AdminLock != nil {
		t.Fatalf("setup: the 401 did not replace the store's lock reason: %+v", info)
	}
	adminHeld(t, x.n2, store.AdminAccountDisabled)

	x.w.setIntercept(func(http.ResponseWriter, *http.Request, http.Handler) bool { return false })
	x.w.down.Store(true)
	if x.n2.d.retryUnconfirmed(context.Background()) {
		t.Error("the retry unlocked with the server unreachable")
	}
	if err := x.n2.call(OpUnlock, nil, nil); err == nil || !strings.Contains(err.Error(), "could not be asked again") {
		t.Errorf("hop unlock with the server unreachable: %v", err)
	}
	adminLocked(t, x.n2, store.AdminAccountDisabled, "")
}

// hop lock over the operator's lock is a lock of its own, and does not
// end the refusal: hop unlock with the server unreachable loads no key.
// Once the server accepts the device again, the refusal is over: a later
// unlock offline loads keys as for any device offline.
func TestHopLockKeepsAnAdminLock(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n2, x.n2.st, SyncOptions{noPoll: true})
	laptop := laptopID(t, x.n2)
	x.n2.must(OpSyncNow, nil, nil)
	blockDevice(t, x.w, laptop, "")
	if err := x.n2.call(OpSyncNow, nil, nil); err == nil {
		t.Fatal("hop sync of a blocked device worked")
	}
	adminLocked(t, x.n2, store.AdminDeviceBlocked, "")

	x.n2.must(OpLock, nil, nil)
	adminHeld(t, x.n2, store.AdminDeviceBlocked)
	x.w.down.Store(true)
	if err := x.n2.call(OpUnlock, nil, nil); err == nil || !strings.Contains(err.Error(), "operator blocked this device") {
		t.Errorf("hop unlock after hop lock, with the server unreachable: %v", err)
	}
	adminLocked(t, x.n2, store.AdminDeviceBlocked, "")

	// The server accepts the device: the refusal is cleared.
	x.w.down.Store(false)
	unblockDevice(t, x.w, laptop)
	x.n2.must(OpLock, nil, nil)
	x.n2.must(OpUnlock, nil, nil)
	if k := x.n2.agentKeys(); k != 1 {
		t.Fatalf("after the unblock, the agent serves %d key(s)", k)
	}
	x.n2.must(OpLock, nil, nil)
	var st StatusResult
	x.n2.must(OpStatus, nil, &st)
	if st.Vault == nil || st.Vault.AdminLock != nil {
		t.Errorf("status after the server accepted the device: %+v", st.Vault)
	}
	x.w.down.Store(true)
	x.n2.must(OpUnlock, nil, nil)
	if k := x.n2.agentKeys(); k != 1 {
		t.Errorf("an unlock offline after the unblock: the agent serves %d key(s)", k)
	}
}

// A logout of a disabled account's device whose verified head is behind
// the server's (another device committed since) can't catch up without a
// session: it stays pending, asked again as often as it is run, and posts
// nothing, neither to the log nor to retire-post; the device and its
// vault stay. Once the account is enabled, the logout goes through.
func TestLogoutWhileDisabledBehindTheServer(t *testing.T) {
	x := newSyncSetup(t)
	ctx := context.Background()
	laptop := laptopID(t, x.n2)
	x.w.start(x.n1, x.n1.st, SyncOptions{noPoll: true})
	x.n1.putHost(webHost("web3", x.keyID, "203.0.113.18"))
	x.n1.must(OpSyncNow, nil, nil)
	disableAccount(t, x.w, "")

	var posts atomic.Int32
	x.w.setIntercept(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		if req.Method == http.MethodPost && (req.URL.Path == "/v1/retire-status/post" || strings.HasSuffix(req.URL.Path, "/log")) {
			posts.Add(1)
		}
		return false
	})
	retirer := x.w.client(t).Retirer(x.pub.VaultID)
	for range 2 {
		res, err := x.n2.st.Logout(ctx, retirer, store.LogoutOptions{})
		if !errors.Is(err, store.ErrLogoutPending) || res.Done || res.State != store.StateRetiring ||
			!strings.Contains(err.Error(), "operator refused this device a session") {
			t.Fatalf("logout behind the server's head: %+v, %v", res, err)
		}
	}
	if n := posts.Load(); n != 0 {
		t.Errorf("the pending logout posted %d time(s)", n)
	}
	var dev *server.Device
	if err := x.w.st.View(ctx, func(tx server.Tx) (err error) {
		dev, err = tx.Device(x.pub.AccountID, laptop)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !dev.Active {
		t.Error("the server has the laptop retired")
	}
	if !exists(t, filepath.Join(x.n2.cfg.DataDir, "device.json")) {
		t.Fatal("the pending logout removed device.json")
	}

	enableAccount(t, x.w)
	res, err := x.n2.st.Logout(ctx, retirer, store.LogoutOptions{})
	if err != nil || !res.Done {
		t.Fatalf("logout after the enable: %+v, %v", res, err)
	}
	if exists(t, filepath.Join(x.n2.cfg.DataDir, "device.json")) {
		t.Error("the logout left device.json")
	}
}

// An "active" answer to a question asked before the operator's refusal
// never clears that refusal, even when the refusal lands while the answer
// is on its way back: the generation is compared where the hold is
// cleared.
func TestStaleActiveAnswerKeepsANewerAdminLock(t *testing.T) {
	x := newSyncSetup(t)
	var hook atomic.Pointer[func()]
	o := Options{Sync: SyncOptions{noPoll: true}, afterCheck: func() {
		if f := hook.Swap(nil); f != nil {
			(*f)()
		}
	}}
	x.w.startWith(x.n2, x.n2.st, o)
	x.n2.pause(true)
	d := x.n2.d
	d.mu.Lock()
	d.unconfirmedLocked(store.ErrServerUnconfirmed)
	d.mu.Unlock()
	refuse := func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.unconfirmedLocked(&store.AdminRefusal{Code: store.AdminAccountDisabled})
	}
	hook.Store(&refuse)
	if d.retryUnconfirmed(context.Background()) {
		t.Fatal("the retry unlocked although a refusal landed during its check")
	}
	if hook.Load() != nil {
		t.Fatal("setup: the refusal did not land")
	}
	adminHeld(t, x.n2, store.AdminAccountDisabled)

	x.w.down.Store(true)
	if err := x.n2.call(OpUnlock, nil, nil); err == nil {
		t.Error("hop unlock with the server unreachable loaded keys after the stale answer")
	}
}

// deleteAccount deletes the account as hop-server accounts delete does,
// after the disable it needs, without a backup.
func deleteAccount(t *testing.T, w *syncWorld) {
	t.Helper()
	disableAccount(t, w, "")
	deleteDisabled(t, w)
}

// deleteDisabled deletes the disabled account, without a backup.
func deleteDisabled(t *testing.T, w *syncWorld) {
	t.Helper()
	ctx := context.Background()
	p, err := server.PlanDelete(ctx, w.st, syncEmail, adminOp(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.DeleteAccount(ctx, w.st, adminOp(), p, server.DeleteOptions{NoBackup: true}); err != nil {
		t.Fatal(err)
	}
}

// refusedLocked checks that n is locked by a server that no longer knows
// the device (a 401, as for a deleted account's device): the agent
// empty, the vault locked in memory as unconfirmed, a session refused,
// with no operator's refusal in the store or in status (the server
// claims none), no revocation and no report, and nothing deleted.
func refusedLocked(t *testing.T, n *node) {
	t.Helper()
	if k := n.agentKeys(); k != 0 {
		t.Errorf("%s: the agent serves %d key(s)", n.name, k)
	}
	info := n.st.Info()
	if !info.Locked || !info.ServerUnconfirmed || info.AdminLock != nil || !strings.Contains(info.LockReason, store.ErrSessionRefused.Error()) {
		t.Errorf("%s: the vault is not locked by a refused session alone: %+v, %+v", n.name, info, info.AdminLock)
	}
	var st StatusResult
	n.must(OpStatus, nil, &st)
	if st.Vault == nil || !st.Vault.Locked || st.Vault.AdminLock != nil {
		t.Errorf("%s: status: %+v", n.name, st.Vault)
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

// hop sync on a device whose account was deleted gets the 401 of a
// device the server doesn't know, and the device locks as a client from
// before account delete does: the agent empties, the ssh sessions hop
// started end, and nothing is recorded or deleted, the vault's files
// included. Nothing claims a delete. The retry and hop unlock ask again
// and stay locked.
func TestDeleteLocksHopSync(t *testing.T) {
	x := newSyncSetup(t)
	ctx := context.Background()
	x.w.start(x.n1, x.n1.st, SyncOptions{noPoll: true})
	x.w.start(x.n2, x.n2.st, SyncOptions{noPoll: true})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	x.n1.must(OpSyncNow, nil, nil)
	x.n2.must(OpSyncNow, nil, nil)
	eventually(t, 10*time.Second, "web1 reaches the laptop", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })
	session := watchAt(t, x.n2.d.ControlSocket(), "web1", "")

	deleteAccount(t, x.w)
	err := x.n2.call(OpSyncNow, nil, nil)
	if err == nil || strings.Contains(err.Error(), "deleted") {
		t.Errorf("hop sync of a deleted account: %v", err)
	}
	session.ended(t, 5*time.Second, whyRefused)
	refusedLocked(t, x.n2)
	if e := endedStatus(t, x.n2); e == nil || e.Why != whyRefused {
		t.Errorf("ended sessions in status: %+v", e)
	}

	if x.n2.d.retryUnconfirmed(ctx) {
		t.Fatal("the retry unlocked a deleted account's vault")
	}
	refusedLocked(t, x.n2)
	if err := x.n2.call(OpUnlock, nil, nil); err == nil {
		t.Error("hop unlock of a deleted account succeeded")
	}
	refusedLocked(t, x.n2)
}

// Running daemons lock on the disable a delete needs, with the
// operator's refusal in status; the delete that follows reaches them
// through their long-polls as a 401, which replaces the lock's reason
// but not that refusal's hold (TestAdminLockSurvivesAGenericRefusal):
// they stay locked, nothing claims a delete, and nothing is deleted.
func TestDeleteLocksTheBackgroundPull(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{Wait: time.Second})
	x.w.start(x.n2, x.n2.st, SyncOptions{Wait: time.Second})
	for _, n := range []*node{x.n1, x.n2} {
		if k := n.agentKeys(); k != 1 {
			t.Fatalf("setup: %s's agent serves %d key(s)", n.name, k)
		}
	}
	disableAccount(t, x.w, "")
	for _, n := range []*node{x.n1, x.n2} {
		eventually(t, 15*time.Second, n.name+" locks", func() bool { return n.agentKeys() == 0 })
		adminHeld(t, n, store.AdminAccountDisabled)
	}
	deleteDisabled(t, x.w)
	for _, n := range []*node{x.n1, x.n2} {
		if n.d.retryUnconfirmed(context.Background()) {
			t.Fatalf("%s: the retry unlocked a deleted account's vault", n.name)
		}
		if info := n.st.Info(); !info.Locked || !info.ServerUnconfirmed || info.AdminLock != nil ||
			!strings.Contains(info.LockReason, store.ErrSessionRefused.Error()) || strings.Contains(info.LockReason, "deleted") {
			t.Errorf("%s: the 401 is not the lock's reason: %+v", n.name, info)
		}
		adminHeld(t, n, store.AdminAccountDisabled)
		if !exists(t, filepath.Join(n.cfg.DataDir, "device.json")) || !exists(t, filepath.Join(n.cfg.DataDir, "vault", "state.json")) {
			t.Fatalf("%s: the vault was deleted", n.name)
		}
	}
}

// A change queued on a device whose account was deleted is pushed by the
// loop, refused, and the device locks; the change stays queued.
func TestDeleteLocksAPush(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n2, x.n2.st, SyncOptions{noPoll: true})
	// The loop is idle once hop sync is answered, so the pause holds from
	// its next step on: nothing reaches the server before the delete, and
	// the change is queued after it.
	x.n2.must(OpSyncNow, nil, nil)
	x.n2.pause(true)
	deleteAccount(t, x.w)
	x.n2.putHost(webHost("web2", x.keyID, "203.0.113.17"))
	if k := x.n2.agentKeys(); k != 1 {
		t.Fatalf("setup: the paused laptop serves %d key(s) before its push", k)
	}
	x.n2.pause(false)
	eventually(t, 15*time.Second, "the push is refused and the laptop locks", func() bool { return x.n2.agentKeys() == 0 })
	refusedLocked(t, x.n2)
	// Status can't count a locked vault's outbox; its files are there.
	if empty, err := x.n2.st.OutboxEmpty(); err != nil || empty {
		t.Errorf("the queued change is gone after the refused push: empty %v, %v", empty, err)
	}
}

// A daemon that starts for a deleted account locks before any key loads.
func TestDeleteLocksAtStart(t *testing.T) {
	x := newSyncSetup(t)
	deleteAccount(t, x.w)
	x.w.startWatched(x.n2, x.n2.st) // fails if the agent ever served a key
	refusedLocked(t, x.n2)
}

// A logout of a device whose account was deleted can't be recorded: the
// server answers it as a device it doesn't know (401), so it stays
// pending, with no operator's refusal claimed, posts nothing, and deletes
// nothing on the device; --local-only is the way out, and it wipes.
func TestLogoutOfADeletedAccount(t *testing.T) {
	x := newSyncSetup(t)
	ctx := context.Background()
	deleteAccount(t, x.w)
	var posts atomic.Int32
	x.w.setIntercept(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		if req.Method == http.MethodPost && (req.URL.Path == "/v1/retire-status/post" || strings.HasSuffix(req.URL.Path, "/log")) {
			posts.Add(1)
		}
		return false
	})
	retirer := x.w.client(t).Retirer(x.pub.VaultID)
	for range 2 {
		res, err := x.n2.st.Logout(ctx, retirer, store.LogoutOptions{})
		if !errors.Is(err, store.ErrLogoutPending) || errors.Is(err, store.ErrAdminRefused) || !errors.Is(err, syncclient.ErrUnauthorized) ||
			res.Done || res.State != store.StateRetiring {
			t.Fatalf("logout of a deleted account: %+v, %v", res, err)
		}
	}
	if n := posts.Load(); n != 0 {
		t.Errorf("the pending logout posted %d time(s)", n)
	}
	data := x.n2.cfg.DataDir
	for _, f := range []string{filepath.Join(data, "device.json"), filepath.Join(data, "vault", "state.json")} {
		if !exists(t, f) {
			t.Errorf("the pending logout removed %s", f)
		}
	}
	res, err := x.n2.st.Logout(ctx, nil, store.LogoutOptions{LocalOnly: true})
	if err != nil || !res.Done {
		t.Fatalf("logout --local-only: %+v, %v", res, err)
	}
	if exists(t, filepath.Join(data, "device.json")) {
		t.Error("logout --local-only left device.json")
	}
}
