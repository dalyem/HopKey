package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// proofChecker is the fake server as CheckServer and ProveRevocation ask
// it: its sessions and retire-status, and the proof that proof serves.
type proofChecker struct {
	retirer
	proof func(after uint64) ([]Committed, DeviceReceipt, error)
}

func (p proofChecker) RevocationProof(ctx context.Context, auth DeviceAuth, after uint64) ([]Committed, DeviceReceipt, error) {
	return p.proof(after)
}

// revokedChain is an account where, past device b's verified head, the log
// holds device c's bootstrap (a membership addition), a rotation of the
// account keys, a checkpoint that revokes c (a removal) and the one that
// revokes b. b was refused a session since, and recorded the server's
// report.
type revokedChain struct {
	a, b *fixture
	f    *fakeServer
	// entries are the proof: from b's head to the receipt's entry, without
	// their objects.
	entries  []Committed
	rc       DeviceReceipt
	aID, bID model.ID
	cReceipt DeviceReceipt
	// from is b's verified head.
	from uint64
	// oldAccount is the account signing key b held at its head.
	oldAccount ed25519.PrivateKey
	// The indexes in entries of each step.
	bootstrap, rotation, removal, revoke int
}

func newRevokedChain(t *testing.T) *revokedChain {
	t.Helper()
	ctx := context.Background()
	pw := []byte(testPassword)
	a, b, r := newCkptPair(t)
	aID, bID := deviceID(t, a.s), deviceID(t, b.s)
	b.s.mu.Lock()
	from := b.s.state.Head.Seq
	oldAccount := append(ed25519.PrivateKey(nil), b.s.sec.Account.Sig...)
	b.s.mu.Unlock()

	c := secondDeviceNamed(t, a, r, "laptop")
	cID := deviceID(t, c.s)
	if _, err := a.s.Rotate(ctx, r, pw, CheckpointOptions{Keep: []string{bID.String(), cID.String()}}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := a.s.AckKit(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.s.RevokeDevices(ctx, r, pw, []string{cID.String()}, CheckpointOptions{Keep: []string{bID.String()}}); err != nil {
		t.Fatalf("revoke c: %v", err)
	}
	if err := a.s.AckKit(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.s.RevokeDevices(ctx, r, pw, []string{bID.String()}, CheckpointOptions{}); err != nil {
		t.Fatalf("revoke b: %v", err)
	}
	if err := a.s.AckKit(); err != nil {
		t.Fatal(err)
	}

	f := newFakeServer(t, r)
	_, _, receipts := f.public(t)
	x := &revokedChain{a: a, b: b, f: f, aID: aID, bID: bID, rc: receipts[bID], cReceipt: receipts[cID], oldAccount: oldAccount, from: from,
		bootstrap: -1, rotation: -1, removal: -1, revoke: -1}
	if x.rc.How != "revoked" || x.cReceipt.How != "revoked" {
		t.Fatalf("receipts: b %+v, c %+v", x.rc, x.cReceipt)
	}
	cs, _, err := r.Since(ctx, from)
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := 0
	for _, cm := range cs {
		if cm.Seq > x.rc.Seq {
			break
		}
		i := len(x.entries)
		x.entries = append(x.entries, Committed{Seq: cm.Seq, H: cm.H, Wire: bare(t, cm.Wire)})
		switch cm.Wire.Entry.Kind {
		case vaultlog.KindBootstrap:
			x.bootstrap = i
		case vaultlog.KindCheckpoint:
			switch checkpoints {
			case 0:
				x.rotation = i
			case 1:
				x.removal = i
			case 2:
				x.revoke = i
			}
			checkpoints++
		}
	}
	if x.bootstrap < 0 || x.rotation < 0 || x.removal < 0 || x.revoke != len(x.entries)-1 || x.entries[x.revoke].Seq != x.rc.Seq {
		t.Fatalf("the chain: bootstrap %d, rotation %d, removal %d, revoke %d of %d entries", x.bootstrap, x.rotation, x.removal, x.revoke, len(x.entries))
	}

	// b learns of it as a device does: refused a session, it asks
	// retire-status and records the server's report.
	res, err := b.s.CheckServer(ctx, x.serve(x.entries, x.rc, 0), nil)
	if err != nil || res.Report == nil {
		t.Fatalf("CheckServer: %+v, %v", res, err)
	}
	return x
}

// bare is w without its objects, as the proof endpoint serves it.
func bare(t testing.TB, w *vaultlog.Wire) *vaultlog.Wire {
	t.Helper()
	b, err := w.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	c, err := vaultlog.ParseWire(b)
	if err != nil {
		t.Fatal(err)
	}
	c.Objects = []vaultlog.Object{}
	return c
}

// serve answers each proof request with the entries past after, page at a
// time (0: all of them), and rc.
func (x *revokedChain) serve(entries []Committed, rc DeviceReceipt, page int) proofChecker {
	return proofChecker{retirer: retirer{x.f}, proof: func(after uint64) ([]Committed, DeviceReceipt, error) {
		var out []Committed
		for _, c := range entries {
			if c.Seq > after && (page == 0 || len(out) < page) {
				out = append(out, c)
			}
		}
		return out, rc, nil
	}}
}

// forged returns the entries with entry i's signature by role (any role
// when role is "") corrupted.
func (x *revokedChain) forged(t *testing.T, i int, role vaultlog.Role) []Committed {
	t.Helper()
	out := append([]Committed(nil), x.entries...)
	w := bare(t, out[i].Wire)
	n := 0
	for j := range w.Sigs {
		if role == "" || w.Sigs[j].Role == role {
			w.Sigs[j].Sig = append([]byte(nil), w.Sigs[j].Sig...)
			w.Sigs[j].Sig[0] ^= 1
			n++
		}
	}
	if n == 0 {
		t.Fatalf("entry %d has no %q signature", i, role)
	}
	out[i].Wire = w
	return out
}

// intact fails unless b still has everything: a refused proof deletes
// nothing and leaves the report in place.
func (x *revokedChain) intact(t *testing.T, what string) {
	t.Helper()
	data := x.b.cfg.DataDir
	for _, rel := range []string{"device.json", "vault/state.json", "vault/server.json", "vault/server-revoked.json"} {
		if _, err := os.Lstat(filepath.Join(data, rel)); err != nil {
			t.Errorf("%s: %s: %v", what, rel, err)
		}
	}
	if rec, err := ReadRevocation(data); rec != nil || err != nil {
		t.Errorf("%s: a revocation record: %+v, %v", what, rec, err)
	}
	if x.b.s.IsRevoked() {
		t.Errorf("%s: the store counts itself revoked", what)
	}
}

// A proof is the authenticated departure authorization of the account: a
// chain that verifies, through account-key rotations and membership
// changes, to the entry that removed this device. Anything else the server
// sends is refused and deletes nothing.
func TestRevocationProofRefusals(t *testing.T) {
	ctx := context.Background()
	x := newRevokedChain(t)
	rc := x.rc
	other := func(f func(*DeviceReceipt)) DeviceReceipt {
		r := rc
		f(&r)
		return r
	}
	alt := crypto.SHA256([]byte("another entry"))
	cases := []struct {
		name  string
		proof proofChecker
	}{
		{"a wrong receipt hash", x.serve(x.entries, other(func(r *DeviceReceipt) { r.H = alt }), 0)},
		{"another device in the receipt", x.serve(x.entries, other(func(r *DeviceReceipt) { r.DeviceID = x.aID }), 0)},
		{"another revoked device's receipt", x.serve(x.entries, x.cReceipt, 0)},
		{"the wrong departure kind", x.serve(x.entries, other(func(r *DeviceReceipt) { r.How = "retired" }), 0)},
		{"an unknown departure kind", x.serve(x.entries, other(func(r *DeviceReceipt) { r.How = "removed" }), 0)},
		{"a receipt at a seq this device holds", x.serve(x.entries, other(func(r *DeviceReceipt) { r.Seq = x.entries[0].Seq - 1 }), 0)},
		{"a receipt short of the revoking entry", x.serve(x.entries, other(func(r *DeviceReceipt) { r.Seq--; r.H = x.entries[x.revoke-1].H }), 0)},
		{"an invalid account_new signature", x.serve(x.forged(t, x.rotation, vaultlog.RoleAccountNew), rc, 0)},
		{"a forged account_old signature on the rotation", x.serve(x.forged(t, x.rotation, vaultlog.RoleAccountOld), rc, 0)},
		{"a forged membership addition", x.serve(x.forged(t, x.bootstrap, ""), rc, 0)},
		{"a forged membership removal", x.serve(x.forged(t, x.removal, vaultlog.RoleDevice), rc, 0)},
		{"a forged revocation", x.serve(x.forged(t, x.revoke, vaultlog.RoleAccountOld), rc, 0)},
		{"a revocation signed with the account key the rotation replaced", x.serve(x.resigned(t, x.revoke, vaultlog.RoleAccountOld), rc, 0)},
		{"a truncated chain", x.serve(x.entries[:x.revoke], rc, 0)},
		{"a chain with an entry left out", x.serve(append(append([]Committed(nil), x.entries[:x.rotation]...), x.entries[x.rotation+1:]...), rc, 0)},
		{"a replayed entry", x.replayed(t, rc)},
		{"a replayed page", x.firstPageAlways(rc, 2)},
		{"a receipt that changes across pages", x.changingReceipt(rc, alt)},
		{"an entry whose H is not its own", x.serve(x.misnamed(t), rc, 0)},
	}
	for _, c := range cases {
		err := x.b.s.ProveRevocation(ctx, c.proof, nil)
		if !errors.Is(err, ErrProofRefused) || errors.Is(err, ErrDeviceRevoked) {
			t.Errorf("%s: %v, want a refused proof", c.name, err)
		}
		x.intact(t, c.name)
	}

	// The genuine chain, a page at a time, through two rotations of the
	// account key and a device that came and went, verifies and wipes b.
	err := x.b.s.ProveRevocation(ctx, x.serve(x.entries, rc, 1), nil)
	if !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("the genuine proof: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(x.b.cfg.DataDir, "device.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("device.json after the wipe: %v", err)
	}
	if rec, err := ReadRevocation(x.b.cfg.DataDir); err != nil || rec == nil || rec.Seq != rc.Seq || rec.DeviceID != x.bID {
		t.Errorf("the revocation record: %+v, %v", rec, err)
	}
}

// resigned returns the entries with entry i's role signature made, validly,
// by the account key b held at its head, which the rotation before entry
// i replaced: a signature that was good before the rotation, and is not
// after it.
func (x *revokedChain) resigned(t *testing.T, i int, role vaultlog.Role) []Committed {
	t.Helper()
	if i <= x.rotation {
		t.Fatal("the entry must come after the rotation")
	}
	out := append([]Committed(nil), x.entries...)
	w := bare(t, out[i].Wire)
	n := 0
	for j := range w.Sigs {
		if w.Sigs[j].Role == role {
			sig, err := crypto.Sign(x.oldAccount, crypto.LabelLogEntry, &w.Entry)
			if err != nil {
				t.Fatal(err)
			}
			w.Sigs[j].Sig = sig
			n++
		}
	}
	if n == 0 {
		t.Fatalf("entry %d has no %q signature", i, role)
	}
	out[i].Wire = w
	return out
}

// replayed serves, first, the entry at b's own head again before the rest.
func (x *revokedChain) replayed(t *testing.T, rc DeviceReceipt) proofChecker {
	head := x.from
	cs, _, err := x.f.fakeRemote.Since(context.Background(), head-1)
	if err != nil || len(cs) == 0 {
		t.Fatal(err)
	}
	held := Committed{Seq: cs[0].Seq, H: cs[0].H, Wire: bare(t, cs[0].Wire)}
	return proofChecker{retirer: retirer{x.f}, proof: func(after uint64) ([]Committed, DeviceReceipt, error) {
		return append([]Committed{held}, x.entries...), rc, nil
	}}
}

// firstPageAlways answers every request with the first page.
func (x *revokedChain) firstPageAlways(rc DeviceReceipt, page int) proofChecker {
	return proofChecker{retirer: retirer{x.f}, proof: func(after uint64) ([]Committed, DeviceReceipt, error) {
		return x.entries[:page], rc, nil
	}}
}

// changingReceipt serves a page at a time, and another receipt from the
// second page on.
func (x *revokedChain) changingReceipt(rc DeviceReceipt, alt crypto.Hash) proofChecker {
	calls := 0
	inner := x.serve(x.entries, rc, 1)
	return proofChecker{retirer: retirer{x.f}, proof: func(after uint64) ([]Committed, DeviceReceipt, error) {
		calls++
		es, r, err := inner.proof(after)
		if calls > 1 {
			r.H = alt
		}
		return es, r, err
	}}
}

// misnamed gives the revoking entry the H of the one before it.
func (x *revokedChain) misnamed(t *testing.T) []Committed {
	out := append([]Committed(nil), x.entries...)
	out[x.revoke].H = out[x.revoke-1].H
	return out
}

// A crash in the wipe that a verified proof started is still a proven
// revocation, not a refused proof; the next start finishes the wipe.
func TestProvenRevocationWipeResumesAfterACrash(t *testing.T) {
	ctx := context.Background()
	x := newRevokedChain(t)
	x.b.s.testHook = crashAt("retire:cache")
	err := x.b.s.ProveRevocation(ctx, x.serve(x.entries, x.rc, 0), nil)
	if !errors.Is(err, ErrDeviceRevoked) || errors.Is(err, ErrProofRefused) {
		t.Fatalf("a proof that verified, then a crash in the wipe: %v, want the revocation proven", err)
	}
	if !errors.Is(err, errCrash) || !errors.Is(err, ErrWipeIncomplete) {
		t.Errorf("the error does not say the wipe failed: %v", err)
	}
	if !x.b.s.IsRevoked() {
		t.Error("the store does not count itself revoked")
	}
	data := x.b.cfg.DataDir
	if rec, err := ReadRevocation(data); err != nil || rec == nil {
		t.Errorf("the revocation record: %+v, %v", rec, err)
	}

	// The next start.
	release(x.b.cfg)
	x.b.s.Close()
	if s, err := Open(ctx, x.b.cfg); !errors.Is(err, ErrNoVault) {
		if s != nil {
			s.Close()
		}
		t.Fatalf("opening after the crash: %v, want the wipe finished", err)
	}
	for _, rel := range []string{"device.json", "device.key", "vault/state.json", "vault/server-revoked.json"} {
		if _, err := os.Lstat(filepath.Join(data, rel)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s after the resumed wipe: %v", rel, err)
		}
	}
	if rec, err := ReadRevocation(data); err != nil || rec == nil || rec.DeviceID != x.bID {
		t.Errorf("the revocation record after the resumed wipe: %+v, %v", rec, err)
	}
	if pending, _ := LogoutCleanupPending(data); !pending {
		t.Error("the ssh files are not marked as owed")
	}
}

// server-revoked.json carries a MAC under the device-local key. A record
// whose MAC does not verify still keeps the vault locked, but status calls
// it corrupt and does not show its metadata as the server's.
func TestTamperedServerReportStaysLockedAndSaysCorrupt(t *testing.T) {
	ctx := context.Background()
	x := newRevokedChain(t)
	path := filepath.Join(x.b.cfg.DataDir, "vault", "server-revoked.json")
	down := x.serve(x.entries, x.rc, 0)
	ask := func() {
		t.Helper()
		x.f.down = errDown
		defer func() { x.f.down = nil }()
		if _, err := x.b.s.CheckServer(ctx, down, nil); !errors.Is(err, errDown) {
			t.Fatalf("CheckServer with the server down: %v", err)
		}
	}

	ask()
	info := x.b.s.Info()
	if info.ServerReport == nil || info.ServerReportCorrupt || info.ServerReport.Seq != x.rc.Seq || info.ServerReport.How != "revoked" {
		t.Fatalf("an authentic report: %+v, corrupt %v", info.ServerReport, info.ServerReportCorrupt)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f serverReportFile
	if err := canonjson.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	f.Seq += 7
	f.How = "retired"
	if b, err = canonjson.Marshal(f); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	ask()
	info = x.b.s.Info()
	if !info.ServerReportCorrupt {
		t.Error("a report whose MAC does not verify is not called corrupt")
	}
	if r := info.ServerReport; r == nil || r.Seq == f.Seq || r.How == "retired" {
		t.Errorf("the tampered report is shown as the server's: %+v", r)
	}
	if err := x.b.s.Unlock(ctx); !errors.Is(err, ErrServerRevoked) {
		t.Errorf("unlock with a tampered report: %v, want it still locked", err)
	}

	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	info = x.b.s.Info()
	if !info.ServerReportCorrupt || !info.Locked {
		t.Errorf("an unparseable report: corrupt %v, locked %v", info.ServerReportCorrupt, info.Locked)
	}
	if err := x.b.s.Unlock(ctx); !errors.Is(err, ErrServerRevoked) {
		t.Errorf("unlock with an unparseable report: %v, want it still locked", err)
	}
}

// Every contact counts at once (LastContact), though contact.json is
// written at most once a minute; Close writes the last one. While the
// account's max-offline policy is short, every contact is written.
func TestContactKeptInMemoryAndSavedAtClose(t *testing.T) {
	ctx := context.Background()
	a, b, r := newCkptPair(t)
	now := time.Now().Add(2 * time.Minute)
	b.s.cfg.Now = func() time.Time { return now }
	saved := func() time.Time {
		t.Helper()
		b.s.mu.Lock()
		defer b.s.mu.Unlock()
		at, ok, err := b.s.lastContact()
		if err != nil || !ok {
			t.Fatalf("contact.json: %v, %v", ok, err)
		}
		return at
	}
	last := func(s *Store) time.Time {
		t.Helper()
		at, ok, err := s.LastContact()
		if err != nil || !ok {
			t.Fatalf("LastContact: %v, %v", ok, err)
		}
		return at
	}

	pull(t, b.s, r)
	first := now
	now = now.Add(30 * time.Second)
	pull(t, b.s, r)
	if got := last(b.s); got.Unix() != now.Unix() {
		t.Errorf("LastContact %v, want the latest contact %v", got, now)
	}
	if got := saved(); got.Unix() != first.Unix() {
		t.Errorf("contact.json %v, want %v: written more than once a minute", got, first)
	}

	// A one-minute policy: every contact is written.
	if _, err := a.s.PutPolicy(ctx, model.Policy{MaxOffline: 60}); err != nil {
		t.Fatal(err)
	}
	pushAll(t, a.s, r)
	now = now.Add(10 * time.Second)
	pull(t, b.s, r)
	now = now.Add(10 * time.Second)
	pull(t, b.s, r)
	if got := saved(); got.Unix() != now.Unix() {
		t.Errorf("with a one-minute policy, contact.json %v, want every contact (%v)", got, now)
	}

	// Without one, Close writes the last contact.
	p := policyItem(t, a.s)
	p.MaxOffline = 0
	if _, err := a.s.PutPolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	pushAll(t, a.s, r)
	now = now.Add(time.Minute)
	pull(t, b.s, r)
	now = now.Add(20 * time.Second)
	pull(t, b.s, r)
	if got := saved(); got.Unix() == now.Unix() {
		t.Fatal("setup: the last contact was written already")
	}
	release(b.cfg)
	b.s.Close()
	s := open(t, b.cfg)
	track(t, b.cfg, s)
	if got := last(s); got.Unix() != now.Unix() {
		t.Errorf("after Close and Open, LastContact %v, want the last contact %v", got, now)
	}
}

// policyItem is the vault's one policy item.
func policyItem(t *testing.T, s *Store) model.Policy {
	t.Helper()
	snap, err := s.Snapshot(context.Background())
	if err != nil || len(snap.Policies) != 1 {
		t.Fatalf("policies: %+v, %v", snap.Policies, err)
	}
	return snap.Policies[0]
}
