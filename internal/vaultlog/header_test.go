package vaultlog

import (
	"testing"
)

// bare is wire without its objects, as a revocation proof serves it.
func bare(t *testing.T, wire *Wire) *Wire {
	t.Helper()
	c := cloneWire(t, wire)
	c.Objects = []Object{}
	return c
}

// CheckHeader verifies who signed an entry without its objects: a
// revocation proof chains from the verified head through entries a device
// can't decrypt, and a forged one does not verify.
func TestCheckHeaderVerifiesARevocationWithoutObjects(t *testing.T) {
	w := newWorld(t).withItems()
	pre := w.st
	normal := w.normal(Changes{})
	mid := w.st
	p := w.checkpointParams(idDevB)
	cp := w.unverifiedCheckpoint(p)

	c, err := CheckHeader(pre, bare(t, normal))
	if err != nil {
		t.Fatalf("a normal entry without its objects: %v", err)
	}
	if c.Revokes(idDevB) {
		t.Error("a normal entry revokes B")
	}
	c, err = CheckHeader(c.Post, bare(t, cp))
	if err != nil {
		t.Fatalf("the revoking checkpoint without its objects: %v", err)
	}
	if !c.Revokes(idDevB) || c.Revokes(idDevA) {
		t.Error("the checkpoint's revocations are not B's")
	}
	if _, err := CheckPublic(mid, bare(t, cp), nil); err == nil {
		t.Error("the full public stage accepted a wire without its objects")
	}

	// Not chained from the verified head.
	if _, err := CheckHeader(pre, bare(t, cp)); err == nil {
		t.Error("a checkpoint that skips an entry verified")
	}
	// Signed by an account key the device does not know.
	forged := mutate(t, cp, map[Role]signer{RoleAccountOld: acctSigner(fixedAccount(t, 1, "a stranger"))}, func(*Entry, *Wire) {})
	if _, err := CheckHeader(mid, bare(t, forged)); err == nil {
		t.Error("a checkpoint with a stranger's account signature verified")
	}
	// Signed by a device that is not a member.
	forged = mutate(t, cp, map[Role]signer{RoleDevice: devSigner(w.devs[idDevC])}, func(*Entry, *Wire) {})
	if _, err := CheckHeader(mid, bare(t, forged)); err == nil {
		t.Error("a checkpoint signed by a device that is not a member verified")
	}
	if _, err := CheckHeader(nil, bare(t, cp)); err == nil {
		t.Error("a header verified with no state")
	}
}
