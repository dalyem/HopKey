package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

func putShortcut(t *testing.T, s *Store, sc model.Shortcut) model.Shortcut {
	t.Helper()
	out, err := s.PutShortcut(context.Background(), sc)
	if err != nil {
		t.Fatalf("put shortcut %q: %v", sc.Keys, err)
	}
	return out
}

func shortcutByKeys(snap model.Snapshot, keys string, host model.ID) (model.Shortcut, bool) {
	for _, s := range snap.Shortcuts {
		if s.Keys == keys && s.HostID == host {
			return s, true
		}
	}
	return model.Shortcut{}, false
}

// A global and a host shortcut made on one device reach the other as they
// were written, and a delete follows them.
func TestShortcutsSyncBetweenDevices(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	g := putShortcut(t, p.a.s, model.Shortcut{Keys: "u", Name: "uptime", Command: "uptime", Enter: true})
	h := putShortcut(t, p.a.s, model.Shortcut{Keys: "gl", Command: "git log --oneline\t-5", HostID: p.host.ItemID, Description: "recent\ncommits"})
	if res := pushAll(t, p.a.s, p.r); res.Outcome != PushEmpty {
		t.Fatalf("a's push: %+v", res)
	}
	pull(t, p.b.s, p.r)
	snap := snapshot(t, p.b.s)
	if len(snap.Shortcuts) != 2 {
		t.Fatalf("b's shortcuts: %+v", snap.Shortcuts)
	}
	for _, want := range []model.Shortcut{g, h} {
		got, ok := shortcutByKeys(snap, want.Keys, want.HostID)
		if !ok || got != want {
			t.Errorf("b has %+v, a wrote %+v", got, want)
		}
	}
	if snap.Marks != nil {
		t.Errorf("marks after a pull: %v", snap.Marks)
	}
	if err := p.b.s.Delete(ctx, g.ItemID); err != nil {
		t.Fatal(err)
	}
	pushAll(t, p.b.s, p.r)
	pull(t, p.a.s, p.r)
	if _, ok := shortcutByKeys(snapshot(t, p.a.s), "u", model.ID{}); ok {
		t.Error("the delete did not reach a")
	}
}

// Two devices change a shortcut's command and keys at once: one unit, so
// the second change holds rather than combine into a binding neither
// chose. Descriptions merge on their own.
func TestShortcutConcurrentEdits(t *testing.T) {
	p := newPair(t)
	sc := putShortcut(t, p.a.s, model.Shortcut{Keys: "r", Command: "systemctl status app", Enter: true, HostID: p.host.ItemID})
	pushAll(t, p.a.s, p.r)
	pull(t, p.b.s, p.r)

	onA, onB := sc, sc
	onA.Command = "systemctl restart app"
	onB.Keys, onB.Enter = "s", false
	putShortcut(t, p.a.s, onA)
	putShortcut(t, p.b.s, onB)
	if res := pushAll(t, p.b.s, p.r); res.Outcome != PushEmpty {
		t.Fatalf("b's push: %+v", res)
	}
	res := pushAll(t, p.a.s, p.r)
	if res.Outcome != PushHeld || res.Hold == nil || res.Hold.Cause != merge.CauseGuardedConflict {
		t.Fatalf("a's concurrent edit: %+v %+v", res, res.Hold)
	}
	if !slices.ContainsFunc(res.Hold.Conflicts, func(c merge.Conflict) bool { return c.Name == merge.UnitShortcut }) {
		t.Errorf("conflicts %v, want the shortcut unit", res.Hold.Conflicts)
	}

	q := newPair(t)
	sc = putShortcut(t, q.a.s, model.Shortcut{Keys: "d", Command: "df -h", Enter: true})
	pushAll(t, q.a.s, q.r)
	pull(t, q.b.s, q.r)
	onA, onB = sc, sc
	onA.Description = "disk"
	onB.Command = "df -hT"
	putShortcut(t, q.a.s, onA)
	putShortcut(t, q.b.s, onB)
	pushAll(t, q.b.s, q.r)
	if res := pushAll(t, q.a.s, q.r); res.Outcome != PushEmpty {
		t.Fatalf("a description edit beside b's command edit: %+v %+v", res, res.Hold)
	}
	pull(t, q.b.s, q.r)
	got, _ := shortcutByKeys(snapshot(t, q.b.s), "d", model.ID{})
	if got.Command != "df -hT" || got.Description != "disk" {
		t.Errorf("merged: %+v", got)
	}
}

// A host shortcut refers to its host as a jump host does: the host can't
// be deleted while one is there, and a shortcut can't name a host that is
// not live.
func TestShortcutHostReference(t *testing.T) {
	ctx := context.Background()
	t.Run("local-only", func(t *testing.T) {
		f := newVault(t, testConfig(t))
		_, host := addHost(t, f.s, "web")
		sc := putShortcut(t, f.s, model.Shortcut{Keys: "x", Command: "exit", Enter: true, HostID: host.ItemID})
		err := f.s.Delete(ctx, host.ItemID)
		if vaultlog.RuleOf(err) != vaultlog.RuleRefIntegrity {
			t.Fatalf("delete of a host with a shortcut: %v", err)
		}
		if _, err := f.s.PutShortcut(ctx, model.Shortcut{Keys: "y", Command: "id", HostID: model.ID{9}}); vaultlog.RuleOf(err) != vaultlog.RuleRefIntegrity {
			t.Fatalf("a shortcut of no host: %v", err)
		}
		if err := f.s.Delete(ctx, sc.ItemID); err != nil {
			t.Fatal(err)
		}
		if err := f.s.Delete(ctx, host.ItemID); err != nil {
			t.Fatalf("delete once the shortcut is gone: %v", err)
		}
	})
	t.Run("server-backed", func(t *testing.T) {
		f, _ := serverVault(t)
		_, host := addHost(t, f.s, "web")
		putShortcut(t, f.s, model.Shortcut{Keys: "x", Command: "exit", Enter: true, HostID: host.ItemID})
		if err := f.s.Delete(ctx, host.ItemID); err == nil || !strings.Contains(err.Error(), "shortcut") {
			t.Fatalf("queued delete of a host with a shortcut: %v", err)
		}
		if _, err := f.s.PutShortcut(ctx, model.Shortcut{Keys: "y", Command: "id", HostID: model.ID{9}}); !errors.Is(err, errDangling) {
			t.Fatalf("a queued shortcut of no host: %v", err)
		}
	})
}

// One device adds a host shortcut while the other deletes the host. The
// one that reaches the server second holds, whichever it is, and nothing
// commits a shortcut of a host that is gone.
func TestShortcutHostDeletedConcurrently(t *testing.T) {
	ctx := context.Background()
	t.Run("shortcut second", func(t *testing.T) {
		p := newPair(t)
		putShortcut(t, p.a.s, model.Shortcut{Keys: "x", Command: "exit", Enter: true, HostID: p.host.ItemID})
		if err := p.b.s.Delete(ctx, p.host.ItemID); err != nil {
			t.Fatal(err)
		}
		if res := pushAll(t, p.b.s, p.r); res.Outcome != PushEmpty {
			t.Fatalf("b's delete: %+v", res)
		}
		res := pushAll(t, p.a.s, p.r)
		if res.Outcome != PushHeld || res.Hold == nil || res.Hold.Cause != merge.CauseRuleFailure {
			t.Fatalf("a's shortcut of a deleted host: %+v %+v", res, res.Hold)
		}
	})
	t.Run("delete second", func(t *testing.T) {
		p := newPair(t)
		putShortcut(t, p.b.s, model.Shortcut{Keys: "x", Command: "exit", Enter: true, HostID: p.host.ItemID})
		if err := p.a.s.Delete(ctx, p.host.ItemID); err != nil {
			t.Fatal(err)
		}
		pushAll(t, p.b.s, p.r)
		res := pushAll(t, p.a.s, p.r)
		if res.Outcome != PushHeld || res.Hold == nil {
			t.Fatalf("a's delete of a host that now has a shortcut: %+v", res)
		}
		if _, ok := verifiedHost(t, p.a.s, p.host.ItemID); !ok {
			t.Error("the host went with its shortcut still there")
		}
	})
}

// A fork carries shortcuts under new IDs, a host shortcut pointing at its
// host's new ID. One whose host is gone from what the device shows is
// left out with a warning, never made global.
func TestForkCarriesShortcuts(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a := p.a.s
	putShortcut(t, a, model.Shortcut{Keys: "u", Command: "uptime", Enter: true})
	putShortcut(t, a, model.Shortcut{Keys: "w", Command: "who", HostID: p.host.ItemID})
	pushAll(t, a, p.r)
	_, other := addHost(t, a, "other")
	pushAll(t, a, p.r)
	pull(t, p.b.s, p.r)
	putShortcut(t, a, model.Shortcut{Keys: "o", Command: "id", Enter: true, HostID: other.ItemID})
	if err := p.b.s.Delete(ctx, other.ItemID); err != nil {
		t.Fatal(err)
	}
	pushAll(t, p.b.s, p.r)
	pull(t, a, p.r)

	res := fork(t, p.a.cfg, false)
	if res.Shortcuts != 2 {
		t.Errorf("plan counts %d shortcuts, want 2", res.Shortcuts)
	}
	if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, `shortcut "o"`) }) {
		t.Errorf("no warning for the shortcut of the deleted host: %v", res.Warnings)
	}
	snap := snapshot(t, open(t, p.a.cfg))
	web := hostNamed(t, snap, "web")
	if web.ItemID == p.host.ItemID {
		t.Fatal("the fork kept the host's ID")
	}
	if _, ok := shortcutByKeys(snap, "w", web.ItemID); !ok {
		t.Errorf("the host shortcut does not follow its host's new ID: %+v", snap.Shortcuts)
	}
	if _, ok := shortcutByKeys(snap, "u", model.ID{}); !ok {
		t.Errorf("the global shortcut: %+v", snap.Shortcuts)
	}
	if len(snap.Shortcuts) != 2 {
		t.Errorf("shortcuts %+v", snap.Shortcuts)
	}
}

// Publishing a local-only vault whose log ever held a shortcut needs a
// server that lists shortcut, as access needs one that lists access.
func TestPublishWithShortcuts(t *testing.T) {
	ctx := context.Background()
	f, srv := publishFixture(t)
	sc := putShortcut(t, f.s, model.Shortcut{Keys: "u", Command: "uptime", Enter: true})
	if err := f.s.Delete(ctx, sc.ItemID); err != nil {
		t.Fatal(err)
	}
	calls := 0
	for _, p := range []Publisher{publisher{srv}, capsPublisher{publisher{srv}, []model.Type{model.TypeAccess, model.TypeHost}, &calls}} {
		_, err := f.s.Publish(ctx, p, pubOpts)
		if !errors.Is(err, ErrShortcutsUnsupported) {
			t.Fatalf("publish: %v", err)
		}
		// The history holds the shortcut, so removing it would not help:
		// only a server that takes shortcuts will do.
		if msg := err.Error(); strings.Contains(msg, "remove") || strings.Contains(msg, "shortcut rm") {
			t.Errorf("publish: %q advises removing shortcuts", msg)
		} else if _, caps := p.(capsPublisher); caps && !strings.Contains(msg, "upgrade hop-server") {
			t.Errorf("publish: %q, want the advice to upgrade hop-server", msg)
		}
		if pending, err := f.s.l.publicationPending(); err != nil || pending {
			t.Fatalf("publication journaled: %v %v", pending, err)
		}
	}
	if calls != 1 || srv.signups != 0 {
		t.Fatalf("capabilities calls %d, signups %d", calls, srv.signups)
	}
	if _, err := f.s.Publish(ctx, capsPublisher{publisher{srv}, []model.Type{model.TypeHost, model.TypeShortcut}, &calls}, pubOpts); err != nil {
		t.Fatalf("publish to a server that lists shortcut: %v", err)
	}
	published(t, f, f.s, srv)
}
