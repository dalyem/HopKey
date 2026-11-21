package vaultlog

import (
	"testing"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// A shortcut's host_id is a reference (§5.3): it names a live host or is
// "", and the host can't go while the shortcut names it.
func TestShortcutHostReference(t *testing.T) {
	w := newWorld(t).withItems()
	sc := func(id byte, host model.ID) *model.Shortcut {
		return &model.Shortcut{Header: model.Header{ItemID: fixedID(id), Type: model.TypeShortcut}, Keys: "u", Command: "uptime", HostID: host}
	}
	wantRule(t, w.transition(w.unverified(Changes{Put: []crypto.Item{sc(0x70, idK1)}})), RuleRefIntegrity)
	wantRule(t, w.transition(w.unverified(Changes{Put: []crypto.Item{sc(0x70, fixedID(0x7f))}})), RuleRefIntegrity)
	mustAccept(t, w.transition(w.unverified(Changes{Put: []crypto.Item{sc(0x70, model.ID{})}})))
	w.normal(Changes{Put: []crypto.Item{sc(0x71, idH1)}})
	wantRule(t, w.transition(w.unverified(Changes{Delete: []model.ID{idH1}})), RuleRefIntegrity)
	mustAccept(t, w.transition(w.unverified(Changes{Delete: []model.ID{idH1, fixedID(0x71)}})))
}
