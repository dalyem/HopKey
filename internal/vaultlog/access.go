package vaultlog

import (
	"bytes"
	"slices"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// Log rules of the access item (crypto spec rev 17, Part 2, §5.1). They
// compare a put with the item's pre-state, so a device that anchors at a
// checkpoint applies only the schema to the items in the anchor.
const (
	RuleAccessIdentity   Rule = "access.identity"   // label, record_id, public_key, fingerprint or options changed
	RuleAccessTargets    Rule = "access.targets"    // a target was dropped, or its binding or user changed
	RuleAccessAuthor     Rule = "access.author"     // a normal put whose by isn't the entry's author
	RuleAccessCheckpoint Rule = "access.checkpoint" // a checkpoint put that changes a non-header member
	RuleAccessTerminal   Rule = "access.terminal"   // a removed or abandoned target changed
)

// ItemTypes are the item types this build accepts in the log (§5.2),
// sorted. The server reports them in GET /v1/capabilities.
func ItemTypes() []model.Type {
	out := []model.Type{model.TypeAccess, model.TypeCredential, model.TypeGrant, model.TypeHost,
		model.TypeKey, model.TypePolicy, model.TypeSnippet}
	slices.Sort(out)
	return out
}

// CheckAccessPut applies the access log rules to one item_put. pre is the
// item in the pre-state, nil for a create; post is the put. kind is the
// entry's kind and author its author device.
func CheckAccessPut(pre, post *model.Access, kind Kind, author model.ID) error {
	if kind == KindNormal && post.By != author {
		return fail(RuleAccessAuthor, "access item %v names device %v as its author, the entry's author is %v", post.ItemID, post.By, author)
	}
	if pre == nil {
		return nil
	}
	if err := CheckAccessIdentity(pre, post); err != nil {
		return err
	}
	if kind == KindCheckpoint && !sameAccessBody(pre, post) {
		return fail(RuleAccessCheckpoint, "checkpoint re-put of access item %v changes it", post.ItemID)
	}
	return nil
}

// CheckAccessIdentity is the record-identity, target-identity and
// terminal non-regression rules for a put of post over pre.
func CheckAccessIdentity(pre, post *model.Access) error {
	if pre.Label != post.Label || pre.RecordID != post.RecordID || pre.PublicKey != post.PublicKey ||
		pre.Fingerprint != post.Fingerprint || !jsonEqual(pre.Options, post.Options) {
		return fail(RuleAccessIdentity, "access item %v changes its label, record_id, key or options; that needs a new record", post.ItemID)
	}
	for _, t := range pre.Targets {
		n := AccessTargetOf(post, t.HostItemID, t.ServerKeyFP)
		if n == nil {
			return fail(RuleAccessTargets, "access item %v drops its target on host %v bound to %s", post.ItemID, t.HostItemID, t.ServerKeyFP)
		}
		if n.User != t.User {
			return fail(RuleAccessTargets, "access item %v changes the login user of its target on host %v", post.ItemID, t.HostItemID)
		}
		if model.AccessTerminal(t.State) && !jsonEqual(t, *n) {
			return fail(RuleAccessTerminal, "access item %v changes its %s target on host %v bound to %s", post.ItemID, t.State, t.HostItemID, t.ServerKeyFP)
		}
	}
	return nil
}

// AccessTargetOf returns a's target with binding (host, fp), or nil.
func AccessTargetOf(a *model.Access, host model.ID, fp string) *model.AccessTarget {
	for i := range a.Targets {
		if a.Targets[i].HostItemID == host && a.Targets[i].ServerKeyFP == fp {
			return &a.Targets[i]
		}
	}
	return nil
}

// sameAccessBody reports whether a and b agree on every non-header member.
func sameAccessBody(a, b *model.Access) bool {
	x, y := *a, *b
	x.Header, y.Header = model.Header{}, model.Header{}
	return jsonEqual(x, y)
}

func jsonEqual(a, b any) bool {
	x, err1 := canonjson.Marshal(a)
	y, err2 := canonjson.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}
