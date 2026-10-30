package merge

import (
	"errors"
	"slices"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// In the put table seen is at item_version 1, want at 2 and S at 7, so
// every case also shows that header members never matter and that the
// result's header comes from S.
const (
	verSeen = 1
	verWant = 2
	verS    = 7
)

func TestRebuildPut(t *testing.T) {
	type mods []hostMod
	tests := []struct {
		name string
		seen mods // mods on the base host
		want mods
		s    mods

		// Write: the result is the base host with these mods, at S's version,
		// and the free members whose remote value want replaced.
		result   mods
		replaced []string
		// Hold: the cause and the guarded members on each side.
		hold          Cause
		local, remote []string
	}{
		{
			name:   "S unchanged since seen",
			want:   mods{name("new")},
			result: mods{name("new")},
		},
		{
			name:   "remote guarded change only keeps the remote value",
			s:      mods{addrs("10.0.0.2")},
			result: mods{addrs("10.0.0.2")},
		},
		{
			name:   "local guarded change, remote free change",
			want:   mods{name("new")},
			s:      mods{hostDesc("remote")},
			result: mods{name("new"), hostDesc("remote")},
		},
		{
			name:   "local free change, remote guarded change",
			want:   mods{hostDesc("local")},
			s:      mods{name("theirs")},
			result: mods{name("theirs"), hostDesc("local")},
		},
		{
			name:     "free member in both takes want",
			want:     mods{hostDesc("b")},
			s:        mods{hostDesc("c")},
			result:   mods{hostDesc("b")},
			replaced: []string{"description"},
		},
		{
			name:     "free in both, guarded only local",
			want:     mods{name("new"), hostDesc("b")},
			s:        mods{hostDesc("c")},
			result:   mods{name("new"), hostDesc("b")},
			replaced: []string{"description"},
		},
		{
			name:     "free in both, guarded only remote",
			want:     mods{hostDesc("b")},
			s:        mods{user("admin"), hostDesc("c")},
			result:   mods{user("admin"), hostDesc("b")},
			replaced: []string{"description"},
		},
		{
			name:   "free in both, equal",
			want:   mods{hostDesc("same")},
			s:      mods{hostDesc("same")},
			result: mods{hostDesc("same")},
		},
		{
			// A new credential on one device and a new address on another
			// would combine into something neither approved.
			name:   "credential versus address holds",
			want:   mods{credRef(t, idCred2)},
			s:      mods{addrs("10.0.0.2")},
			hold:   CauseGuardedConflict,
			local:  []string{"credential_id"},
			remote: []string{"addresses"},
		},
		{
			name:   "same guarded member changed differently holds",
			want:   mods{name("x")},
			s:      mods{name("y")},
			hold:   CauseGuardedConflict,
			local:  []string{"name"},
			remote: []string{"name"},
		},
		{
			name:   "guarded conflict holds even with a free change alongside",
			want:   mods{name("x"), hostDesc("l")},
			s:      mods{user("admin"), hostDesc("r")},
			hold:   CauseGuardedConflict,
			local:  []string{"name"},
			remote: []string{"user"},
		},
		{
			name:   "identical guarded edits write",
			want:   mods{name("x")},
			s:      mods{name("x")},
			result: mods{name("x")},
		},
		{
			name:   "identical guarded edits keep the remote free change",
			want:   mods{name("x")},
			s:      mods{name("x"), hostDesc("r")},
			result: mods{name("x"), hostDesc("r")},
		},
		{
			name:   "identical guarded edits take the local free change",
			want:   mods{name("x"), hostDesc("l")},
			s:      mods{name("x")},
			result: mods{name("x"), hostDesc("l")},
		},
		{
			// Rev 16 held this (lists compared whole). Rev 17 merges tags by
			// class: c added here, b removed there.
			name:   "a set both sides changed merges by class",
			seen:   mods{tags("a", "b")},
			want:   mods{tags("a", "b", "c")},
			s:      mods{tags("a")},
			result: mods{tags("a", "c")},
		},
		{
			// A reorder is a change to tags, which is in no unit with the
			// addresses, so rev 17 writes both (rev 16 held it).
			name:   "a reordered list is a change, and merges with an address",
			seen:   mods{tags("a", "b")},
			want:   mods{tags("b", "a")},
			s:      mods{tags("a", "b"), addrs("10.0.0.2")},
			result: mods{tags("b", "a"), addrs("10.0.0.2")},
		},
		{
			name:   "identical list edits write",
			seen:   mods{tags("a")},
			want:   mods{tags("a", "b")},
			s:      mods{tags("a", "b")},
			result: mods{tags("a", "b")},
		},
		{
			// The user's earlier edit (name) was queued and merged first. It
			// absorbed a remote address into S. This later edit saw the old
			// address, so the new one is remote to it and is never overwritten.
			name:   "queued edit whose predecessor absorbed a remote guarded change holds",
			seen:   mods{name("renamed")},
			want:   mods{name("renamed"), user("bob")},
			s:      mods{name("renamed"), addrs("10.0.0.9")},
			hold:   CauseGuardedConflict,
			local:  []string{"user"},
			remote: []string{"addresses"},
		},
		{
			name:   "queued edit of a free member keeps what the predecessor absorbed",
			seen:   mods{name("renamed")},
			want:   mods{name("renamed"), hostDesc("later")},
			s:      mods{name("renamed"), addrs("10.0.0.9")},
			result: mods{name("renamed"), addrs("10.0.0.9"), hostDesc("later")},
		},
		{
			// The predecessor renamed the host to "mine" and was discarded with
			// take theirs, so S keeps "theirs". This edit was made on top of the
			// overlay that still showed "mine".
			name:   "discarded predecessor is not resurrected by a free edit",
			seen:   mods{name("mine")},
			want:   mods{name("mine"), hostDesc("l2")},
			s:      mods{name("theirs")},
			result: mods{name("theirs"), hostDesc("l2")},
		},
		{
			name:   "discarded predecessor is not resurrected by a guarded edit",
			seen:   mods{name("mine")},
			want:   mods{name("mine"), user("bob")},
			s:      mods{name("theirs")},
			hold:   CauseGuardedConflict,
			local:  []string{"user"},
			remote: []string{"name"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seen := host(t, verSeen, tc.seen...)
			want := host(t, verWant, tc.want...)
			s := host(t, verS, tc.s...)
			res := Rebuild(put(seen, want), s, true, false)
			if tc.hold != "" {
				if res.Kind != KindHold || res.Cause != tc.hold {
					t.Fatalf("got %s/%s, want a %s hold", res.Kind, res.Cause, tc.hold)
				}
				if !slices.Equal(res.Local, tc.local) || !slices.Equal(res.Remote, tc.remote) {
					t.Errorf("local %v remote %v, want local %v remote %v", res.Local, res.Remote, tc.local, tc.remote)
				}
				if res.Plaintext != nil {
					t.Error("a hold carries a plaintext")
				}
				return
			}
			if res.Kind != KindWrite || res.Action != ActionPut {
				t.Fatalf("got %s/%s/%v, want a put write", res.Kind, res.Action, res.Cause)
			}
			samePlain(t, res.Plaintext, host(t, verS, tc.result...))
			if !slices.Equal(res.Replaced, tc.replaced) {
				t.Errorf("replaced %v, want %v", res.Replaced, tc.replaced)
			}
		})
	}
}

func TestRebuildHeaderMembersNeverMatter(t *testing.T) {
	// Three different item_versions and identical bodies: nothing changed.
	seen, want, s := host(t, 1), host(t, 5), host(t, 9)
	res := Rebuild(put(seen, want), s, true, false)
	if res.Kind != KindWrite {
		t.Fatalf("got %s/%s, want a write", res.Kind, res.Cause)
	}
	samePlain(t, res.Plaintext, s)

	// A remote version bump with no body change is not a remote change, so
	// a guarded edit made against the older version goes through.
	res = Rebuild(put(host(t, 1), host(t, 2, name("x"))), host(t, 9), true, false)
	if res.Kind != KindWrite {
		t.Fatalf("got %s/%s, want a write", res.Kind, res.Cause)
	}
	samePlain(t, res.Plaintext, host(t, 9, name("x")))

	// And a delete goes through when only the version differs.
	if res := Rebuild(del(host(t, 1)), host(t, 9), true, false); res.Kind != KindWrite || res.Action != ActionDelete {
		t.Errorf("delete: got %s/%s/%s", res.Kind, res.Action, res.Cause)
	}
}

func TestRebuildPutNotLive(t *testing.T) {
	seen, want := host(t, 1), host(t, 2, name("x"))
	for _, tc := range []struct {
		name    string
		retired bool
	}{
		{"deleted in S", true},
		{"never existed in S", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := Rebuild(put(seen, want), nil, false, tc.retired)
			if res.Kind != KindHold || res.Cause != CauseNotLive {
				t.Errorf("got %s/%s, want a not_live hold", res.Kind, res.Cause)
			}
		})
	}
}

func TestRebuildCreate(t *testing.T) {
	want := host(t, 1, name("new"))
	tests := []struct {
		name          string
		live, retired bool
		hold          bool
	}{
		{"free ID", false, false, false},
		{"ID live", true, false, true},
		{"ID retired", false, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var current *Item
			if tc.live {
				current = host(t, 3)
			}
			res := Rebuild(create(want), current, tc.live, tc.retired)
			if tc.hold {
				if res.Kind != KindHold || res.Cause != CauseIDTaken {
					t.Fatalf("got %s/%s, want an id_taken hold", res.Kind, res.Cause)
				}
				return
			}
			if res.Kind != KindWrite || res.Action != ActionCreate {
				t.Fatalf("got %s/%s/%s, want a create write", res.Kind, res.Action, res.Cause)
			}
			samePlain(t, res.Plaintext, want)
		})
	}
}

func TestRebuildDelete(t *testing.T) {
	seen := host(t, 1)
	tests := []struct {
		name          string
		s             *Item
		live, retired bool
		kind          Kind
		cause         Cause
	}{
		{"already deleted", nil, false, true, KindDrop, ""},
		{"never existed", nil, false, false, KindDrop, ""},
		{"unchanged", host(t, 4), true, false, KindWrite, ""},
		{"guarded member changed", host(t, 4, name("x")), true, false, KindHold, CauseDeleteChanged},
		// A delete needs S to equal seen on every non-header member, free
		// ones included: the user never saw the new description.
		{"free member changed", host(t, 4, hostDesc("r")), true, false, KindHold, CauseDeleteChanged},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := Rebuild(del(seen), tc.s, tc.live, tc.retired)
			if res.Kind != tc.kind || res.Cause != tc.cause {
				t.Fatalf("got %s/%s, want %s/%s", res.Kind, res.Cause, tc.kind, tc.cause)
			}
			if tc.kind == KindWrite && (res.Action != ActionDelete || res.Plaintext != nil) {
				t.Errorf("a delete write has action %s and plaintext %v", res.Action, res.Plaintext)
			}
		})
	}
}

func TestRebuildFreeAndGuardedTables(t *testing.T) {
	// credential: no free members, so any two edits to different members
	// hold.
	seen := credential(t, 1, nil)
	want := credential(t, 2, func(c *model.Credential) { c.Password = "new" })
	s := credential(t, 3, func(c *model.Credential) { c.Username = "admin" })
	if res := Rebuild(put(seen, want), s, true, false); res.Kind != KindHold || res.Cause != CauseGuardedConflict {
		t.Errorf("credential: got %s/%s, want a guarded hold", res.Kind, res.Cause)
	}
	// ...but a change on one side only is fine.
	res := Rebuild(put(seen, want), seen, true, false)
	samePlain(t, res.Plaintext, credential(t, 1, func(c *model.Credential) { c.Password = "new" }))

	// key: no free members either.
	kseen := key(t, 1, nil)
	kwant := key(t, 2, func(k *model.Key) { k.Name = "renamed" })
	ks := key(t, 3, func(k *model.Key) { k.PrivateKey = "rotated" })
	if res := Rebuild(put(kseen, kwant), ks, true, false); res.Kind != KindHold || res.Cause != CauseGuardedConflict {
		t.Errorf("key: got %s/%s, want a guarded hold", res.Kind, res.Cause)
	}

	// snippet: description is free, command and name are guarded.
	sseen := snippet(t, 1, nil)
	swant := snippet(t, 2, func(s *model.Snippet) { s.Description = "mine" })
	ss := snippet(t, 3, func(s *model.Snippet) { s.Description = "theirs"; s.Command = "reboot" })
	res = Rebuild(put(sseen, swant), ss, true, false)
	if res.Kind != KindWrite {
		t.Fatalf("snippet: got %s/%s, want a write", res.Kind, res.Cause)
	}
	samePlain(t, res.Plaintext, snippet(t, 3, func(s *model.Snippet) { s.Description = "mine"; s.Command = "reboot" }))
	swant = snippet(t, 2, func(s *model.Snippet) { s.Name = "renamed" })
	if res := Rebuild(put(sseen, swant), ss, true, false); res.Kind != KindHold {
		t.Errorf("snippet name vs command: got %s, want a hold", res.Kind)
	}
}

func TestFreeAndGuardedMembers(t *testing.T) {
	for _, tc := range []struct {
		typ    model.Type
		member string
		free   bool
	}{
		{model.TypeHost, "description", true},
		{model.TypeSnippet, "description", true},
		{model.TypeHost, "name", false},
		{model.TypeHost, "aliases", false},
		{model.TypeHost, "tags", false},
		{model.TypeHost, "credential_id", false},
		{model.TypeSnippet, "command", false},
		{model.TypeKey, "description", false},
		{model.TypeCredential, "description", false},
	} {
		if got := IsFree(tc.typ, tc.member); got != tc.free {
			t.Errorf("IsFree(%s, %s) = %v", tc.typ, tc.member, got)
		}
		if got := IsGuarded(tc.typ, tc.member); got != !tc.free {
			t.Errorf("IsGuarded(%s, %s) = %v", tc.typ, tc.member, got)
		}
	}
	for _, h := range []string{"v", "item_id", "type", "item_version"} {
		if IsGuarded(model.TypeHost, h) || IsFree(model.TypeHost, h) {
			t.Errorf("header member %s is classified", h)
		}
	}
}

func TestRebuildRejectsMalformedIntents(t *testing.T) {
	h1, h2 := host(t, 1), host(t, 2, name("x"))
	other := host(t, 1)
	other, err := other.with(map[string]canonjson.Raw{"item_id": rawString(idHost2)})
	if err != nil {
		t.Fatal(err)
	}
	cred := credential(t, 1, nil)
	tests := []struct {
		name string
		in   Intent
	}{
		{"create with seen", Intent{Action: ActionCreate, ItemID: h1.ID(), Type: model.TypeHost, Seen: h1, Want: h2}},
		{"create without want", Intent{Action: ActionCreate, ItemID: h1.ID(), Type: model.TypeHost}},
		{"put without seen", Intent{Action: ActionPut, ItemID: h1.ID(), Type: model.TypeHost, Want: h2}},
		{"put without want", Intent{Action: ActionPut, ItemID: h1.ID(), Type: model.TypeHost, Seen: h1}},
		{"delete with want", Intent{Action: ActionDelete, ItemID: h1.ID(), Type: model.TypeHost, Seen: h1, Want: h2}},
		{"delete without seen", Intent{Action: ActionDelete, ItemID: h1.ID(), Type: model.TypeHost}},
		{"unknown action", Intent{Action: "merge", ItemID: h1.ID(), Type: model.TypeHost, Seen: h1, Want: h2}},
		{"zero item_id", Intent{Action: ActionDelete, Type: model.TypeHost, Seen: h1}},
		{"want of another item", Intent{Action: ActionPut, ItemID: h1.ID(), Type: model.TypeHost, Seen: h1, Want: other}},
		{"want of another type", Intent{Action: ActionPut, ItemID: h1.ID(), Type: model.TypeHost, Seen: h1, Want: cred}},
		{"grant type", Intent{Action: ActionDelete, ItemID: h1.ID(), Type: model.TypeGrant, Seen: h1}},
		{"unknown type", Intent{Action: ActionDelete, ItemID: h1.ID(), Type: "widget", Seen: h1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.in.Validate(); err == nil {
				t.Error("Validate accepted it")
			}
			res := Rebuild(tc.in, h1, true, false)
			if res.Kind != KindHold || res.Cause != CauseRuleFailure || res.Err == nil {
				t.Errorf("Rebuild: got %s/%s/%v, want a rule_failure hold with an error", res.Kind, res.Cause, res.Err)
			}
		})
	}

	// The caller handing over the wrong S is a bug, not a merge.
	for _, tc := range []struct {
		name string
		in   Intent
		cur  *Item
		live bool
	}{
		{"S of another item", put(h1, h2), other, true},
		{"S of another type", put(h1, h2), cred, true},
		{"live without plaintext", put(h1, h2), nil, true},
		{"delete, S of another item", del(h1), other, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := Rebuild(tc.in, tc.cur, tc.live, false)
			if res.Kind != KindHold || res.Cause != CauseRuleFailure {
				t.Errorf("got %s/%s, want a rule_failure hold", res.Kind, res.Cause)
			}
		})
	}
}

func TestCheckCandidate(t *testing.T) {
	h1, h2 := host(t, 1), host(t, 2, name("x"))
	blocker := errors.New("a reference to the item remains")
	calls := 0
	failing := func(Action, *Item) error { calls++; return blocker }
	passing := func(Action, *Item) error { calls++; return nil }

	write := Rebuild(put(h1, h2), h1, true, false)
	if write.Kind != KindWrite {
		t.Fatalf("setup: %s", write.Kind)
	}
	// A failure maps to a rule_failure hold that keeps the cause.
	got := CheckCandidate(write, failing)
	if got.Kind != KindHold || got.Cause != CauseRuleFailure || !errors.Is(got.Err, blocker) {
		t.Errorf("failing check: got %s/%s/%v", got.Kind, got.Cause, got.Err)
	}
	if got.Plaintext != nil {
		t.Error("a held result still carries the plaintext")
	}
	// A pass changes nothing.
	if got := CheckCandidate(write, passing); got.Kind != KindWrite || got.Plaintext != write.Plaintext {
		t.Errorf("passing check changed the result: %s", got.Kind)
	}
	// The check sees the action and the plaintext, which is nil for a delete.
	var sawAction Action
	var sawPlain *Item
	CheckCandidate(Rebuild(del(h1), h1, true, false), func(a Action, p *Item) error {
		sawAction, sawPlain = a, p
		return nil
	})
	if sawAction != ActionDelete || sawPlain != nil {
		t.Errorf("delete check saw %s/%v", sawAction, sawPlain)
	}
	// Holds and drops pass through without running the check.
	calls = 0
	for _, r := range []Result{
		{Kind: KindDrop},
		{Kind: KindHold, Cause: CauseGuardedConflict},
	} {
		if got := CheckCandidate(r, failing); got.Kind != r.Kind || got.Cause != r.Cause {
			t.Errorf("%s changed to %s/%s", r.Kind, got.Kind, got.Cause)
		}
	}
	if calls != 0 {
		t.Errorf("check ran %d times for non-writes", calls)
	}
	// A delete whose rule fails holds as a rule failure too.
	got = CheckCandidate(Rebuild(del(h1), h1, true, false), failing)
	if got.Kind != KindHold || got.Cause != CauseRuleFailure {
		t.Errorf("failing delete: got %s/%s", got.Kind, got.Cause)
	}
}
