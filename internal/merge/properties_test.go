package merge

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"slices"
	"strconv"
	"testing"
	"unicode/utf8"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// Properties of the rev 17 rule (crypto spec rev 17 amendment, §8.2),
// checked over seeded random triples (seen, want, S) drawn from small value
// domains, so that the same values, respellings and classes recur often.

type gen struct{ r *rand.Rand }

func (g gen) pick(n int) int { return g.r.IntN(n) }

func (g gen) list(words []string, max int) []string {
	out := []string{}
	for range g.pick(max + 1) {
		out = append(out, words[g.pick(len(words))])
	}
	return out
}

var (
	genNames   = []string{"web", "Web", "web-1", "db", "web."}
	genAliases = []string{"a", "A", "x", "db.", " db", "z", "test-db"}
	genTags    = []string{"prod", "Prod", "old", "db", "ci", "s", "ſ", "k", "K", "K"}
	genAddrs   = [][]string{{"old.example"}, {"new.example"}, {"old.example", "new.example"}, {}}
	genKeys    = [][]string{{}, {"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1"}, {"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey2"}}
	genIDs     = []string{"", idCred, idCred2}
	genJumps   = []string{"", idHost2, idSnip}
	genOutput  = []string{"", model.AgentOutputNone, model.AgentOutputFull}
	genParams  = [][]string{{}, {"unit"}, {"unit", "since"}, {"since", "unit"}}
)

// mutateHost changes each member of h with probability p.
func (g gen) mutateHost(t testing.TB, h model.Host, p float64) model.Host {
	ch := func() bool { return g.r.Float64() < p }
	id := func(from []string) model.ID {
		s := from[g.pick(len(from))]
		if s == "" {
			return model.ID{}
		}
		return mustID(t, s)
	}
	h.Aliases, h.Tags, h.Addresses, h.HostKeys = slices.Clone(h.Aliases), slices.Clone(h.Tags), slices.Clone(h.Addresses), slices.Clone(h.HostKeys)
	if ch() {
		h.Name = genNames[g.pick(len(genNames))]
	}
	if ch() {
		h.Aliases = g.list(genAliases, 3)
	}
	if ch() {
		// Edit the list as a person would: drop, add or respell one.
		switch g.pick(3) {
		case 0:
			if len(h.Tags) > 0 {
				i := g.pick(len(h.Tags))
				h.Tags = append(h.Tags[:i:i], h.Tags[i+1:]...)
			}
		case 1:
			h.Tags = append(h.Tags, genTags[g.pick(len(genTags))])
		default:
			h.Tags = g.list(genTags, 3)
		}
	}
	if ch() {
		h.Addresses = slices.Clone(genAddrs[g.pick(len(genAddrs))])
	}
	if ch() {
		h.Port = []uint32{22, 2222}[g.pick(2)]
	}
	if ch() {
		h.User = []string{"deploy", "root"}[g.pick(2)]
	}
	if ch() {
		h.HostKeys = slices.Clone(genKeys[g.pick(len(genKeys))])
	}
	if ch() {
		h.KeyID = id(genIDs)
	}
	if ch() {
		h.CredentialID = id(genIDs)
	}
	if ch() {
		h.JumpHostID = id(genJumps)
	}
	if ch() {
		h.Route = []string{"auto", "direct", "tailnet"}[g.pick(3)]
	}
	if ch() {
		if g.pick(2) == 0 {
			h.Tailscale = nil
		} else {
			h.Tailscale = &model.Tailscale{StableNodeID: "n1", DNSName: "web.ts.net", SSH: "no"}
		}
	}
	if ch() {
		h.AgentAccess = []string{"allow", "deny"}[g.pick(2)]
	}
	if ch() {
		h.AgentOutput = genOutput[g.pick(len(genOutput))]
	}
	if ch() {
		h.Description = []string{"", "x", "y"}[g.pick(3)]
	}
	return h
}

func (g gen) baseHost(t testing.TB) model.Host {
	h := model.Host{
		Header: model.Header{V: 1, ItemID: mustID(t, idHost), Type: model.TypeHost, ItemVersion: 1},
		Name:   "web", Aliases: []string{}, Tags: []string{"prod", "old"}, Addresses: []string{"old.example"},
		Port: 22, User: "deploy", Route: "auto", HostKeys: []string{}, AgentAccess: "deny",
	}
	return g.mutateHost(t, h, 0.5)
}

func itemOf(t testing.TB, v any, ver uint64) *Item {
	t.Helper()
	it, err := ItemOf(v)
	if err != nil {
		t.Fatal(err)
	}
	it, err = it.with(map[string]canonjson.Raw{"item_version": rawString(strconv.FormatUint(ver, 10))})
	if err != nil {
		t.Fatal(err)
	}
	return it
}

// itemGen draws items of one type: a base, and edits of a version, each
// a new version as one device would write it.
type itemGen struct {
	base   func() any
	mutate func(x any) any
}

// kind picks a type and returns its generator. Half the draws are hosts,
// which have the most members, units and couplings.
func (g gen) kind(t testing.TB) itemGen {
	half := func() bool { return g.pick(2) == 0 }
	switch g.pick(8) {
	case 0:
		mut := func(x model.Snippet) model.Snippet {
			x.Params = slices.Clone(x.Params)
			if half() {
				x.Name = []string{"restart", "status"}[g.pick(2)]
			}
			if half() {
				x.Command = []string{"c", "d"}[g.pick(2)]
			}
			if g.pick(3) == 0 {
				x.Params = slices.Clone(genParams[g.pick(len(genParams))])
			}
			if half() {
				x.Description = []string{"d", "e", "f"}[g.pick(3)]
			}
			return x
		}
		sn := model.Snippet{Header: model.Header{V: 1, ItemID: mustID(t, idSnip), Type: model.TypeSnippet, ItemVersion: 1}, Name: "restart", Command: "c", Params: []string{}, Description: "d"}
		return itemGen{func() any { return mut(sn) }, func(x any) any { return mut(x.(model.Snippet)) }}
	case 1:
		mut := func(x model.Credential) model.Credential {
			if g.pick(3) == 0 {
				x.Name = []string{"n", "m"}[g.pick(2)]
			}
			if half() {
				x.Username = []string{"u", "v"}[g.pick(2)]
			}
			if half() {
				x.Password = []string{"p", "q"}[g.pick(2)]
			}
			return x
		}
		c := model.Credential{Header: model.Header{V: 1, ItemID: mustID(t, idCred), Type: model.TypeCredential, ItemVersion: 1}, Name: "n", Username: "u", Password: "p"}
		return itemGen{func() any { return c }, func(x any) any { return mut(x.(model.Credential)) }}
	case 2:
		mut := func(x model.Policy) model.Policy {
			if half() {
				x.MaxOffline = []uint64{0, 3600, 7200}[g.pick(3)]
			}
			return x
		}
		p := model.Policy{Header: model.Header{V: 1, ItemID: mustID(t, idHost2), Type: model.TypePolicy, ItemVersion: 1}}
		return itemGen{func() any { return p }, func(x any) any { return mut(x.(model.Policy)) }}
	case 3:
		// The key unit is every member: a rotation changes the type and
		// both halves together, a rename only the name.
		mut := func(x model.Key) model.Key {
			if g.pick(3) == 0 {
				x.Name = []string{"k", "deploy"}[g.pick(2)]
			}
			if g.pick(3) == 0 {
				i := g.pick(3)
				x.KeyType = []string{"ed25519", "ecdsa-p256", "rsa"}[i]
				x.PrivateKey = []string{"PRIV-ed", "PRIV-ec", "PRIV-rsa"}[i]
				x.PublicKey = []string{"ssh-ed25519 AAAAed", "ecdsa-sha2-nistp256 AAAAec", "ssh-rsa AAAArsa"}[i]
			}
			if g.pick(4) == 0 {
				x.DedicatedGrant = []model.ID{{}, mustID(t, idHost2)}[g.pick(2)]
			}
			return x
		}
		k := model.Key{Header: model.Header{V: 1, ItemID: mustID(t, idKey), Type: model.TypeKey, ItemVersion: 1},
			Name: "k", KeyType: "ed25519", PrivateKey: "PRIV-ed", PublicKey: "ssh-ed25519 AAAAed"}
		return itemGen{func() any { return mut(k) }, func(x any) any { return mut(x.(model.Key)) }}
	}
	return itemGen{
		func() any { return g.baseHost(t) },
		func(x any) any { return g.mutateHost(t, x.(model.Host), 0.15+0.3*g.r.Float64()) },
	}
}

// triple draws (seen, want, S) of one type.
func (g gen) triple(t testing.TB) (seen, want, s *Item) {
	k := g.kind(t)
	b := k.base()
	return itemOf(t, b, 1), itemOf(t, k.mutate(b), 2), itemOf(t, k.mutate(b), 7)
}

func sameResult(a, b Result) bool {
	if a.Kind != b.Kind || a.Cause != b.Cause || !slices.Equal(a.Replaced, b.Replaced) {
		return false
	}
	if a.Kind == KindWrite {
		return bytes.Equal(a.Plaintext.Plaintext(), b.Plaintext.Plaintext())
	}
	return true
}

// checkProperties checks P1-P5, P7-P9 for one triple.
func checkProperties(t *testing.T, seen, want, s *Item) {
	t.Helper()
	in := put(seen, want)
	res := Rebuild(in, s, true, false)
	old := frozenRev16Put(in, s)
	fail := func(what string) {
		t.Helper()
		t.Fatalf("%s\n seen %s\n want %s\n S    %s\n rev17 %+v\n rev16 %+v", what, seen.Plaintext(), want.Plaintext(), s.Plaintext(), res, old)
	}

	// P4: rev 17 holds only where rev 16 holds, and where rev 16 writes,
	// rev 17 writes the same bytes and the same replaced note.
	switch {
	case res.Kind == KindHold && old.Kind != KindHold:
		fail("P4: rev 17 holds where rev 16 writes")
	case old.Kind == KindWrite && !sameResult(res, old):
		fail("P4: rev 16 writes, and rev 17 writes something else")
	case old.Kind == KindWrite && res.Combined != nil:
		fail("P4: a combined note on a change rev 16 writes")
	case old.Kind == KindHold && res.Kind == KindWrite && res.Combined == nil:
		fail("a write rev 16 would have held has no combined note")
	case res.Kind == KindHold && res.Cause != CauseGuardedConflict:
		fail("unexpected hold cause")
	}

	// P1: the hold decision is symmetric, with the same conflicts.
	swapped := Rebuild(put(seen, s), want, true, false)
	if (swapped.Kind == KindHold) != (res.Kind == KindHold) {
		fail("P1: swapping want and S changes the hold decision")
	}
	if res.Kind == KindHold && !slices.Equal(sortedIDs(res.Conflicts), sortedIDs(swapped.Conflicts)) {
		fail("P1: swapping want and S changes the conflicts")
	}
	// P2: both orders write the same bytes, except a free member both
	// changed (each order's rebasing side wins it).
	if res.Kind == KindWrite && swapped.Kind == KindWrite {
		ex := map[string]bool{}
		for _, m := range res.Replaced {
			ex[m] = true
		}
		for _, m := range names(res.Plaintext, swapped.Plaintext) {
			if !ex[m] && !memberEqual(res.Plaintext, swapped.Plaintext, m) {
				fail("P2: the two orders write different " + m)
			}
		}
	}
	if res.Kind == KindWrite {
		checkWritten(t, in, s, res.Plaintext, nil, fail)
		// P6, no resurrection: a member the user didn't change keeps S's.
		for _, m := range names(seen, want, s) {
			if memberEqual(want, seen, m) && !memberEqual(res.Plaintext, s, m) {
				fail("P6: " + m + " was not changed here, and S's value was overwritten")
			}
		}
	}
	// P8, P9: proposals.
	pm, pt, ok, err := proposals(in, s)
	if err != nil {
		fail("proposals: " + err.Error())
	}
	if ok != (res.Kind == KindHold && len(res.Conflicts) > 0) {
		fail("a proposal exists exactly for a unit, class or coupling hold")
	}
	if ok {
		a := analyze(in.Type, seen, want, s)
		checkWritten(t, in, s, pm, &a, fail)
		checkWritten(t, in, s, pt, &a, fail)
		checkProposal(pm, want, &a, fail)
		checkProposal(pt, s, &a, fail)
		pm2, pt2, _, _ := proposals(in, s)
		if !bytes.Equal(pm.Plaintext(), pm2.Plaintext()) || !bytes.Equal(pt.Plaintext(), pt2.Plaintext()) {
			fail("P9: proposals are not deterministic")
		}
	}
}

func sortedIDs(cs []Conflict) []string {
	out := conflictIDs(cs)
	slices.Sort(out)
	return out
}

// checkWritten checks P3 (unit integrity), P5 (no invention) and, for an
// automatic write (a == nil), P7 (no coupled combination).
func checkWritten(t *testing.T, in Intent, s, w *Item, a *analysis, fail func(string)) {
	t.Helper()
	cl := classifications[in.Type]
	for _, u := range cl.units {
		fromWant, fromS := true, true
		for _, m := range u.members {
			fromWant = fromWant && memberEqual(w, in.Want, m)
			fromS = fromS && memberEqual(w, s, m)
		}
		if !fromWant && !fromS {
			fail("P3: unit " + u.name + " mixes the two sides")
		}
	}
	for _, m := range names(in.Seen, in.Want, s, w) {
		if !memberEqual(w, in.Seen, m) && !memberEqual(w, in.Want, m) && !memberEqual(w, s, m) {
			if key := cl.sets[m]; key != nil {
				got, _ := stringList(w, m)
				for _, x := range got {
					var found bool
					for _, src := range []*Item{in.Seen, in.Want, s} {
						l, _ := stringList(src, m)
						found = found || slices.Contains(l, x)
					}
					if !found {
						fail("P5: " + m + " has an invented string " + x)
					}
				}
				continue
			}
			fail("P5: " + m + " has an invented value")
		}
	}
	if a != nil || len(cl.couplings) == 0 {
		return
	}
	// P7: a trigger fired by one side means the other side's effective
	// changes to the coupled group did not survive.
	v := func(it *Item) *hostView { x, _ := viewOf(it); return x }
	seen, want, sv := v(in.Seen), v(in.Want), v(s)
	if seen == nil || want == nil || sv == nil {
		return
	}
	for _, cp := range cl.couplings {
		g := cl.unit(cp.group).members
		if cp.trigger(want, sv, seen).fired() {
			for _, m := range g {
				if !memberEqual(w, in.Want, m) {
					fail("P7: " + cp.name + " fired here, and S's " + m + " was written")
				}
			}
		}
		if cp.trigger(sv, want, seen).fired() {
			for _, m := range g {
				if !memberEqual(w, s, m) {
					fail("P7: " + cp.name + " fired on S, and this device's " + m + " was written")
				}
			}
		}
	}
}

// checkProposal checks P8: a proposal takes X's values on C and the
// automatic merge's outside it.
func checkProposal(p, x *Item, a *analysis, fail func(string)) {
	for m, mm := range a.merged {
		switch a.cl.kind(m) {
		case kindAtomic:
			if a.c.atoms[m] {
				if !memberEqual(p, x, m) {
					fail("P8: conflict member " + m + " is not X's")
				}
				continue
			}
		case kindSet:
			if cm := a.c.classes[m]; len(cm) > 0 {
				key := a.cl.sets[m]
				got, _ := stringList(p, m)
				xl, _ := stringList(x, m)
				var ml []string
				if err := json.Unmarshal(mm, &ml); err != nil {
					fail("P8: " + err.Error())
				}
				part := func(l []string, inC bool) map[string]bool {
					out := map[string]bool{}
					for _, s := range l {
						if cm[key(s)] == inC {
							out[s] = true
						}
					}
					return out
				}
				if !mapsEqual(part(got, true), part(xl, true)) || !mapsEqual(part(got, false), part(ml, false)) {
					fail("P8: set member " + m + " is not X's on C and the merge's elsewhere")
				}
				continue
			}
		}
		raw, ok := p.members[m]
		if ok != (mm != nil) || !bytes.Equal(raw, mm) {
			fail("P8: member " + m + " outside C is not the automatic merge's")
		}
	}
}

func mapsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func TestRev17Properties(t *testing.T) {
	g := gen{rand.New(rand.NewPCG(17, 5_4))}
	holds, combined := 0, 0
	for range 20000 {
		seen, want, s := g.triple(t)
		checkProperties(t, seen, want, s)
		res := Rebuild(put(seen, want), s, true, false)
		if res.Kind == KindHold {
			holds++
		} else if res.Combined != nil {
			combined++
		}
	}
	// The generator must reach both sides of the rule often.
	if holds < 1000 || combined < 500 {
		t.Errorf("weak generator: %d holds, %d combined writes", holds, combined)
	}
}

// P6, chained queues: this device queues several changes to one item,
// each seen as the one before it, while another device's change is
// already on the server. They are rebased one after the other, each
// against what the one before left (§2.5: a later record keeps its
// original seen), and a held one is resolved with take theirs (the record
// is dropped), keep mine or a --merge proposal. Every step has the
// properties above (P6 among them: a member the step's change did not
// touch keeps the value before it, so a change take theirs dropped never
// comes back with the next one). Over the whole chain, a member that no
// change still standing touched keeps the server's value, unless the user
// confirmed a --merge proposal that set it; and every value comes from the
// base, the server's version or a queued change (no invention).
func TestRev17ChainedQueues(t *testing.T) {
	g := gen{rand.New(rand.NewPCG(17, 6))}
	var steps, holds, afterHold, resolved int
	for range 4000 {
		k := g.kind(t)
		vs := []any{k.base()}
		for range 2 + g.pick(3) {
			vs = append(vs, k.mutate(vs[len(vs)-1]))
		}
		ws := make([]*Item, len(vs))
		for i, v := range vs {
			ws[i] = itemOf(t, v, uint64(1+i))
		}
		s0 := itemOf(t, k.mutate(vs[0]), 9)
		cur, held := s0, false
		confirmed := map[string]bool{} // set by a confirmed --merge proposal
		kept := map[string]bool{}      // touched by a change that was written
		for i := 1; i < len(ws); i++ {
			in := put(ws[i-1], ws[i])
			checkProperties(t, ws[i-1], ws[i], cur)
			steps++
			if held {
				afterHold++
			}
			res := Rebuild(in, cur, true, false)
			fail := func(what string) {
				t.Helper()
				t.Fatalf("step %d: %s\n seen %s\n want %s\n cur  %s\n %+v", i, what, ws[i-1].Plaintext(), ws[i].Plaintext(), cur.Plaintext(), res)
			}
			keep := func() {
				for _, m := range diff(ws[i], ws[i-1]) {
					kept[m] = true
				}
			}
			switch res.Kind {
			case KindWrite:
				keep()
				cur = res.Plaintext
			case KindHold:
				holds++
				held = true
				var r Intent
				var err error
				choice := g.pick(4)
				switch choice {
				case 0:
					continue // take theirs: the record is dropped
				case 1:
					r, err = KeepMine(in, res.Cause, cur)
				case 2:
					r, err = KeepMineMerge(in, res.Cause, cur)
				default:
					r, err = TakeTheirsMerge(in, res.Cause, cur)
				}
				if errors.Is(err, ErrRefused) {
					continue // not offered: take theirs instead
				}
				if err != nil {
					fail("resolution: " + err.Error())
				}
				w := Rebuild(r, cur, true, false)
				if w.Kind != KindWrite {
					fail("a resolution against the S it was made for does not write")
				}
				resolved++
				keep()
				if choice >= 2 {
					for _, m := range diff(w.Plaintext, cur) {
						confirmed[m] = true
					}
				}
				cur = w.Plaintext
			}
		}
		for _, m := range names(append([]*Item{s0, cur}, ws...)...) {
			if headerMember(m) {
				continue
			}
			if !kept[m] && !confirmed[m] && !memberEqual(cur, s0, m) {
				t.Fatalf("P6: no change still standing touched %s, and the server's value did not survive\n S %s\n end %s", m, s0.Plaintext(), cur.Plaintext())
			}
			if fromAny(cur, m, s0, ws...) {
				continue
			}
			t.Fatalf("P5 over the chain: %s was invented\n end %s", m, cur.Plaintext())
		}
	}
	t.Logf("%d steps, %d holds, %d steps after a hold, %d resolved", steps, holds, afterHold, resolved)
	if holds < 300 || afterHold < 300 || resolved < 100 {
		t.Errorf("weak chains: %d steps, %d holds, %d steps after a hold, %d resolved", steps, holds, afterHold, resolved)
	}
}

func headerMember(m string) bool { return slices.Contains(headerMembers[:], m) }

// fromAny reports whether w's m is the value of m in one of the sources or,
// for a set member, whether each of its strings is in one of them.
func fromAny(w *Item, m string, s *Item, ws ...*Item) bool {
	srcs := append([]*Item{s}, ws...)
	for _, src := range srcs {
		if memberEqual(w, src, m) {
			return true
		}
	}
	cl := classifications[w.typ]
	if cl == nil || cl.sets[m] == nil {
		return false
	}
	got, _ := stringList(w, m)
	for _, x := range got {
		found := false
		for _, src := range srcs {
			l, _ := stringList(src, m)
			found = found || slices.Contains(l, x)
		}
		if !found {
			return false
		}
	}
	return true
}

// inject puts an arbitrary string into one of the three versions, beyond
// the generator's small domains: as a tag or an alias (any spelling, any
// class key), as the name, or as the value of a member no classification
// lists, which sends the item to the rev 16 fallback.
func inject(items []*Item, which uint8, extra string) ([]*Item, bool) {
	if !utf8.ValidString(extra) {
		return nil, false
	}
	raw, err := canonjson.Marshal(extra)
	if err != nil {
		return nil, false
	}
	i := int(which/4) % len(items)
	it := items[i]
	var set map[string]canonjson.Raw
	switch m := []string{"tags", "aliases", "name", "x_unlisted"}[which%4]; m {
	case "tags", "aliases":
		l, ok := stringList(it, m)
		if !ok {
			return items, true
		}
		set = map[string]canonjson.Raw{m: encodeList(append(l, extra))}
	case "name":
		if _, ok := it.members[m]; !ok {
			return items, true
		}
		set = map[string]canonjson.Raw{m: raw}
	default:
		set = map[string]canonjson.Raw{m: raw}
	}
	nit, err := it.with(set)
	if err != nil {
		return nil, false
	}
	out := slices.Clone(items)
	out[i] = nit
	return out, true
}

// The fuzz target draws from the generator and then injects an arbitrary
// string, so that fuzzing reaches strings, class keys and unclassified
// members the small domains above never produce. Without -fuzz, go test
// runs the seeds below.
func FuzzRev17Properties(f *testing.F) {
	for i := range uint64(32) {
		f.Add(i, i*7919, "", uint8(i))
	}
	for i, s := range []string{"PROD", "ſ", "K", "İ", "ß", "ﬀ", " db", "db.", "web", "Web", "\u00a0prod", "ǅ"} {
		f.Add(uint64(100+i), uint64(i), s, uint8(i))
	}
	f.Fuzz(func(t *testing.T, a, b uint64, extra string, which uint8) {
		g := gen{rand.New(rand.NewPCG(a, b))}
		seen, want, s := g.triple(t)
		if extra != "" {
			items, ok := inject([]*Item{seen, want, s}, which, extra)
			if !ok {
				t.Skip("not a string an item can hold")
			}
			seen, want, s = items[0], items[1], items[2]
		}
		checkProperties(t, seen, want, s)
	})
}
