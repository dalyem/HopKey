package merge

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// The rev 17 put rule (crypto spec rev 17 amendment, §2.5-§2.7): per-type
// units, set members merged by selector class, and couplings between one
// side's change and the other's. It holds only where rev 16 holds and,
// where rev 16 writes, writes the same bytes (P4).

// ConflictKind says what kind of conflict holds a put.
type ConflictKind string

const (
	// ConflictUnit: both sides changed a unit, to different values.
	ConflictUnit ConflictKind = "unit"
	// ConflictClass: both sides changed one selector class of a set member
	// (a tag or an alias, in its spellings) differently.
	ConflictClass ConflictKind = "class"
	// ConflictCoupling: one side's change fired a coupling's trigger and
	// the other side effectively changed its coupled group.
	ConflictCoupling ConflictKind = "coupling"
)

// Conflict is one reason a put holds on guarded_conflict.
type Conflict struct {
	Kind ConflictKind `json:"kind"`
	// Name is the unit's name for a unit conflict, the coupling's for a
	// coupling, and the set member's for a class conflict.
	Name string `json:"name"`
	// Trigger, for a coupling: "local" when this device's change fired it,
	// "remote" when the server's did.
	Trigger string `json:"trigger,omitempty"`
	// Local and Remote are the conflict's members each side changed: for a
	// coupling, the trigger's members on the triggering side and the
	// coupled group's on the other.
	Local  []string `json:"local"`
	Remote []string `json:"remote"`
	// A conflict names members, never values: a class conflict's raced
	// strings can be the whole of a large set member, more than once over.
	// ConflictSpellings derives them from the three versions.
}

// Coupling triggers.
const (
	TriggerLocal  = "local"
	TriggerRemote = "remote"
)

// Combined says that a write combined changes rev 16 would have held: the
// non-free members this device changed and those the server changed,
// sorted. It names members, never values.
type Combined struct {
	Local  []string
	Remote []string
}

// hostView is what a host's triggers read.
type hostView struct {
	name           string
	aliases, tags  []string
	access, output string
	hasOutput      bool
}

func viewOf(it *Item) (*hostView, bool) {
	v := &hostView{}
	for _, f := range []struct {
		m    string
		into any
	}{{"name", &v.name}, {"aliases", &v.aliases}, {"tags", &v.tags}, {"agent_access", &v.access}} {
		raw, ok := it.members[f.m]
		if !ok || json.Unmarshal(raw, f.into) != nil {
			return nil, false
		}
	}
	if v.aliases == nil || v.tags == nil {
		return nil, false // null is not a list
	}
	if raw, ok := it.members["agent_output"]; ok {
		if json.Unmarshal(raw, &v.output) != nil {
			return nil, false
		}
		v.hasOutput = true
	}
	return v, true
}

// triggerParts are the parts of X's change that fired a trigger: atomic
// members (name, or the agent unit) and, per set member, the added classes.
type triggerParts struct {
	atoms   []string
	classes map[string][]string
	spell   []string // the added spellings
}

func (p triggerParts) fired() bool { return len(p.atoms) > 0 || len(p.classes) > 0 }

// spellings groups list's distinct strings by class key.
func spellings(key func(string) string, list []string) map[string][]string {
	out := map[string][]string{}
	for _, s := range list {
		k := key(s)
		if !slices.Contains(out[k], s) {
			out[k] = append(out[k], s)
		}
	}
	for k := range out {
		slices.Sort(out[k])
	}
	return out
}

// selectorAdded fires when X, against base, adds a selector that Y does not
// have the same way: a new name, or an alias or tag class with no spelling
// in base and X's spellings in it different from Y's. A respelling within a
// class is not an addition.
func selectorAdded(x, y, base *hostView) triggerParts {
	var p triggerParts
	if model.NameKey(x.name) != model.NameKey(base.name) && x.name != y.name {
		p.atoms = []string{"name"}
	}
	for _, s := range []struct {
		member  string
		key     func(string) string
		x, y, b []string
	}{{"aliases", model.NameKey, x.aliases, y.aliases, base.aliases}, {"tags", model.TagKey, x.tags, y.tags, base.tags}} {
		xs, ys, bs := spellings(s.key, s.x), spellings(s.key, s.y), spellings(s.key, s.b)
		for k, sp := range xs {
			if _, inBase := bs[k]; inBase || slices.Equal(sp, ys[k]) {
				continue
			}
			if p.classes == nil {
				p.classes = map[string][]string{}
			}
			p.classes[s.member] = append(p.classes[s.member], k)
			p.spell = append(p.spell, sp...)
		}
		slices.Sort(p.classes[s.member])
	}
	slices.Sort(p.spell)
	return p
}

// Agent ranks: what an agent may do on a host, and how much of the output
// it gets. An absent agent_output is redacted. A value the schema doesn't
// admit ranks highest, so a change to it counts as widening.
func rankAccess(v *hostView) int {
	switch v.access {
	case "deny":
		return 0
	case "allow":
		return 1
	}
	return 2
}

func rankOutput(v *hostView) int {
	switch {
	case !v.hasOutput:
		return 1
	case v.output == model.AgentOutputNone:
		return 0
	case v.output == model.AgentOutputFull:
		return 2
	}
	return 3
}

func sameAgent(a, b *hostView) bool {
	return a.access == b.access && a.hasOutput == b.hasOutput && a.output == b.output
}

// agentWidening fires when X widens the agent unit against base (either
// member, even if the other narrows) and X's unit differs from Y's.
func agentWidening(x, y, base *hostView) triggerParts {
	widens := rankAccess(x) > rankAccess(base) || rankOutput(x) > rankOutput(base)
	if !widens || sameAgent(x, y) {
		return triggerParts{}
	}
	return triggerParts{atoms: []string{"agent_access", "agent_output"}}
}

// conflictSet is C of §2.11: the atomic members and the set classes that a
// proposal takes from one side whole.
type conflictSet struct {
	atoms   map[string]bool
	classes map[string]map[string]bool
}

func (c *conflictSet) addAtoms(ms ...string) {
	for _, m := range ms {
		c.atoms[m] = true
	}
}

func (c *conflictSet) addClasses(member string, ks ...string) {
	if c.classes[member] == nil {
		c.classes[member] = map[string]bool{}
	}
	for _, k := range ks {
		c.classes[member][k] = true
	}
}

// analysis is the rev 17 rule's working for one put.
type analysis struct {
	// fallback: the item is decided by the rev 16 rule.
	fallback bool
	// l and r are L and R; lStar and rStar the effective changes.
	l, r, lStar, rStar []string
	// merged is M: each non-header member's value (nil: absent).
	merged    map[string]canonjson.Raw
	replaced  []string
	conflicts []Conflict
	c         conflictSet
	cl        *classification
}

// rev16Holds reports whether rev16(seen, want, S) holds: L and R both hold
// a non-free member, and want and S differ on a non-free member.
func rev16Holds(t model.Type, want, s *Item, l, r []string) bool {
	nl, nr := nonFree(t, l), nonFree(t, r)
	return len(nl) > 0 && len(nr) > 0 && !sameOnGuarded(t, want, s)
}

func nonFree(t model.Type, ms []string) []string {
	var out []string
	for _, m := range ms {
		if IsGuarded(t, m) {
			out = append(out, m)
		}
	}
	return out
}

// analyze runs §2.5 steps 2-5 for a put whose item is live in S.
func analyze(t model.Type, seen, want, s *Item) analysis {
	a := analysis{merged: map[string]canonjson.Raw{}, c: conflictSet{atoms: map[string]bool{}, classes: map[string]map[string]bool{}}}
	a.cl = classifications[t]
	all := names(seen, want, s)
	for _, m := range all {
		if a.cl != nil && a.cl.kind(m) == kindSystem {
			continue // never in L or R; S's value until the writer stamps it
		}
		inL, inR := !memberEqual(want, seen, m), !memberEqual(s, seen, m)
		if inL {
			a.l = append(a.l, m)
			if !memberEqual(want, s, m) {
				a.lStar = append(a.lStar, m)
			}
		}
		if inR {
			a.r = append(a.r, m)
			if !memberEqual(s, want, m) {
				a.rStar = append(a.rStar, m)
			}
		}
		if (inL || inR) && (a.cl == nil || a.cl.kind(m) == kindUnclassified) {
			a.fallback = true
		}
	}
	if a.fallback {
		return a
	}
	var views [3]*hostView // seen, want, S
	if len(a.cl.couplings) > 0 {
		for i, it := range []*Item{seen, want, s} {
			v, ok := viewOf(it)
			if !ok {
				// A host whose selector or agent members don't parse can't be
				// classified: rev 16 decides it.
				a.fallback = true
				return a
			}
			views[i] = v
		}
	}
	for _, m := range all {
		inL, inR := slices.Contains(a.l, m), slices.Contains(a.r, m)
		switch {
		case a.cl.kind(m) == kindSystem:
			a.merged[m] = s.members[m]
		case !inL:
			a.merged[m] = s.members[m]
		case !inR:
			a.merged[m] = want.members[m]
		case memberEqual(want, s, m):
			a.merged[m] = s.members[m]
		default:
			switch a.cl.kind(m) {
			case kindFree:
				a.merged[m] = want.members[m]
				a.replaced = append(a.replaced, m)
			case kindSet:
				res, raced, ok := classMergeMember(a.cl.sets[m], seen, want, s, m)
				if !ok {
					a.fallback = true
					return a
				}
				a.merged[m] = res
				if len(raced) > 0 {
					a.c.addClasses(m, raced...)
					a.conflicts = append(a.conflicts, Conflict{Kind: ConflictClass, Name: m, Local: []string{m}, Remote: []string{m}})
				}
			default: // atomic: the unit check decides
				a.merged[m] = want.members[m]
			}
		}
	}
	for _, u := range a.cl.units {
		lu, ru := intersect(a.l, u.members), intersect(a.r, u.members)
		if len(lu) > 0 && len(ru) > 0 && len(intersect(diff(want, s), u.members)) > 0 {
			a.c.addAtoms(u.members...)
			a.conflicts = append(a.conflicts, Conflict{Kind: ConflictUnit, Name: u.name, Local: lu, Remote: ru})
		}
	}
	for _, cp := range a.cl.couplings {
		g := a.cl.unit(cp.group).members
		// This device's change fires the trigger and the server's changes
		// the group, or the other way round.
		if p := cp.trigger(views[1], views[2], views[0]); p.fired() {
			if o := intersect(a.rStar, g); len(o) > 0 {
				a.addCoupling(cp.name, TriggerLocal, p, g, p.members(), o)
			}
		}
		if p := cp.trigger(views[2], views[1], views[0]); p.fired() {
			if o := intersect(a.lStar, g); len(o) > 0 {
				a.addCoupling(cp.name, TriggerRemote, p, g, o, p.members())
			}
		}
	}
	return a
}

func (a *analysis) addCoupling(name, trigger string, p triggerParts, group, local, remote []string) {
	a.c.addAtoms(group...)
	a.c.addAtoms(p.atoms...)
	for m, ks := range p.classes {
		a.c.addClasses(m, ks...)
	}
	a.conflicts = append(a.conflicts, Conflict{
		Kind: ConflictCoupling, Name: name, Trigger: trigger, Local: local, Remote: remote,
	})
}

// members are the members a trigger's parts name, sorted.
func (p triggerParts) members() []string {
	out := slices.Clone(p.atoms)
	for m := range p.classes {
		out = append(out, m)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func intersect(a, b []string) []string {
	var out []string
	for _, m := range a {
		if slices.Contains(b, m) {
			out = append(out, m)
		}
	}
	return out
}

// stringList decodes a set member; ok is false unless it is present and a
// list of strings.
func stringList(it *Item, m string) ([]string, bool) {
	raw, ok := it.members[m]
	var out []string
	if !ok || json.Unmarshal(raw, &out) != nil || out == nil {
		return nil, false
	}
	return out, true
}

func encodeList(list []string) canonjson.Raw {
	if list == nil {
		list = []string{}
	}
	j, err := canonjson.Marshal(list)
	if err != nil {
		panic(err) // strings from canonical JSON are valid UTF-8
	}
	return j
}

func classMergeMember(key func(string) string, seen, want, s *Item, m string) (canonjson.Raw, []string, bool) {
	b, ok1 := stringList(seen, m)
	mine, ok2 := stringList(want, m)
	theirs, ok3 := stringList(s, m)
	if !ok1 || !ok2 || !ok3 {
		return nil, nil, false
	}
	res, raced := classMerge(key, b, mine, theirs)
	return encodeList(res), raced, true
}

// classMerge is §2.6: a three-way merge of a set member by class. Each
// class takes whichever side changed it, or the common change; a class both
// sides changed differently is raced and takes nothing. The result is
// deduplicated and sorted by (class key, string), as UTF-8 bytes. It runs
// only for a member both sides changed to different lists.
func classMerge(key func(string) string, base, mine, theirs []string) (result, raced []string) {
	bs, ms, ts := spellings(key, base), spellings(key, mine), spellings(key, theirs)
	classes := map[string]bool{}
	for _, x := range []map[string][]string{bs, ms, ts} {
		for k := range x {
			classes[k] = true
		}
	}
	for k := range classes {
		b, m, t := bs[k], ms[k], ts[k]
		switch {
		case slices.Equal(m, b):
			result = append(result, t...)
		case slices.Equal(t, b), slices.Equal(m, t):
			result = append(result, m...)
		default:
			raced = append(raced, k)
		}
	}
	sortByClass(key, result)
	slices.Sort(raced)
	return result, raced
}

func sortByClass(key func(string) string, list []string) {
	slices.SortFunc(list, func(a, b string) int {
		if c := strings.Compare(key(a), key(b)); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
}

// racedSpellings are the strings of the raced classes in seen, want and
// S, sorted.
func racedSpellings(key func(string) string, raced []string, seen, want, s *Item, m string) []string {
	rk := map[string]bool{}
	for _, k := range raced {
		rk[k] = true
	}
	found := map[string]bool{}
	var out []string
	for _, it := range []*Item{seen, want, s} {
		list, _ := stringList(it, m)
		for _, x := range list {
			if rk[key(x)] && !found[x] {
				found[x] = true
				out = append(out, x)
			}
		}
	}
	slices.Sort(out)
	return out
}

// ConflictSpellings are the strings a conflict of a held put of type t is
// about, derived from the held intent's seen and want and the server's
// version s, sorted: for a class conflict, the strings of the raced
// classes in all three; for a selector-added coupling fired by an added
// alias or tag class, the added spellings. Anything else has none, as has
// a conflict the three versions no longer show (nil).
func ConflictSpellings(t model.Type, seen, want, s *Item, c Conflict) []string {
	cl := classifications[t]
	if cl == nil || seen == nil || want == nil || s == nil {
		return nil
	}
	switch c.Kind {
	case ConflictClass:
		key := cl.sets[c.Name]
		if key == nil {
			return nil
		}
		b, ok1 := stringList(seen, c.Name)
		mine, ok2 := stringList(want, c.Name)
		theirs, ok3 := stringList(s, c.Name)
		if !ok1 || !ok2 || !ok3 {
			return nil
		}
		_, raced := classMerge(key, b, mine, theirs)
		if len(raced) == 0 {
			return nil
		}
		return racedSpellings(key, raced, seen, want, s, c.Name)
	case ConflictCoupling:
		if c.Name != CouplingSelectorAdded {
			return nil
		}
		views := [3]*hostView{}
		for i, it := range []*Item{seen, want, s} {
			v, ok := viewOf(it)
			if !ok {
				return nil
			}
			views[i] = v
		}
		x, y := views[1], views[2]
		if c.Trigger == TriggerRemote {
			x, y = y, x
		}
		return selectorAdded(x, y, views[0]).spell
	}
	return nil
}

// rebuildPutRev17 is §2.5 from step 2, for an item that is live in S.
func rebuildPutRev17(in Intent, s *Item) Result {
	a := analyze(in.Type, in.Seen, in.Want, s)
	if a.fallback {
		return rebuildPutRev16(in, s)
	}
	local, remote := nonFree(in.Type, a.l), nonFree(in.Type, a.r)
	if len(a.conflicts) > 0 {
		res := hold(CauseGuardedConflict)
		res.Local, res.Remote, res.Conflicts = local, remote, a.conflicts
		return res
	}
	merged, err := s.with(a.merged)
	if err != nil {
		return ruleFailure(err)
	}
	res := Result{Kind: KindWrite, Action: ActionPut, Plaintext: merged, Replaced: a.replaced}
	if rev16Holds(in.Type, in.Want, s, a.l, a.r) {
		res.Combined = &Combined{Local: local, Remote: remote}
	}
	return res
}

// proposals builds P_mine and P_theirs for a put held under §2.5 step 6
// (§2.11). ok is false when no proposal exists: the item falls back to
// rev 16, or it doesn't hold on a unit, class or coupling conflict.
func proposals(in Intent, s *Item) (mine, theirs *Item, ok bool, err error) {
	if in.Action != ActionPut || s == nil {
		return nil, nil, false, nil
	}
	a := analyze(in.Type, in.Seen, in.Want, s)
	if a.fallback || len(a.conflicts) == 0 {
		return nil, nil, false, nil
	}
	if mine, err = a.proposal(in.Want, s); err != nil {
		return nil, nil, false, err
	}
	if theirs, err = a.proposal(s, s); err != nil {
		return nil, nil, false, err
	}
	return mine, theirs, true, nil
}

// proposal is P_X, with X's values for the conflict members and the
// automatic merge's everywhere else. It keeps S's header.
func (a *analysis) proposal(x, s *Item) (*Item, error) {
	set := map[string]canonjson.Raw{}
	for m, mm := range a.merged {
		switch a.cl.kind(m) {
		case kindAtomic:
			if a.c.atoms[m] {
				set[m] = x.members[m]
				continue
			}
		case kindSet:
			if cm := a.c.classes[m]; len(cm) > 0 {
				v, err := setProposal(a.cl.sets[m], cm, mm, x, m)
				if err != nil {
					return nil, err
				}
				set[m] = v
				continue
			}
		}
		set[m] = mm
	}
	return s.with(set)
}

// setProposal is P_X[m] for a set member with conflict classes cm.
func setProposal(key func(string) string, cm map[string]bool, mm canonjson.Raw, x *Item, m string) (canonjson.Raw, error) {
	var mList []string
	if err := json.Unmarshal(mm, &mList); err != nil {
		return nil, err
	}
	xList, _ := stringList(x, m)
	t := map[string]bool{}
	for _, s := range mList {
		if !cm[key(s)] {
			t[s] = true
		}
	}
	for _, s := range xList {
		if cm[key(s)] {
			t[s] = true
		}
	}
	if sameSet(t, xList) {
		return x.members[m], nil
	}
	if sameSet(t, mList) {
		return mm, nil
	}
	var out []string
	have := map[string]bool{}
	for _, l := range []struct {
		list []string
		inC  bool
	}{{mList, false}, {xList, true}} {
		for _, s := range l.list {
			if cm[key(s)] == l.inC && !have[s] {
				have[s] = true
				out = append(out, s)
			}
		}
	}
	return encodeList(out), nil
}

func sameSet(t map[string]bool, list []string) bool {
	seen := map[string]bool{}
	for _, s := range list {
		if !t[s] {
			return false
		}
		seen[s] = true
	}
	return len(seen) == len(t)
}
