package merge

import (
	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// frozenRev16Put is internal/merge/merge.go's rebuildPut and sameOnGuarded
// exactly as rev 16 shipped them (commit 9d43456), renamed. It is the
// oracle for property P4 (crypto spec rev 17 amendment, §4.1, §8.2): it
// must never change, so that a change to the production rev 16 fallback
// can't hide a change to what rev 17 refines.
func frozenRev16Put(in Intent, s *Item) Result {
	var local, remote []string // guarded members in L and in R
	var replaced []string      // free members in L and R that differ
	inL := map[string]bool{}
	for _, m := range names(in.Want, in.Seen, s) {
		l := !memberEqual(in.Want, in.Seen, m)
		r := !memberEqual(s, in.Seen, m)
		inL[m] = l
		if frozenIsFree(in.Type, m) && l && r && !memberEqual(in.Want, s, m) {
			replaced = append(replaced, m)
		}
		if frozenIsGuarded(in.Type, m) {
			if l {
				local = append(local, m)
			}
			if r {
				remote = append(remote, m)
			}
		}
	}
	if len(local) > 0 && len(remote) > 0 && !frozenSameOnGuarded(in.Type, in.Want, s) {
		res := hold(CauseGuardedConflict)
		res.Local, res.Remote = local, remote
		return res
	}
	// want's value for each member in L, S's value for every other member.
	// A free member in both L and R is in L, so it takes want's value.
	set := map[string]canonjson.Raw{}
	for m, l := range inL {
		src := s
		if l {
			src = in.Want
		}
		set[m] = src.members[m] // nil removes an absent member
	}
	merged, err := s.with(set)
	if err != nil {
		return ruleFailure(err)
	}
	return Result{Kind: KindWrite, Action: ActionPut, Plaintext: merged, Replaced: replaced}
}
func frozenSameOnGuarded(t model.Type, a, b *Item) bool {
	for _, m := range diff(a, b) {
		if frozenIsGuarded(t, m) {
			return false
		}
	}
	return true
}

// The rev 16 free members: a host's or a snippet's description.
func frozenIsFree(t model.Type, member string) bool {
	switch t {
	case model.TypeHost, model.TypeSnippet:
		return member == "description"
	}
	return false
}

func frozenIsGuarded(t model.Type, member string) bool {
	return !isHeader(member) && !frozenIsFree(t, member)
}
