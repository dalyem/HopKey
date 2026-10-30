// Package access holds the rules of the access item and hop access (crypto
// spec rev 17, Part 2): the writer's validation V_access, the managed line
// and tombstone grammar, and the planners' decisions. Nothing here reads a
// file, a clock or the network.
package access

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Path is the write path a V_access check is for (§5.1 rule 7).
type Path int

const (
	// PathWrite: a planner's put, or an automatic rebase of a queued one.
	// It may set a same_machine attestation in a move to removing.
	PathWrite Path = iota
	// PathResolve: keep mine, edit, retry and both --merge choices. They
	// never create, change or clear an attestation.
	PathResolve
)

// ErrRefused is wrapped by every *Refusal.
var ErrRefused = errors.New("access: refused by V_access")

// Refusal is a write V_access refuses. Host and FP name the target, when
// the rule is about one.
type Refusal struct {
	Rule string
	Host model.ID
	FP   string
	Msg  string
}

func (r *Refusal) Error() string { return r.Msg }

func (r *Refusal) Is(target error) bool { return target == ErrRefused }

// Rules of V_access, as a Refusal names them.
const (
	RuleLog         = "log"         // rule 1: a log rule
	RuleTerminal    = "terminal"    // rule 2: a removed or abandoned target changes
	RuleTransition  = "transition"  // rule 3: not a row of the §7.1 table
	RuleDelete      = "delete"      // rule 5
	RuleAttestation = "attestation" // rule 7
	RuleNothing     = "nothing"     // rule 6: no substantive change
)

func refuse(rule string, t *model.AccessTarget, format string, args ...any) error {
	r := &Refusal{Rule: rule, Msg: fmt.Sprintf(format, args...)}
	if t != nil {
		r.Host, r.FP = t.HostItemID, t.ServerKeyFP
	}
	return r
}

// Check is V_access(S, next) for a put (§5.1): s is the item in current
// verified state (nil for a create) and next the plaintext about to be
// journaled, with by already stamped. A put that isn't substantive is
// refused with RuleNothing; callers that drop such a put instead test
// Substantive first.
func Check(s, next *model.Access, path Path) error {
	if s == nil {
		return checkCreate(next)
	}
	if err := vaultlog.CheckAccessIdentity(s, next); err != nil {
		var re *vaultlog.RuleError
		if errors.As(err, &re) && re.Rule == vaultlog.RuleAccessTerminal {
			t := terminalChanged(s, next)
			return refuse(RuleTerminal, t, "target on host %v (bound to %s) is %s in the vault now; a removed or abandoned target never changes. Run hop access check instead", t.HostItemID, t.ServerKeyFP, t.State)
		}
		return refuse(RuleLog, nil, "%v", err)
	}
	for i := range next.Targets {
		n := &next.Targets[i]
		o := vaultlog.AccessTargetOf(s, n.HostItemID, n.ServerKeyFP)
		var err error
		if o == nil {
			err = checkNewTarget(s, next, n)
		} else {
			err = checkTransition(o, n, path)
		}
		if err != nil {
			return err
		}
	}
	if !Substantive(s, next) {
		return refuse(RuleNothing, nil, "nothing to record")
	}
	return nil
}

func terminalChanged(s, next *model.Access) *model.AccessTarget {
	for i := range s.Targets {
		t := &s.Targets[i]
		if n := vaultlog.AccessTargetOf(next, t.HostItemID, t.ServerKeyFP); model.AccessTerminal(t.State) && (n == nil || !same(t, n)) {
			return t
		}
	}
	return &model.AccessTarget{}
}

func checkCreate(next *model.Access) error {
	for i := range next.Targets {
		t := &next.Targets[i]
		if t.State != model.AccessPending || t.Gen != 1 || t.SameMachine != nil || t.Error != "" {
			return refuse(RuleTransition, t, "a new record's targets start pending with gen 1; host %v is %s with gen %d", t.HostItemID, t.State, t.Gen)
		}
	}
	return nil
}

// checkNewTarget: a target absent from S starts pending with gen 1 and no
// attestation, or, in a migrate, takes the intent of the old target of the
// same host that the same put abandons.
func checkNewTarget(s, next *model.Access, n *model.AccessTarget) error {
	if n.Gen != 1 || n.SameMachine != nil || n.Error != "" {
		return refuse(RuleTransition, n, "a new target on host %v starts with gen 1 and no attestation", n.HostItemID)
	}
	switch n.State {
	case model.AccessPending:
		return nil
	case model.AccessRemoving:
		for i := range s.Targets {
			o := &s.Targets[i]
			if o.HostItemID != n.HostItemID || o.State != model.AccessRemoving {
				continue
			}
			if x := vaultlog.AccessTargetOf(next, o.HostItemID, o.ServerKeyFP); x != nil && x.State == model.AccessAbandoned {
				return nil
			}
		}
	}
	return refuse(RuleTransition, n, "a new target on host %v can't start %s", n.HostItemID, n.State)
}

// checkTransition is rules 2, 3 and 7 for a target present in S (o) and
// in next (n).
func checkTransition(o, n *model.AccessTarget, path Path) error {
	if model.AccessTerminal(o.State) {
		if !same(o, n) {
			return refuse(RuleTerminal, o, "target on host %v (bound to %s) is %s in the vault now; a removed or abandoned target never changes. Run hop access check instead", o.HostItemID, o.ServerKeyFP, o.State)
		}
		return nil
	}
	if o.State == n.State && o.Gen == n.Gen {
		// Unchanged, or the result of a removal that didn't end removed.
		if same(o, n) {
			return nil
		}
		if o.State == model.AccessRemoving && o.Alongside == n.Alongside && sameAttestation(o, n) {
			return nil
		}
		return refuse(RuleTransition, o, "target on host %v changes without a change of state", o.HostItemID)
	}
	bad := func() error {
		return refuse(RuleTransition, o, "target on host %v (bound to %s) is %s with gen %d in the vault now; your change would make it %s with gen %d. Run hop access check instead",
			o.HostItemID, o.ServerKeyFP, o.State, o.Gen, n.State, n.Gen)
	}
	if n.Alongside != o.Alongside && n.State != model.AccessPending {
		return bad()
	}
	attest := !sameAttestation(o, n)
	switch {
	case n.State == model.AccessPending:
		// A retry of a failed target, or a repair of an installed one.
		if (o.State != model.AccessFailed && o.State != model.AccessInstalled) || n.Gen != o.Gen+1 || n.Error != "" || attest {
			return bad()
		}
	case n.State == model.AccessInstalled || n.State == model.AccessFailed:
		// The result of an add that acted under this gen.
		if o.State != model.AccessPending || n.Gen != o.Gen || attest {
			return bad()
		}
	case n.State == model.AccessRemoving:
		// Before a removal: from pending, installed or failed; or, to set
		// an attestation for gen + 1, from removing.
		if n.Gen != o.Gen+1 || n.Error != "" || (o.State == model.AccessRemoving && !attest) {
			return bad()
		}
		if attest {
			if path != PathWrite || n.SameMachine == nil || n.SameMachine.Gen != n.Gen {
				return refuse(RuleAttestation, o, "the shared-host statement for host %v can't be carried over by a resolution; take theirs, then re-run hop access rm LABEL HOST --same-machine", o.HostItemID)
			}
		}
	case n.State == model.AccessRemoved:
		if o.State != model.AccessRemoving || n.Gen != o.Gen || n.Error != "" || attest {
			return bad()
		}
	case n.State == model.AccessAbandoned:
		if n.Gen != o.Gen+1 || attest {
			return bad()
		}
	default:
		return bad()
	}
	if attest && path != PathWrite {
		return refuse(RuleAttestation, o, "the shared-host statement for host %v can't be carried over by a resolution; take theirs, then re-run hop access rm LABEL HOST --same-machine", o.HostItemID)
	}
	return nil
}

// CheckDelete is V_access rule 5: every target terminal, and, unless the
// delete is forget's, every target removed.
func CheckDelete(s *model.Access, forget bool) error {
	for i := range s.Targets {
		t := &s.Targets[i]
		if !model.AccessTerminal(t.State) {
			return refuse(RuleDelete, t, "record %s still has a %s target on host %v; finish or abandon it first", s.Label, t.State, t.HostItemID)
		}
		if !forget && t.State != model.AccessRemoved {
			return refuse(RuleDelete, t, "record %s has an abandoned target on host %v; hop access forget %s deletes the record", s.Label, t.HostItemID, s.Label)
		}
	}
	return nil
}

// CheckAttestationUnchanged refuses next if any target's same_machine
// differs from S's (§5.0, rule 7 for resolutions).
func CheckAttestationUnchanged(s, next *model.Access) error {
	for i := range next.Targets {
		n := &next.Targets[i]
		var sm *model.SameMachine
		if o := vaultlog.AccessTargetOf(s, n.HostItemID, n.ServerKeyFP); o != nil {
			sm = o.SameMachine
		}
		if !jsonEqual(sm, n.SameMachine) {
			return refuse(RuleAttestation, n, "the shared-host statement for host %v can't be carried over by a resolution; take theirs, then re-run hop access rm LABEL HOST --same-machine", n.HostItemID)
		}
	}
	return nil
}

// Substantive reports whether next changes some non-header member of s
// other than by (§5.1 rule 6).
func Substantive(s, next *model.Access) bool {
	x, y := *s, *next
	x.Header, y.Header = model.Header{}, model.Header{}
	x.By, y.By = model.ID{}, model.ID{}
	return !jsonEqual(x, y)
}

func same(a, b *model.AccessTarget) bool { return jsonEqual(*a, *b) }

func sameAttestation(a, b *model.AccessTarget) bool { return jsonEqual(a.SameMachine, b.SameMachine) }

func jsonEqual(a, b any) bool {
	x, err1 := canonjson.Marshal(a)
	y, err2 := canonjson.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// Result is what a planner run observed for one target it acted on: the
// record it acted for (its item ID and record ID, fixed when the command
// started; a label can name another record later), the state the target
// was in and its gen when the run acted, and the state and error to
// record.
type Result struct {
	ItemID   model.ID
	RecordID model.ID
	Host     model.ID
	FP       string
	From     string // pending or removing
	Gen      uint64
	State    string
	Error    string
}

// Same reports whether a is the record r was observed for.
func (r Result) Same(a *model.Access) bool {
	return a != nil && a.ItemID == r.ItemID && a.RecordID == r.RecordID
}

// ApplyResults builds a result put from s, the newest verified state
// (§7.1): each result is recorded only if s is the record it was observed
// for and its target is still in From with Gen; a target that moved on
// belongs to the newer operation, and its result is dropped (§5.1 rule 4).
// It returns the put and the results it kept. The put's by is not
// stamped.
func ApplyResults(s *model.Access, rs []Result, now model.Timestamp) (*model.Access, []Result) {
	next := Clone(s)
	var kept []Result
	for _, r := range rs {
		if !r.Same(s) {
			continue
		}
		t := vaultlog.AccessTargetOf(next, r.Host, r.FP)
		if t == nil || t.State != r.From || t.Gen != r.Gen {
			continue
		}
		t.State, t.Error, t.Time = r.State, r.Error, now
		kept = append(kept, r)
	}
	return next, kept
}

// Clone returns a deep copy of a.
func Clone(a *model.Access) *model.Access {
	c := *a
	c.Options.From = append([]string(nil), a.Options.From...)
	c.Targets = make([]model.AccessTarget, len(a.Targets))
	for i, t := range a.Targets {
		if t.SameMachine != nil {
			sm := *t.SameMachine
			sm.HostItemIDs = append([]model.ID(nil), t.SameMachine.HostItemIDs...)
			t.SameMachine = &sm
		}
		c.Targets[i] = t
	}
	return &c
}

// sortTargets sorts targets as §5.1 requires: by (host_item_id,
// server_key_fp), as bytes.
func sortTargets(ts []model.AccessTarget) {
	slices.SortFunc(ts, func(a, b model.AccessTarget) int {
		if c := bytes.Compare(a.HostItemID[:], b.HostItemID[:]); c != 0 {
			return c
		}
		return strings.Compare(a.ServerKeyFP, b.ServerKeyFP)
	})
}
