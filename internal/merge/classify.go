package merge

import (
	"slices"

	"github.com/dalyem/hopkey/internal/model"
)

// The classification of every item type's members for the merge rule
// (crypto spec rev 17, §5.4, §2.3 of the amendment). It is kept here and
// nowhere else. Every non-header member has exactly one kind:
//
//   - atomic: compared whole, and in exactly one unit;
//   - set: a list of strings, merged three-way by selector class;
//   - free: merges on its own, and the rebasing side's value wins.
//
// A member the type's classification doesn't list is unclassified, and a
// change to one makes the whole item fall back to the rev 16 rule.

type memberKind int

const (
	kindUnclassified memberKind = iota
	kindAtomic
	kindSet
	kindFree
)

// Unit names, as a conflict reports them.
const (
	UnitConnection = "connection"
	UnitName       = "name"
	UnitAgent      = "agent"
	UnitExecutable = "executable"
	UnitKey        = "key"
	UnitCredential = "credential"
	UnitPolicy     = "policy"
)

// Coupling names, as a conflict reports them.
const (
	// CouplingSelectorAdded: a new name, or a new alias or tag class, on
	// one side while the other changed how the host connects.
	CouplingSelectorAdded = "selector-added"
	// CouplingAgentWidening: agent permissions widened on one side while
	// the other changed how the host connects.
	CouplingAgentWidening = "agent-widening"
)

type unit struct {
	name    string
	members []string
}

// coupling: a change on one side that fires trigger must not combine with
// an effective change to a member of the unit group on the other side.
type coupling struct {
	name    string
	trigger func(x, y, base *hostView) triggerParts
	group   string
}

type classification struct {
	units     []unit
	sets      map[string]func(string) string // set member -> class key
	free      []string
	couplings []coupling
}

var classifications = map[model.Type]*classification{
	model.TypeHost: {
		units: []unit{
			{UnitConnection, []string{"addresses", "port", "user", "route", "tailscale", "host_keys", "jump_host_id", "key_id", "credential_id"}},
			{UnitName, []string{"name"}},
			{UnitAgent, []string{"agent_access", "agent_output"}},
		},
		sets: map[string]func(string) string{"aliases": model.NameKey, "tags": model.TagKey},
		free: []string{"description"},
		couplings: []coupling{
			{CouplingSelectorAdded, selectorAdded, UnitConnection},
			{CouplingAgentWidening, agentWidening, UnitConnection},
		},
	},
	model.TypeSnippet: {
		units: []unit{{UnitExecutable, []string{"name", "command", "params"}}},
		free:  []string{"description"},
	},
	model.TypeKey: {
		units: []unit{{UnitKey, []string{"name", "key_type", "private_key", "public_key", "dedicated_grant"}}},
	},
	model.TypeCredential: {
		units: []unit{{UnitCredential, []string{"name", "username", "password"}}},
	},
	model.TypePolicy: {
		units: []unit{{UnitPolicy, []string{"max_offline"}}},
	},
}

func (c *classification) kind(member string) memberKind {
	switch {
	case slices.Contains(c.free, member):
		return kindFree
	case c.sets[member] != nil:
		return kindSet
	}
	for _, u := range c.units {
		if slices.Contains(u.members, member) {
			return kindAtomic
		}
	}
	return kindUnclassified
}

func (c *classification) unit(name string) unit {
	for _, u := range c.units {
		if u.name == name {
			return u
		}
	}
	return unit{}
}

// ConflictMembers is every member of a conflict on an item of type t, for
// showing it whole (§2.11): for a unit conflict, every member of the unit;
// for a class conflict, its set member; for a coupling, every member of
// the coupled group and the members of its trigger. Whatever either side
// changed in it is included too. Sorted.
func ConflictMembers(t model.Type, c Conflict) []string {
	cl := classifications[t]
	out := slices.Concat(c.Local, c.Remote)
	switch c.Kind {
	case ConflictUnit:
		if cl != nil {
			out = append(out, cl.unit(c.Name).members...)
		}
	case ConflictClass:
		out = append(out, c.Name)
	case ConflictCoupling:
		if cl != nil {
			for _, cp := range cl.couplings {
				if cp.name == c.Name {
					out = append(out, cl.unit(cp.group).members...)
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
