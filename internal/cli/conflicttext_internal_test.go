package cli

import (
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/merge"
)

// Every conflict kind gets a line that says what it is.
func TestConflictText(t *testing.T) {
	for _, tc := range []struct {
		c         merge.Conflict
		spellings []string
		want      string
	}{
		{merge.Conflict{Kind: merge.ConflictUnit, Name: merge.UnitConnection, Local: []string{"host_keys"}, Remote: []string{"addresses"}},
			nil, "connection: both changed how it connects (addresses, port, user, route, Tailscale link, pinned keys, jump host, key, credential), differently (here host_keys; on the server addresses)"},
		{merge.Conflict{Kind: merge.ConflictUnit, Name: merge.UnitAgent, Local: []string{"agent_access"}, Remote: []string{"agent_output"}},
			nil, "agent: both changed what agents may do on it (agent access and agent output), differently (here agent_access; on the server agent_output)"},
		{merge.Conflict{Kind: merge.ConflictClass, Name: "tags", Local: []string{"tags"}, Remote: []string{"tags"}},
			[]string{"Prod", "prod"}, `tags: the same tag was changed differently on each side (["Prod","prod"])`},
		{merge.Conflict{Kind: merge.ConflictCoupling, Name: merge.CouplingAgentWidening, Trigger: merge.TriggerRemote,
			Local: []string{"user"}, Remote: []string{"agent_access", "agent_output"}},
			nil, "coupling agent-widening: the server widened what agents may do on it (agent_access, agent_output) while this device changed how it connects (user)"},
		{merge.Conflict{Kind: merge.ConflictUnit, Name: merge.UnitExecutable, Local: []string{"name"}, Remote: []string{"command"}},
			nil, "executable: both changed its name or command"},
	} {
		if got := conflictText(tc.c, tc.spellings); !strings.HasPrefix(got, tc.want) {
			t.Errorf("conflictText = %q\nwant prefix %q", got, tc.want)
		}
	}
}
