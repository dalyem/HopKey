package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/store"
)

// A fork whose backup was missing at its end says so, and never that the
// old vault was deleted, on the terminal or in --json (A3c review 3, P2).
func TestForkDoneReportsAMissingBackup(t *testing.T) {
	r := &store.ForkResult{BackupMissing: true}
	r.DataDir, r.Backup = "/d/data", "/d/data.forked-20261030-0123abcd"
	var out strings.Builder
	printForkDone(&out, r)
	if s := out.String(); strings.Contains(s, "was deleted") || !strings.Contains(s, "is missing from /d/data.forked-20261030-0123abcd") ||
		!strings.Contains(s, "could not verify that it deleted it") {
		t.Errorf("the report: %q", s)
	}
	b, err := json.Marshal(ForkReport{ForkResult: *r})
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); !strings.Contains(s, `"backup_missing":true`) || strings.Contains(s, `"discarded"`) {
		t.Errorf("--json: %s", s)
	}
}
