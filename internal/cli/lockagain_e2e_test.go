package cli_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
)

// A daemon too old to say which vault it serves can't be checked: hop
// says the lock state is not verified, and what to run.
func TestLockAgainWarnsAboutADaemonThatDoesNotSayItsVault(t *testing.T) {
	f := newFakeDaemon(t)
	f.ops[daemon.OpStatus] = func(json.RawMessage) (any, error) {
		return map[string]any{"vault": map[string]any{"locked": false}}, nil
	}
	var stderr strings.Builder
	cli.LockAgain(context.Background(), f.env(t, strings.NewReader(""), &strings.Builder{}, &stderr))
	if !strings.Contains(stderr.String(), "hop: warning:") || !strings.Contains(stderr.String(), "hop lock") {
		t.Errorf("stderr: %q", stderr.String())
	}
}
