package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
)

// A daemon that exits at once (no vault, say) ends the autostart wait
// there: the command fails within moments, not after DaemonWait, and
// shows what this start logged, not lines an earlier run left.
func TestAutostartStopsWaitingWhenTheDaemonExits(t *testing.T) {
	base := shortTemp(t)
	fake := filepath.Join(base, "fake-hop")
	script := "#!/bin/sh\necho 'hop: opening the vault: there is no vault on this device; run hop init' >&2\nexit 255\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	paths := daemon.Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg"), StateDir: filepath.Join(base, "state")}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.LogFile(), []byte("2026-01-01T00:00:00Z a line from an earlier start\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var so, se bytes.Buffer
	env := &cli.Env{
		Stdout: &so, Stderr: &se, Getenv: func(string) string { return "" },
		Home: filepath.Join(base, "home"), DataDir: filepath.Join(base, "data"), Paths: paths,
		Executable: fake, Environ: os.Environ(),
	}
	start := time.Now()
	code := cli.Run(context.Background(), []string{"ls"}, env)
	took := time.Since(start)
	if code == 0 {
		t.Fatalf("hop ls with a daemon that exits: exit 0")
	}
	if took > 5*time.Second {
		t.Errorf("hop ls waited %v for a daemon that had exited", took)
	}
	msg := se.String()
	if !strings.Contains(msg, "there is no vault on this device") {
		t.Errorf("the error does not give the daemon's reason:\n%s", msg)
	}
	if strings.Contains(msg, "earlier start") {
		t.Errorf("the error shows a log line from an earlier start:\n%s", msg)
	}
	if strings.Contains(msg, "did not come up within") {
		t.Errorf("the error reports a timeout for a daemon that exited:\n%s", msg)
	}
}
