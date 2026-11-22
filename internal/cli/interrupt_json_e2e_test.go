package cli_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/cli"
)

// A --json command that Ctrl-C ends where it can't return says so in JSON
// on stderr, as one that returns does.
func TestInterruptedJSONCommandSaysSoInJSON(t *testing.T) {
	m := newMachine(t, &authWorld{}, "kc")
	ictx, interrupt := context.WithCancelCause(context.Background())
	exited := make(chan int, 1)
	release := make(chan struct{})
	s := &session{tty: true, ctx: ictx}
	s.exit = func(code int) { exited <- code }
	s.onSecret = func(string) (string, bool) {
		interrupt(cli.ErrInterrupted) // Ctrl-C, while the prompt waits
		<-release
		return "", true
	}
	done := make(chan int, 1)
	go func() { done <- m.hop(t, s, "init", "--json") }()
	t.Cleanup(func() { close(release); <-done })
	select {
	case code := <-exited:
		if code != cli.ExitInterrupted {
			t.Errorf("exit %d, want %d", code, cli.ExitInterrupted)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no exit after the interrupt")
	}
	out := strings.TrimSpace(s.stderr.String())
	last := out[strings.LastIndex(out, "\n")+1:]
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(last), &e); err != nil || e.Error != "interrupted" {
		t.Errorf("stderr does not end in a JSON error: %q (%v)", out, err)
	}
}
