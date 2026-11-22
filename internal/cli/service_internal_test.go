package cli

import (
	"errors"
	"testing"
)

type fakeExit int

func (c fakeExit) Error() string { return "exit status" }
func (c fakeExit) ExitCode() int { return int(c) }

// Only launchd's not-loaded exit statuses count, never its text alone,
// and only systemd's complete absence phrases for hopkey.service.
func TestServiceNotLoadedClassifiers(t *testing.T) {
	for _, c := range []struct {
		name string
		out  string
		err  error
		want bool
	}{
		{"exit 3, no text", "", fakeExit(3), true},
		{"exit 113, no text", "", fakeExit(113), true},
		{"misleading text, exit 1", "Boot-out failed: No such process", fakeExit(1), false},
		{"misleading text, exit 5", "Could not find specified service", fakeExit(5), false},
		{"no exit status", "No such process", errors.New("boom"), false},
	} {
		if got := launchdNotLoaded([]byte(c.out), c.err); got != c.want {
			t.Errorf("launchd %s: %v, want %v", c.name, got, c.want)
		}
	}
	for _, c := range []struct {
		name string
		out  string
		want bool
	}{
		{"disable, file gone", "Failed to disable unit: Unit file hopkey.service does not exist.", true},
		{"stop, not loaded", "Failed to stop hopkey.service: Unit hopkey.service not loaded.", true},
		{"restart, not found", "Failed to restart hopkey.service: Unit hopkey.service not found.", true},
		{"another unit", "Failed to stop other.service: Unit other.service not loaded.", false},
		{"bus not found", "Failed to connect to bus: No medium found; not found", false},
		{"generic does not exist", "Failed to disable unit: Access denied; does not exist", false},
	} {
		if got := systemdNotLoaded([]byte(c.out), fakeExit(5)); got != c.want {
			t.Errorf("systemd %s: %v, want %v", c.name, got, c.want)
		}
	}
}
