package cli

import (
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model"
)

// SetAccessTestHook has f called at the points of a hop access run
// (before-session, before-record, before-check-read) until the test
// ends. f must be safe for concurrent runs.
func SetAccessTestHook(t testing.TB, f func(point string, a *model.Access)) {
	old := accessTestHook
	accessTestHook = f
	t.Cleanup(func() { accessTestHook = old })
}

// SetAccessSessionTimeout bounds each locked session of hop access by d
// until the test ends.
func SetAccessSessionTimeout(t testing.TB, d time.Duration) {
	old := accessSessionTimeout
	accessSessionTimeout = d
	t.Cleanup(func() { accessSessionTimeout = old })
}

// SetAccessDeadlines sets the client's deadline from a session's header
// to the end of its payload, and how long a session the client gave up on
// may take to end, until the test ends.
func SetAccessDeadlines(t testing.TB, decision, grace time.Duration) {
	oldD, oldG := accessDecisionDeadline, accessAbortGrace
	accessDecisionDeadline, accessAbortGrace = decision, grace
	t.Cleanup(func() { accessDecisionDeadline, accessAbortGrace = oldD, oldG })
}
