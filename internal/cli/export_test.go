package cli

import (
	"context"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/termpanel"
)

// SessionShortcuts is the session panel's lookup, sessionShortcuts.
func SessionShortcuts(ctx context.Context, e *Env, rr *daemon.ResolveResult) ([]termpanel.Shortcut, error) {
	return e.sessionShortcuts(ctx, rr)
}

// ShortcutHotkey is shortcutHotkey.
func ShortcutHotkey(e *Env) (key byte, on bool, err error) { return e.shortcutHotkey() }

// SetLogoutCleanupHook sets testHookLogoutCleanup until the returned
// function runs.
func SetLogoutCleanupHook(f func()) (restore func()) {
	testHookLogoutCleanup = f
	return func() { testHookLogoutCleanup = nil }
}

// SetRedactHook sets testHookRedact until the returned function runs.
func SetRedactHook(f func(texts [][]byte)) (restore func()) {
	testHookRedact = f
	return func() { testHookRedact = nil }
}

// MCPCutRoom is what hop mcp's cut to the output limit leaves free.
const MCPCutRoom = cutRoom

// LockAgain is lockAgain, for a command whose output is not JSON.
func LockAgain(ctx context.Context, e *Env) { lockAgain(ctx, e, false) }
