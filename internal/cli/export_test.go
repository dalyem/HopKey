package cli

import "context"

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
