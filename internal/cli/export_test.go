package cli

// SetLogoutCleanupHook sets testHookLogoutCleanup until the returned
// function runs.
func SetLogoutCleanupHook(f func()) (restore func()) {
	testHookLogoutCleanup = f
	return func() { testHookLogoutCleanup = nil }
}
