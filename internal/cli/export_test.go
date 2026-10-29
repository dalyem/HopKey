package cli

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
