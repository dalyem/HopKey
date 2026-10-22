//go:build !unix

package safepath

// checkPrivateDir has nothing to check here: there is no uid, and the mode
// bits do not describe who can enter a directory. The named-pipe and ACL work
// for Windows will replace this.
func checkPrivateDir(string) error { return nil }
