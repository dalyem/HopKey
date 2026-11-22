// Package filelock takes advisory locks on files, exclusive or shared, used to say "a
// process owns this directory" (sshagent) or "a process is rewriting this
// directory" (sshconfig).
//
// The lock lives as long as the returned file stays open, and the kernel
// drops it if the process dies, so it can never go stale. The lock file is
// never meant to be deleted: removing a lock file while another process
// opens it is a race.
package filelock

import "errors"

// ErrLocked means TryLock found the lock held by someone else.
var ErrLocked = errors.New("filelock: file is locked")
