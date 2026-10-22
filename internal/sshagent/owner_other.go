//go:build !unix

package sshagent

import "os"

// Windows has no uid; the named-pipe ACL work will replace this.
func ownedByCurrentUser(os.FileInfo) bool { return true }
