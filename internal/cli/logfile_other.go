//go:build !unix

package cli

import (
	"fmt"
	"os"
)

// openLog opens the daemon log for appending: see openPrivateLog.
func openLog(path string, uid int) (*os.File, error) {
	return openPrivateLog(path, "the daemon log", uid, maxLogSize)
}

// openPrivateLog opens a log for appending, refusing a symlink, and moves
// one that grew past rotateAt (zero: never) to path+".1" first. There is no
// owner or mode to check here; the directory's ACL decides who can read it.
func openPrivateLog(path, what string, uid int, rotateAt int64) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%s %s is not a regular file", what, oneLine(path))
		}
		if rotateAt > 0 && fi.Size() > rotateAt {
			if err := os.Rename(path, path+".1"); err != nil {
				return nil, err
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
}
