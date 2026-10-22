//go:build !unix

package cli

import (
	"fmt"
	"os"
)

// openLog opens the daemon log for appending, refusing a symlink. There is no
// owner or mode to check here; the directory's ACL decides who can read it.
func openLog(path string, uid int) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("the daemon log %s is not a regular file", oneLine(path))
		}
		if fi.Size() > maxLogSize {
			if err := os.Rename(path, path+".1"); err != nil {
				return nil, err
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
}
