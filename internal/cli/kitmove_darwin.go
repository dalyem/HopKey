package cli

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames oldpath to newpath only if newpath does not
// exist, atomically: renamex_np with RENAME_EXCL. A filesystem without it
// reports errNoReplaceUnsupported.
func renameNoReplace(oldpath, newpath string) error {
	err := unix.RenamexNp(oldpath, newpath, unix.RENAME_EXCL)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errors.ErrUnsupported), errors.Is(err, unix.EINVAL):
		return errNoReplaceUnsupported
	}
	return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
}

// linkUnsupported reports whether a link error means the filesystem cannot
// make hard links.
func linkUnsupported(err error) bool {
	return errors.Is(err, errors.ErrUnsupported) || errors.Is(err, unix.EPERM)
}
