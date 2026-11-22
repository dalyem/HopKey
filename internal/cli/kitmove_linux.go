package cli

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames oldpath to newpath only if newpath does not
// exist, atomically: renameat2 with RENAME_NOREPLACE. Kernels before 3.15
// (ENOSYS) and filesystems without the flag (EINVAL) report
// errNoReplaceUnsupported.
func renameNoReplace(oldpath, newpath string) error {
	err := unix.Renameat2(unix.AT_FDCWD, oldpath, unix.AT_FDCWD, newpath, unix.RENAME_NOREPLACE)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL), errors.Is(err, unix.EOPNOTSUPP):
		return errNoReplaceUnsupported
	}
	return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
}

// linkUnsupported reports whether a link error means the filesystem cannot
// make hard links. Linux reports EPERM for that (FAT, for one).
func linkUnsupported(err error) bool {
	return errors.Is(err, errors.ErrUnsupported) || errors.Is(err, unix.EPERM)
}
