//go:build unix

package cli

import (
	"fmt"
	"os"
	"syscall"
)

// openLog opens the daemon log for appending. The log is where the daemon's
// stderr goes, so it must be a file only uid can read and write, and it must
// be the file at path, not whatever a symlink there points to:
//
//   - a symlink at path is refused (O_NOFOLLOW, and an lstat first so a named
//     pipe or device is never opened);
//   - a file that already exists must be a regular file owned by uid;
//   - one with a mode other than 0600 is tightened to it.
//
// A log that grew past maxLogSize is set to 0600 and moved to path+".1"
// first, keeping one previous generation.
func openLog(path string, uid int) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("the daemon log %s is a symlink; remove it", path)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("the daemon log %s is not a regular file", path)
		}
		if fi.Size() > maxLogSize {
			// Tighten the mode first: the previous generation keeps whatever
			// mode the file has when it is renamed.
			if err := tighten(path); err != nil {
				return nil, err
			}
			if err := os.Rename(path, path+".1"); err != nil {
				return nil, err
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the daemon log: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		err = fmt.Errorf("the daemon log %s is not a regular file", path)
	case !ok:
		err = fmt.Errorf("cannot tell who owns the daemon log %s", path)
	case int(st.Uid) != uid:
		err = fmt.Errorf("the daemon log %s belongs to uid %d, not %d", path, st.Uid, uid)
	case fi.Mode().Perm() != 0o600:
		err = f.Chmod(0o600)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// tighten sets the mode of the regular file at path to 0600, without following
// a symlink put there since the caller looked.
func tighten(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("opening the daemon log: %w", err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("the daemon log %s is not a regular file", path)
	}
	return f.Chmod(0o600)
}
