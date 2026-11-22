//go:build unix

package cli

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openMarker opens the control marker at path for reading: the file itself,
// never what a symlink there points to (O_NOFOLLOW), and only a regular file
// that this user owns and that group and others cannot write, as the opened
// file says (fstat), so nothing swapped in after a look is read. A marker
// that is not there is os.ErrNotExist.
func openMarker(path string) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err == nil {
		st, ok := fi.Sys().(*syscall.Stat_t)
		switch {
		case !fi.Mode().IsRegular():
			err = errors.New("it is not a regular file")
		case !ok:
			err = errors.New("hop cannot tell who owns it")
		case int(st.Uid) != os.Geteuid():
			err = fmt.Errorf("it belongs to uid %d, not %d", st.Uid, os.Geteuid())
		case fi.Mode().Perm()&0o022 != 0:
			err = fmt.Errorf("group or others can write it (mode %o)", fi.Mode().Perm())
		}
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// privateDirMode fails for a directory that group or others can write.
func privateDirMode(fi os.FileInfo) error {
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("group or others can write it (mode %o)", fi.Mode().Perm())
	}
	return nil
}
