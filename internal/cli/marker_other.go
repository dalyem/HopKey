//go:build !unix

package cli

import (
	"errors"
	"os"
)

// openMarker opens the control marker at path for reading, refusing
// anything but a regular file. There is no owner or mode to check here; the
// directory's ACL decides who can write it.
func openMarker(path string) (*os.File, os.FileInfo, error) {
	if fi, err := os.Lstat(path); err != nil {
		return nil, nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, nil, errors.New("it is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = errors.New("it is not a regular file")
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// privateDirMode has no mode to check here.
func privateDirMode(os.FileInfo) error { return nil }
