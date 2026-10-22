//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package filelock

import (
	"errors"
	"fmt"
	"os"
)

var errUnsupported = fmt.Errorf("filelock: file locking is not implemented on this platform: %w", errors.ErrUnsupported)

// TryLock is not implemented on this platform.
func TryLock(string) (*os.File, error) { return nil, errUnsupported }

// Lock is not implemented on this platform.
func Lock(string) (*os.File, error) { return nil, errUnsupported }
