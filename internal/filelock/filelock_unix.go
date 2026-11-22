//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package filelock

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// TryLock takes an exclusive flock on path without waiting, creating the file
// (0600) if needed. A lock that is already held yields ErrLocked. Close the
// returned file to release the lock.
func TryLock(path string) (*os.File, error) { return lock(path, unix.LOCK_EX|unix.LOCK_NB) }

// Lock is TryLock that waits until the lock is free. Two Lock calls conflict
// even inside one process, because each opens its own file description.
func Lock(path string) (*os.File, error) { return lock(path, unix.LOCK_EX) }

// TryLockShared takes a shared lock without waiting: any number of shared
// holders coexist, and an exclusive holder excludes them (ErrLocked).
func TryLockShared(path string) (*os.File, error) { return lock(path, unix.LOCK_SH|unix.LOCK_NB) }

func lock(path string, how int) (*os.File, error) {
	// O_NOFOLLOW: the directory is private, but do not trust that blindly.
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("filelock: open %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	for {
		err = unix.Flock(fd, how)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("filelock: lock %s: %w", path, err)
	}
	return f, nil
}
