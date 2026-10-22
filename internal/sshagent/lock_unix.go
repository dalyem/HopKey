//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package sshagent

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive, non-blocking flock on path, creating the file
// if needed. The lock lives as long as the returned file stays open, and the
// kernel drops it if the process dies, so it can never go stale. A lock that
// is already held yields ErrInUse.
func lockFile(path string) (*os.File, error) {
	// O_NOFOLLOW: the directory is private, but do not trust that blindly.
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("sshagent: open lock file: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrInUse
		}
		return nil, fmt.Errorf("sshagent: lock %s: %w", path, err)
	}
	return f, nil
}
