//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package sshagent

import (
	"errors"
	"os"
)

func lockFile(string) (*os.File, error) {
	return nil, errors.New("sshagent: socket locking is not implemented on this platform")
}
