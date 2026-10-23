//go:build unix

package cli

import (
	"errors"
	"os/exec"
	"syscall"
)

var syscallECONNREFUSED error = syscall.ECONNREFUSED

// detach puts the daemon in its own session, so closing the terminal that
// started it does not signal it.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// execReplace replaces the current process with path.
func execReplace(path string, argv, environ []string) error {
	return syscall.Exec(path, argv, environ)
}

// processAlive reports whether a process with this pid exists (one of
// another user's counts too).
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
