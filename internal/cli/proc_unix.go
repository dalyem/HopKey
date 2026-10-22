//go:build unix

package cli

import (
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
