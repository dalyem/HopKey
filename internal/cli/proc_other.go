//go:build !unix

package cli

import (
	"errors"
	"os"
	"os/exec"
)

var syscallECONNREFUSED = errors.New("connection refused")

func detach(cmd *exec.Cmd) {}

// execReplace cannot replace the process here, so it runs ssh as a child and
// exits with its status.
func execReplace(path string, argv, environ []string) error {
	cmd := exec.Command(path, argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = environ
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		os.Exit(0)
	case errors.As(err, &ee):
		os.Exit(ee.ExitCode())
	}
	return err
}

// processAlive can't tell here, so a marker counts until it is old
// (holdMarkerMaxAge).
func processAlive(pid int) bool { return true }
