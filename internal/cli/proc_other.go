//go:build !unix

package cli

import (
	"errors"
	"os/exec"
)

var syscallECONNREFUSED = errors.New("connection refused")

func detach(cmd *exec.Cmd) {}

// processAlive can't tell here, so a marker counts until it is old
// (holdMarkerMaxAge).
func processAlive(pid int) bool { return true }
