//go:build !unix

package cli

import "context"

// runTerminalSSH runs hop <target>'s ssh as a child on this process's
// streams, watched by the daemon (watchSession), and returns its exit
// status.
func (e *Env) runTerminalSSH(_ context.Context, path string, argv, environ []string, alias string) (code int, endedWhy string, err error) {
	return e.runPipedSSH(path, argv, environ, alias)
}
