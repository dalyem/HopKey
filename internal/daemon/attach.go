package daemon

import (
	"context"
	"time"
)

// AttachTimeout bounds hop session attach. ssh waits for its LocalCommand
// before the session starts, so a daemon that is slow to answer costs a
// session at most this long, and then it is not registered.
const AttachTimeout = 300 * time.Millisecond

// Attach is hop session attach: it tells the daemon at controlSocket that
// this process's parent, the ssh that runs it as its LocalCommand, is a
// session through hop's config for alias (sessions.go). It waits for the
// answer, so that this process is still the ssh's child while the daemon
// looks, and never starts a daemon.
func Attach(controlSocket, alias string) error {
	ctx, cancel := context.WithTimeout(context.Background(), AttachTimeout)
	defer cancel()
	c, err := Dial(ctx, controlSocket)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Call(ctx, OpSessionAttach, AttachParams{Alias: alias}, nil)
}
