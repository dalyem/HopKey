package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/procs"
)

// The ssh processes hop starts are registered with the daemon, which ends
// them when this device learns it was revoked (daemon/sessions.go).

// sessionCallTimeout bounds one registration: it is best effort, and never
// holds up the session.
const sessionCallTimeout = 2 * time.Second

// trackSession registers process pid, an ssh hop started (or hop itself,
// about to become ssh), for alias, and returns what unregisters it, which
// says why the daemon ended the session if it did. With no daemon
// running, or one that refuses, nothing is registered.
func (e *Env) trackSession(ctx context.Context, pid int, alias, via string) (done func() (endedWhy string)) {
	none := func() string { return "" }
	p, err := procs.Lookup(pid)
	if err != nil {
		return none
	}
	params := daemon.SessionParams{PID: pid, Start: p.Start, Alias: alias, Via: via}
	if e.sessionCall(ctx, daemon.OpSessionStart, params, nil) != nil {
		return none
	}
	return func() string {
		var res daemon.SessionEndResult
		e.sessionCall(context.WithoutCancel(ctx), daemon.OpSessionEnd, params, &res)
		return res.Ended
	}
}

// sessionCall makes one session call to a daemon that is already running.
func (e *Env) sessionCall(ctx context.Context, op string, params daemon.SessionParams, result any) error {
	ctx, cancel := context.WithTimeout(ctx, sessionCallTimeout)
	defer cancel()
	c, err := dialExisting(ctx, e)
	if err != nil {
		return err
	}
	if c == nil {
		return errNoDaemon
	}
	defer c.Close()
	return c.Call(ctx, op, params, result)
}

var errNoDaemon = errors.New("no hop daemon is running")

// runSSH runs cmd, an ssh to alias, registered with the daemon while it
// runs (trackSession). It is cmd.Run, and says why the daemon ended the
// session if it did.
func (e *Env) runSSH(ctx context.Context, cmd *exec.Cmd, alias, via string) (endedWhy string, err error) {
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := e.trackSession(ctx, cmd.Process.Pid, alias, via)
	err = cmd.Wait()
	return done(), err
}

// endedError is ExecResult.Error for a session the daemon ended.
func endedError(why string) string {
	return safef("the hop daemon ended this ssh session when %s", why)
}

// trackSelf registers this process, which is about to exec ssh to alias
// (hop <target>): the PID and the start time stay through exec. It is
// unregistered only if the exec fails; the daemon forgets it once it ends.
func (e *Env) trackSelf(ctx context.Context, alias string) (undo func() string) {
	return e.trackSession(ctx, os.Getpid(), alias, "hop")
}

// endedLine describes the sessions the daemon ended, for hop status and
// hop auth status; "" when it ended none.
func (e *Env) endedLine(es *daemon.EndedSessions) string {
	if es == nil || es.Count == 0 {
		return ""
	}
	what := "ssh sessions"
	if es.Count == 1 {
		what = "ssh session"
	}
	var list []string
	for i, s := range es.Sessions {
		if i == 5 {
			list = append(list, fmt.Sprintf("and %d more", len(es.Sessions)-i))
			break
		}
		d := fmt.Sprintf("pid %d", s.PID)
		if s.Alias != "" {
			d += " " + s.Alias
		}
		list = append(list, d+" ("+s.Via+")")
	}
	return oneLine(fmt.Sprintf("ended %d %s when %s, %s: %s", es.Count, what, es.Why, e.when(es.At), strings.Join(list, ", ")))
}
