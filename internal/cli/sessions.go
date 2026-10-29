package cli

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/procs"
)

// The ssh sessions that use hop's ssh config register themselves with the
// daemon (daemon/sessions.go), which ends them when this device learns it
// was revoked.

// SessionAttach is hop session attach --control SOCKET ALIAS, the
// LocalCommand of each host in hop's ssh config. ssh runs it, and waits
// for it, once it has logged in. It says nothing and always succeeds, so
// it can't break or hold up the session past daemon.AttachTimeout; with no
// daemon running, or one that refuses, the session is simply not
// registered. It never starts a daemon.
func SessionAttach(args []string) {
	var sock, alias string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--control" && i+1 < len(args):
			i++
			sock = args[i]
		case alias == "" && !strings.HasPrefix(args[i], "-"):
			alias = args[i]
		}
	}
	if sock != "" {
		daemon.Attach(sock, alias)
	}
}

// runSession is hop session attach through Run (SessionAttach).
func runSession(_ context.Context, _ *Env, args []string) error {
	if len(args) > 0 && args[0] == "attach" {
		SessionAttach(args[1:])
	}
	return nil
}

// sessionQueryTimeout bounds asking the daemon whether it ended a session.
const sessionQueryTimeout = 2 * time.Second

// runSSH is cmd.Run for an ssh through hop's config, which registers
// itself with the daemon (SessionAttach). When ssh fails, it asks the
// daemon whether it ended the session, and why.
func (e *Env) runSSH(ctx context.Context, cmd *exec.Cmd) (endedWhy string, err error) {
	if err := cmd.Start(); err != nil {
		return "", err
	}
	start := startedAt(cmd.Process.Pid)
	if err = cmd.Wait(); err != nil {
		endedWhy = e.endedWhy(ctx, cmd.Process.Pid, start)
	}
	return endedWhy, err
}

// startedAt is pid's start time, for endedWhy, or "" when it can't be
// read.
func startedAt(pid int) string {
	p, err := procs.Lookup(pid)
	if err != nil {
		return ""
	}
	return p.Start
}

// endedWhy asks a daemon already running whether it ended ssh process pid,
// which started at start, and why; "" when it did not, or can't say.
func (e *Env) endedWhy(ctx context.Context, pid int, start string) string {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionQueryTimeout)
	defer cancel()
	c, err := dialExisting(ctx, e)
	if err != nil || c == nil {
		return ""
	}
	defer c.Close()
	var res daemon.SessionEndedResult
	if c.Call(ctx, daemon.OpSessionEnded, daemon.SessionEndedParams{PID: pid, Start: start}, &res) != nil {
		return ""
	}
	return res.Ended
}

// endedError is ExecResult.Error for a session the daemon ended.
func endedError(why string) string {
	return safef("the hop daemon ended this ssh session when %s", why)
}

// endedLine describes the sessions the daemon ended, for hop status and
// hop auth status; "" when it ended none and left none running.
func (e *Env) endedLine(es *daemon.EndedSessions) string {
	if es == nil || (es.Count == 0 && es.NotEnded == 0) {
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
		list = append(list, d)
	}
	line := fmt.Sprintf("ended %d %s when %s, %s", es.Count, what, es.Why, e.when(es.At))
	if len(list) > 0 {
		line += ": " + strings.Join(list, ", ")
	}
	if es.NotEnded > 0 {
		line += fmt.Sprintf("; %d not ended: no pidfd held them, so they were not signalled", es.NotEnded)
	}
	return oneLine(line)
}
