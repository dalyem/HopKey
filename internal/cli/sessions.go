package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
)

// The ssh sessions hop starts end when this device learns it was revoked
// (daemon/sessions.go): each hop process that runs ssh subscribes to its
// daemon while ssh runs, and ends its own ssh child when the daemon says
// so. Nothing else is looked for or signalled.

const (
	// watchTimeout bounds subscribing, before ssh starts.
	watchTimeout = time.Second
	// watchRetry is how often a lost or refused subscription is tried
	// again while ssh runs.
	watchRetry = 5 * time.Second
	// endTerm and endKill are when an ended ssh that still runs gets
	// SIGTERM and SIGKILL, after its SIGHUP (child.supervise).
	endTerm = 2 * time.Second
	endKill = 5 * time.Second
)

// errEndedFirst is runSSH not starting ssh: the daemon said the session is
// to end before it started (the device is revoked).
var errEndedFirst = errors.New("ssh not started: the hop daemon ends hop's ssh sessions on this device")

// sessionWatch is the subscription of this process for one ssh it runs.
type sessionWatch struct {
	// atOnce says why the session is to end before it starts; ended
	// gets why it is to end later, once.
	atOnce string
	ended  chan string
	cancel context.CancelFunc
	done   chan struct{}
}

// watchSession subscribes to the daemon for the ssh to alias this process
// is about to run. It never starts a daemon. With none running, or one
// that can't be reached, the session runs unwatched (HOP_DEBUG says so),
// and the subscription is tried again every watchRetry while it runs.
func (e *Env) watchSession(alias string) *sessionWatch {
	ctx, cancel := context.WithCancel(context.Background())
	sw := &sessionWatch{ended: make(chan string, 1), cancel: cancel, done: make(chan struct{})}
	p := daemon.WatchParams{Alias: alias, PID: os.Getpid()}
	w, why, err := e.subscribe(ctx, p)
	if why != "" {
		sw.atOnce = why
		cancel()
		close(sw.done)
		return sw
	}
	go sw.run(ctx, e, p, w, err)
	return sw
}

func (e *Env) subscribe(ctx context.Context, p daemon.WatchParams) (*daemon.Watch, string, error) {
	ctx, cancel := context.WithTimeout(ctx, watchTimeout)
	defer cancel()
	return daemon.WatchSessions(ctx, e.Paths.ControlSocket(), p)
}

// run keeps the subscription w until the daemon says the session is to
// end, or close.
func (sw *sessionWatch) run(ctx context.Context, e *Env, p daemon.WatchParams, w *daemon.Watch, err error) {
	defer close(sw.done)
	for {
		if w == nil {
			e.debugf("the ssh session to %s is not watched by the hop daemon, so a revocation would not end it: %v", p.Alias, cleanErr(err))
			for w == nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(watchRetry):
				}
				var why string
				if w, why, err = e.subscribe(ctx, p); why != "" {
					sw.ended <- why
					return
				}
			}
			e.debugf("the hop daemon watches the ssh session to %s again", p.Alias)
		}
		stop := context.AfterFunc(ctx, func() { w.Close() })
		why, werr := w.Wait()
		stop()
		w.Close()
		if why != "" {
			sw.ended <- why
			return
		}
		if ctx.Err() != nil {
			return
		}
		w, err = nil, werr
	}
}

// close ends the subscription, once ssh is done.
func (sw *sessionWatch) close() {
	sw.cancel()
	<-sw.done
}

// runSSH runs an ssh hop starts (runChild), watched by the daemon
// (watchSession). endedWhy says why the daemon ended it; then ssh was
// sent SIGHUP (it exits 255), or was not started at all (errEndedFirst).
func (e *Env) runSSH(ctx context.Context, sc *sshCmd, alias string) (endedWhy string, err error) {
	sw := e.watchSession(alias)
	defer sw.close()
	if sw.atOnce != "" {
		return sw.atOnce, errEndedFirst
	}
	return runChild(ctx, sc, sw.ended)
}

// runPipedSSH runs hop <target>'s ssh on streams that are not all files
// (runTerminalSSH): with no job control.
func (e *Env) runPipedSSH(path string, argv, environ []string, alias string) (code int, endedWhy string, err error) {
	sc := &sshCmd{path: path, args: argv, env: environ, stdin: e.Stdin, stdout: e.Stdout, stderr: e.Stderr}
	e.sshRan.Store(true)
	endedWhy, err = e.runSSH(context.Background(), sc, alias)
	var ee *sshExitError
	switch {
	case err == nil:
		return 0, endedWhy, nil
	case errors.Is(err, errEndedFirst):
		return 255, endedWhy, nil
	case errors.As(err, &ee):
		code, _ = ee.exited()
		return code, endedWhy, nil
	}
	return 0, "", err
}

// endedError is ExecResult.Error, and hop <target>'s last line, for a
// session the daemon ended.
func endedError(why string) string {
	return safef("the hop daemon ended this ssh session when %s", why)
}

// debugf writes a line to stderr when HOP_DEBUG is set.
func (e *Env) debugf(format string, args ...any) {
	if e.Getenv != nil && e.Getenv("HOP_DEBUG") != "" {
		fmt.Fprintf(e.Stderr, "hop: debug: %s\n", oneLine(safef(format, args...)))
	}
}

// endedLine describes the sessions the daemon told to end, for hop status
// and hop auth status; "" when it told none. Each is a termination request
// sent to a hop process, not an end hop saw happen.
func (e *Env) endedLine(es *daemon.EndedSessions) string {
	if es == nil || es.TerminationRequests == 0 {
		return ""
	}
	what := "termination requests sent to ssh sessions"
	if es.TerminationRequests == 1 {
		what = "termination request sent to an ssh session"
	}
	var list []string
	for i, s := range es.Sessions {
		if i == 5 {
			list = append(list, fmt.Sprintf("and %d more", len(es.Sessions)-i))
			break
		}
		var d []string
		if s.Alias != "" {
			d = append(d, s.Alias)
		}
		if s.PID > 0 {
			d = append(d, fmt.Sprintf("(hop pid %d)", s.PID))
		}
		if len(d) > 0 {
			list = append(list, strings.Join(d, " "))
		}
	}
	line := fmt.Sprintf("%d %s hop started, when %s, %s", es.TerminationRequests, what, es.Why, e.when(es.At))
	if len(list) > 0 {
		line += ": " + strings.Join(list, ", ")
	}
	return oneLine(line)
}
