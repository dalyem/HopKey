package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dalyem/hopkey/internal/procs"
	"github.com/dalyem/hopkey/internal/sshconfig"
)

// Ending the ssh sessions that use hop's ssh config (README, What
// revocation does).
//
// Sessions register themselves; nothing is guessed. hop's ssh config gives
// each of its hosts
//
//	PermitLocalCommand yes
//	LocalCommand exec '<hop>' session attach --control '<control socket>' <alias>
//
// (sshconfig.SessionCommand). ssh runs a LocalCommand once it has logged
// in, and waits for it, so hop session attach runs as the child of the
// very ssh that took hop's block for the host. It sends session.attach,
// and the daemon takes the session from what the kernel says, never from
// what the caller says: the caller's PID from the socket (procs.PeerPID),
// its parent from the process table, and that parent must be run by this
// user, not be the daemon, and run an ssh binary (sshBinaries) by the path
// the kernel recorded at exec. That parent is registered, held by a
// procs.Pin. An ssh that did not take hop's LocalCommand for the host
// (the user's own config, an earlier block that sets PermitLocalCommand
// no or a LocalCommand of its own, -F with another file) never runs it,
// so it is never registered, and never ended. Nor is anything else: the
// daemon does not look through the processes. scp and sftp to a hop alias
// run ssh, which runs the LocalCommand, so they register too; ssh -G
// connects to nothing and runs nothing.
//
// When this device learns that it was revoked (a session the server
// refused, the server's report, a proven revocation, at start too), when
// the max-offline policy locks it, and on hop lock --end-sessions, the
// daemon ends every registered session still running: SIGHUP, then
// SIGTERM after sessionTerm and SIGKILL after sessionKill if it still
// runs. On Linux each signal goes through the session's pidfd, so it
// can't reach a process that took the PID; one that can't be pinned is
// not signalled at all, and status counts it (EndedSessions.NotEnded). On
// macOS each signal follows a fresh check of the start time and program
// (procs.Pin). A plain hop lock and a daemon stop end nothing.

// Session ops. session.attach is hop session attach; session.ended asks
// whether the daemon ended a session, by its PID.
const (
	OpSessionAttach = "session.attach"
	OpSessionEnded  = "session.ended"
)

// AttachParams is the request for OpSessionAttach. Alias is the hop host
// the config block was for, as a name for status; the session itself is
// the caller's parent, which the daemon reads from the kernel.
type AttachParams struct {
	Alias string `json:"alias,omitempty"`
}

// SessionEndedParams asks whether the daemon ended ssh process PID, which
// started at Start (procs.Proc.Start; "" matches any).
type SessionEndedParams struct {
	PID   int    `json:"pid"`
	Start string `json:"start,omitempty"`
}

// SessionEndedResult answers OpSessionEnded. Ended, when the daemon ended
// that session, says why, as EndedSessions.Why does. It is answered once.
type SessionEndedResult struct {
	Ended string `json:"ended,omitempty"`
}

// EndedSessions is what the daemon ended, for status: the sessions ended
// for the last reason that ended any.
type EndedSessions struct {
	Count    int            `json:"count"`
	Why      string         `json:"why"` // follows "when": "this device was revoked"
	At       time.Time      `json:"at"`
	Sessions []EndedSession `json:"sessions"`
	// NotEnded counts the registered sessions that could not be ended
	// safely: no pidfd held them (Linux), so they were not signalled.
	NotEnded int `json:"not_ended,omitempty"`
}

// EndedSession is one ssh process the daemon ended. It names no command
// line: only the PID and the hop alias it registered for.
type EndedSession struct {
	PID   int    `json:"pid"`
	Alias string `json:"alias,omitempty"`
	// Killed means it outlasted SIGHUP and SIGTERM, and SIGKILL ended it.
	Killed bool `json:"killed,omitempty"`
}

// Why the sessions end (EndedSessions.Why).
const (
	whyRevoked = "this device was revoked"
	whyRefused = "the server refused this device a session"
	whyOffline = "the max-offline policy locked the vault"
	whyLock    = "hop lock --end-sessions ran"
)

const (
	sessionTerm = 2 * time.Second // SIGTERM after SIGHUP
	sessionKill = 5 * time.Second // and SIGKILL
	// maxSessions bounds the registered sessions.
	maxSessions = 4096
)

// pin is a process held for signalling (procs.Pin).
type pin interface {
	Signal(sig syscall.Signal) error
	Exited() bool
	Close()
}

// procTable is this machine's processes (procs). Tests replace it.
type procTable interface {
	Lookup(pid int) (procs.Proc, error)
	// Open pins pid and reads it; procs.ErrNoPin means it can't be
	// pinned, and must not be signalled.
	Open(pid int) (procs.Proc, pin, error)
}

type sysProcs struct{}

func (sysProcs) Lookup(pid int) (procs.Proc, error) { return procs.Lookup(pid) }

func (sysProcs) Open(pid int) (procs.Proc, pin, error) {
	p, err := procs.Open(pid)
	if err != nil {
		return procs.Proc{}, nil, err
	}
	return p.Proc, p, nil
}

// session is one registered ssh process. pin is nil when it could not be
// pinned at registration; it is tried again when the session is ended.
type session struct {
	proc  procs.Proc
	alias string
	pin   pin
}

type sessionKey struct {
	pid   int
	start string
}

// sessions is the daemon's record of ssh sessions: the registered ones,
// the ones being ended, and the last that were. In memory only.
type sessions struct {
	mu     sync.Mutex
	reg    map[int]*session
	ending map[sessionKey]bool // while a run ends them
	ended  *EndedSessions
	// why says why each session the daemon ended was ended, for
	// session.ended.
	why    map[sessionKey]string
	closed bool
}

func newSessions() *sessions {
	return &sessions{reg: map[int]*session{}, ending: map[sessionKey]bool{}, why: map[sessionKey]string{}}
}

// dispatchSessions handles session.ended. handled is false for any other
// op. session.attach is answered by attachResponse, which has the caller's
// connection; it never comes here from a connection.
func (d *Daemon) dispatchSessions(req Request, decode func(any) error) (result any, handled bool, err error) {
	switch req.Op {
	case OpSessionAttach:
		return nil, true, invalidf("%s is answered on the control socket only", req.Op)
	case OpSessionEnded:
	default:
		return nil, false, nil
	}
	var p SessionEndedParams
	if err := decode(&p); err != nil {
		return nil, true, err
	}
	s := d.sessions
	s.mu.Lock()
	defer s.mu.Unlock()
	res := &SessionEndedResult{}
	for k, why := range s.why {
		if k.pid == p.PID && (p.Start == "" || k.start == p.Start) {
			res.Ended = why
			delete(s.why, k)
			break
		}
	}
	return res, true, nil
}

// attachResponse answers session.attach on connection c (attachSession).
func (d *Daemon) attachResponse(c *net.UnixConn, req Request) Response {
	var p AttachParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errorResponse(invalidf("bad params for %s: %v", req.Op, err))
		}
	}
	if err := d.attachSession(c, p.Alias); err != nil {
		d.logf("ssh session not registered: %v", err)
		return errorResponse(err)
	}
	return Response{OK: true}
}

// attachSession registers the ssh session of the process that connected
// c: its parent, once the kernel shows that it is an ssh of this user
// (see the top of this file). One registered on a device already revoked
// is ended at once: it started as the others were ended.
func (d *Daemon) attachSession(c *net.UnixConn, alias string) error {
	peer, err := procs.PeerPID(c)
	if err != nil {
		return invalidf("session.attach: the caller's PID can't be read: %v", err)
	}
	uid, self := os.Getuid(), os.Getpid()
	if peer == self {
		return invalidf("session.attach: the caller is the daemon")
	}
	caller, err := d.procs.Lookup(peer)
	if err != nil || !caller.OwnedBy(uid) || caller.Exited {
		return invalidf("session.attach: the caller, process %d, is not a running process of this user", peer)
	}
	ppid := caller.PPID
	switch {
	case ppid <= 1:
		return invalidf("session.attach: the caller, process %d, has no parent", peer)
	case ppid == self:
		return invalidf("session.attach: the caller's parent is the daemon")
	}
	parent, pn, err := d.procs.Open(ppid)
	if errors.Is(err, procs.ErrNoPin) {
		d.logf("ssh session pid %d: %v; registered, but it can't be ended safely", ppid, err)
		parent, err = d.procs.Lookup(ppid)
	}
	if err != nil {
		return invalidf("session.attach: the caller's parent, process %d, is gone", ppid)
	}
	keep := false
	defer func() {
		if !keep && pn != nil {
			pn.Close()
		}
	}()
	switch {
	case !parent.OwnedBy(uid) || parent.Exited:
		return invalidf("session.attach: the caller's parent, process %d, is not a running process of this user", ppid)
	case !isSSH(parent.Exe):
		return invalidf("session.attach: the caller's parent, process %d, runs %q, not ssh", ppid, parent.Exe)
	}
	// What was pinned is the caller's parent, and not a process that took
	// its PID since: the caller, still waiting for this answer, has it
	// as its parent still.
	if again, err := d.procs.Lookup(peer); err != nil || again.Start != caller.Start || again.PPID != ppid {
		return invalidf("session.attach: the caller's parent changed")
	}
	if !sshconfig.ValidAlias(alias) {
		alias = ""
	}
	if err := d.sessions.add(d, &session{proc: parent, alias: alias, pin: pn}); err != nil {
		return err
	}
	keep = true
	if d.sync != nil && d.sync.revokedPhase() {
		d.endSessions(whyRevoked)
	}
	return nil
}

// add registers se, after dropping the sessions that have ended. A
// session already registered stays as it was.
func (s *sessions) add(d *Daemon, se *session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return invalidf("the daemon is stopping")
	}
	for pid, r := range s.reg {
		if d.sessionGone(r) {
			r.close()
			delete(s.reg, pid)
		}
	}
	if r, ok := s.reg[se.proc.PID]; ok {
		if r.proc.Start == se.proc.Start {
			se.close() // registered already: a ProxyJump's or a second attach
			return nil
		}
		r.close()
		delete(s.reg, se.proc.PID)
	}
	if len(s.reg) >= maxSessions {
		return invalidf("%d ssh sessions are registered already", maxSessions)
	}
	s.reg[se.proc.PID] = se
	return nil
}

func (se *session) close() {
	if se.pin != nil {
		se.pin.Close()
	}
}

// sessionGone reports whether se's process has exited, or its PID is
// another process's now.
func (d *Daemon) sessionGone(se *session) bool {
	if se.pin != nil {
		return se.pin.Exited()
	}
	q, err := d.procs.Lookup(se.proc.PID)
	return err != nil || !se.proc.Same(q)
}

// closeAll lets every registered process go, as the daemon stops.
func (s *sessions) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for pid, r := range s.reg {
		r.close()
		delete(s.reg, pid)
	}
}

// sshBinaries are the ssh programs a session may run: ssh on the daemon's
// PATH and in the usual places, links resolved. A program elsewhere, or
// another program named ssh, is not ssh.
func sshBinaries() map[string]bool {
	cands := []string{"/usr/bin/ssh", "/bin/ssh", "/usr/local/bin/ssh", "/opt/homebrew/bin/ssh", "/run/current-system/sw/bin/ssh"}
	if p, err := exec.LookPath("ssh"); err == nil {
		cands = append(cands, p)
	}
	if home, err := os.UserHomeDir(); err == nil {
		cands = append(cands, filepath.Join(home, ".nix-profile", "bin", "ssh"))
	}
	out := map[string]bool{}
	for _, c := range cands {
		if !filepath.IsAbs(c) {
			continue
		}
		if r, err := filepath.EvalSymlinks(c); err == nil {
			out[r] = true
		}
	}
	return out
}

// isSSH reports whether exe, a program path the kernel recorded, is one
// of sshBinaries.
func isSSH(exe string) bool {
	if !filepath.IsAbs(exe) {
		return false
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return sshBinaries()[exe]
}

// revokedPhase reports whether sync stopped for good on a revocation.
func (e *syncer) revokedPhase() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.phase == SyncRevoked
}

// noteEnded adds ended, and the notEnded that could not be, to what
// status shows: the sessions ended for why, after any ended earlier for
// the same reason.
func (s *sessions) noteEnded(why string, ended []EndedSession, notEnded int) {
	if len(ended) == 0 && notEnded == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended == nil || s.ended.Why != why {
		s.ended = &EndedSessions{Why: why}
	}
	s.ended.At = time.Now()
	s.ended.Sessions = append(s.ended.Sessions, ended...)
	s.ended.Count = len(s.ended.Sessions)
	s.ended.NotEnded += notEnded
}

// noteKilled marks the last session status shows for pid as killed.
func (s *sessions) noteKilled(pid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended == nil {
		return
	}
	for i := len(s.ended.Sessions) - 1; i >= 0; i-- {
		if s.ended.Sessions[i].PID == pid {
			s.ended.Sessions[i].Killed = true
			return
		}
	}
}

// endedSessions is what status shows of the sessions ended, or nil.
func (d *Daemon) endedSessions() *EndedSessions {
	s := d.sessions
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended == nil {
		return nil
	}
	e := *s.ended
	e.Sessions = slices.Clone(e.Sessions)
	return &e
}

// sessionTarget is one process to end, and the pin that reaches it.
type sessionTarget struct {
	se  *session
	pin pin
}

// endSessions ends the registered ssh sessions, for why, in the
// background. The channel gets what was ended once that is done. The
// caller may hold d.mu.
func (d *Daemon) endSessions(why string) <-chan []EndedSession {
	s := d.sessions
	s.mu.Lock()
	reg := make([]*session, 0, len(s.reg))
	for _, r := range s.reg {
		reg = append(reg, r)
	}
	s.mu.Unlock()
	done := make(chan []EndedSession, 1)
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		done <- d.endNow(why, reg)
	}()
	return done
}

// endNow ends the sessions in reg (endSessions).
func (d *Daemon) endNow(why string, reg []*session) []EndedSession {
	s := d.sessions
	var targets []sessionTarget
	var opened []pin // pins this run made, closed at its end
	notEnded := 0
	s.mu.Lock()
	for _, se := range reg {
		k := sessionKey{se.proc.PID, se.proc.Start}
		if s.ending[k] {
			continue // another run is ending it
		}
		s.ending[k] = true
		targets = append(targets, sessionTarget{se: se, pin: se.pin})
	}
	s.mu.Unlock()
	live := make([]sessionTarget, 0, len(targets))
	for _, t := range targets {
		if t.pin == nil {
			// Not pinned at registration: pin it now, if it is still the
			// process that registered.
			p, pn, err := d.procs.Open(t.se.proc.PID)
			switch {
			case errors.Is(err, procs.ErrNoPin):
				notEnded++
				d.logf("ssh session pid %d not ended: %v; it is not signalled without one", t.se.proc.PID, err)
				continue
			case err != nil:
				continue
			case !t.se.proc.Same(p):
				pn.Close()
				continue
			}
			opened = append(opened, pn)
			t.pin = pn
		}
		if !t.pin.Exited() {
			live = append(live, t)
		}
	}
	slices.SortFunc(live, func(a, b sessionTarget) int { return a.se.proc.PID - b.se.proc.PID })

	ended := d.signalSessions(live, why, notEnded)

	for _, pn := range opened {
		pn.Close()
	}
	s.mu.Lock()
	for _, t := range targets {
		k := sessionKey{t.se.proc.PID, t.se.proc.Start}
		delete(s.ending, k)
		if r, ok := s.reg[k.pid]; ok && r == t.se && d.sessionGone(r) {
			r.close()
			delete(s.reg, k.pid)
		}
	}
	s.mu.Unlock()
	if len(ended) > 0 {
		d.logf("ended %s when %s: %s", plural(len(ended), "ssh session"), why, describeEnded(ended))
	}
	return ended
}

// signalSessions sends each target SIGHUP, then SIGTERM to those still
// running after sessionTerm and SIGKILL after sessionKill. It returns the
// ones it signalled: a process gone by the first signal is not counted.
// session.ended learns why, so why is noted before the signal that ends
// it.
func (d *Daemon) signalSessions(targets []sessionTarget, why string, notEnded int) []EndedSession {
	s := d.sessions
	note := func(t sessionTarget, on bool) {
		k := sessionKey{t.se.proc.PID, t.se.proc.Start}
		s.mu.Lock()
		defer s.mu.Unlock()
		if !on {
			delete(s.why, k)
			return
		}
		if len(s.why) >= maxSessions {
			clear(s.why) // session.ended calls that never came
		}
		s.why[k] = why
	}
	term, kill := d.opts.sessionTerm, d.opts.sessionKill
	if term <= 0 {
		term = sessionTerm
	}
	if kill <= 0 {
		kill = sessionKill
	}
	var ended []EndedSession
	running := map[int]int{} // index in targets to index in ended
	for i, t := range targets {
		note(t, true)
		if err := t.pin.Signal(syscall.SIGHUP); err != nil {
			note(t, false)
			if !errors.Is(err, procs.ErrGone) {
				d.logf("ending ssh session pid %d: %v", t.se.proc.PID, err)
			}
			continue
		}
		running[i] = len(ended)
		ended = append(ended, EndedSession{PID: t.se.proc.PID, Alias: t.se.alias})
	}
	// Status says so at once, not after the waits.
	s.noteEnded(why, ended, notEnded)
	start := time.Now()
	sent := syscall.SIGHUP
	for len(running) > 0 {
		time.Sleep(50 * time.Millisecond)
		for i := range running {
			if targets[i].pin.Exited() {
				delete(running, i)
			}
		}
		next := syscall.Signal(0)
		switch since := time.Since(start); {
		case len(running) == 0:
		case sent == syscall.SIGHUP && since >= term:
			next = syscall.SIGTERM
		case sent == syscall.SIGTERM && since >= kill:
			next = syscall.SIGKILL
		case sent == syscall.SIGKILL && since >= kill+time.Second:
			for i := range running {
				d.logf("ssh session pid %d still runs after SIGKILL", targets[i].se.proc.PID)
			}
			return ended
		}
		if next == 0 {
			continue
		}
		sent = next
		for i, j := range running {
			if err := targets[i].pin.Signal(next); errors.Is(err, procs.ErrGone) {
				delete(running, i)
			} else if next == syscall.SIGKILL {
				ended[j].Killed = true
				s.noteKilled(ended[j].PID)
			}
		}
	}
	return ended
}

// describeEnded lists sessions for the log: PID and alias; never a
// command line.
func describeEnded(ended []EndedSession) string {
	parts := make([]string, 0, len(ended))
	for _, e := range ended {
		s := fmt.Sprintf("pid %d", e.PID)
		if e.Alias != "" {
			s += " " + e.Alias
		}
		if e.Killed {
			s += " (killed)"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}
