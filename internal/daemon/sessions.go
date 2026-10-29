package daemon

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/dalyem/hopkey/internal/procs"
)

// Ending the ssh sessions hop is responsible for (README, What revocation
// does).
//
// When this device learns that it was revoked (a session the server
// refused, the server's report, a proven revocation, at start too), when
// the max-offline policy locks it, and on hop lock --end-sessions, the
// daemon ends:
//
//   - every ssh that hop itself started: hop <target>, hop exec, hop
//     check, hop mcp and hop key rotate register each one, by PID and
//     start time, with session.start, and say session.end when it ends.
//     The list is in memory only.
//   - plain ssh sessions of this user that use hop: a process running ssh
//     whose environment's SSH_AUTH_SOCK is hop's agent (Linux only, where
//     /proc shows it), or whose destination is a Host alias of hop's ssh
//     config and that reads that config: with -F, or, with no -F, when it
//     is ~/.ssh/hop/config, which hop setup includes from ~/.ssh/config.
//     The aliases are read before a revocation empties the config. On
//     macOS ps finds them by alias only. This is best effort: a session
//     through a copied key or another config is not hop's, and is not
//     found.
//
// Nothing of another user is touched, nor any process that is not ssh
// (one hop registered aside). Each gets SIGHUP, then SIGTERM after
// sessionTerm and SIGKILL after sessionKill if it still runs. Before each
// signal the PID must still have the start time it was found with
// (procs.Signal), so a reused PID is never signalled. A plain hop lock and
// a daemon stop end nothing.

// Session ops.
const (
	OpSessionStart = "session.start"
	OpSessionEnd   = "session.end"
)

// SessionParams is the request for OpSessionStart and OpSessionEnd: one ssh
// process hop started. Start is its start time as procs reads it
// (procs.Proc.Start); the daemon checks it against the process.
type SessionParams struct {
	PID   int    `json:"pid"`
	Start string `json:"start"`
	Alias string `json:"alias,omitempty"` // the Host alias it connects to
	Via   string `json:"via,omitempty"`   // the hop command: "hop exec", "hop mcp"...
}

// SessionEndResult answers OpSessionEnd. Ended, when the daemon ended the
// session itself, says why, as EndedSessions.Why does.
type SessionEndResult struct {
	Ended string `json:"ended,omitempty"`
}

// EndedSessions is what the daemon ended, for status: the sessions ended
// for the last reason that ended any.
type EndedSessions struct {
	Count    int            `json:"count"`
	Why      string         `json:"why"` // follows "when": "this device was revoked"
	At       time.Time      `json:"at"`
	Sessions []EndedSession `json:"sessions"`
}

// EndedSession is one ssh process the daemon ended. It names no command
// line: only the PID, the alias and how it was started.
type EndedSession struct {
	PID   int    `json:"pid"`
	Alias string `json:"alias,omitempty"`
	// Via is the hop command that started it, or "ssh" for a plain ssh
	// found running.
	Via string `json:"via"`
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
	// maxConfigRead bounds how much of the ssh config is read for its
	// aliases.
	maxConfigRead = 16 << 20
)

// procTable is this machine's processes (procs). Tests replace it.
type procTable interface {
	Lookup(pid int) (procs.Proc, error)
	List(uid int) ([]procs.Proc, error)
	Signal(p procs.Proc, sig syscall.Signal) error
}

type sysProcs struct{}

func (sysProcs) Lookup(pid int) (procs.Proc, error)            { return procs.Lookup(pid) }
func (sysProcs) List(uid int) ([]procs.Proc, error)            { return procs.List(uid) }
func (sysProcs) Signal(p procs.Proc, sig syscall.Signal) error { return procs.Signal(p, sig) }

// sessions is the daemon's record of ssh sessions: the ones hop
// registered, the ones being ended, and the last that were.
type sessions struct {
	mu     sync.Mutex
	reg    map[int]SessionParams
	ending map[int]string // PID to start time, while a run ends it
	ended  *EndedSessions
	// why says why each registered session the daemon ended was ended,
	// for its session.end.
	why map[SessionParams]string
}

func newSessions() *sessions {
	return &sessions{reg: map[int]SessionParams{}, ending: map[int]string{}, why: map[SessionParams]string{}}
}

// dispatchSessions handles the session ops. handled is false for any
// other op.
func (d *Daemon) dispatchSessions(req Request, decode func(any) error) (result any, handled bool, err error) {
	switch req.Op {
	case OpSessionStart, OpSessionEnd:
	default:
		return nil, false, nil
	}
	var p SessionParams
	if err := decode(&p); err != nil {
		return nil, true, err
	}
	if req.Op == OpSessionEnd {
		s := d.sessions
		s.mu.Lock()
		defer s.mu.Unlock()
		if r, ok := s.reg[p.PID]; ok && r.Start == p.Start {
			delete(s.reg, p.PID)
		}
		key := SessionParams{PID: p.PID, Start: p.Start}
		why := s.why[key]
		delete(s.why, key)
		return &SessionEndResult{Ended: why}, true, nil
	}
	return nil, true, d.startSession(p)
}

// startSession registers one ssh process hop started, once it is sure
// the process is this user's and has that start time. One registered on
// a device already revoked is ended at once: it started as the others
// were ended.
func (d *Daemon) startSession(p SessionParams) error {
	if p.PID <= 1 || p.Start == "" {
		return invalidf("a session needs a PID and its start time")
	}
	pr, err := d.procs.Lookup(p.PID)
	if err != nil || pr.Start != p.Start || !pr.OwnedBy(os.Getuid()) || pr.Exited {
		return invalidf("no process %d of this user started then", p.PID)
	}
	p.Alias, p.Via = clip(p.Alias, 64), clip(p.Via, 32)
	s := d.sessions
	s.mu.Lock()
	if len(s.reg) >= maxSessions {
		for pid, r := range s.reg {
			if q, err := d.procs.Lookup(pid); err != nil || q.Start != r.Start || q.Exited {
				delete(s.reg, pid)
			}
		}
	}
	full := len(s.reg) >= maxSessions
	if !full {
		s.reg[p.PID] = p
	}
	s.mu.Unlock()
	if full {
		return invalidf("%d ssh sessions are registered already", maxSessions)
	}
	if d.sync != nil && d.sync.revokedPhase() {
		d.endSessions(whyRevoked)
	}
	return nil
}

// revokedPhase reports whether sync stopped for good on a revocation.
func (e *syncer) revokedPhase() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.phase == SyncRevoked
}

// noteEnded adds ended to what status shows: the sessions ended for why,
// after any ended earlier for the same reason.
func (s *sessions) noteEnded(why string, ended []EndedSession) {
	if len(ended) == 0 {
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

// sessionTarget is one process to end.
type sessionTarget struct {
	p          procs.Proc
	alias, via string
}

// endSessions ends the ssh sessions hop is responsible for, for why, in
// the background: what to look for (the registered sessions, hop's
// aliases) is read now, before the caller empties the ssh config. The
// channel gets what was ended once that is done. The caller may hold
// d.mu.
func (d *Daemon) endSessions(why string) <-chan []EndedSession {
	aliases := d.hopAliases()
	s := d.sessions
	s.mu.Lock()
	reg := make([]SessionParams, 0, len(s.reg))
	for _, r := range s.reg {
		reg = append(reg, r)
	}
	s.mu.Unlock()
	done := make(chan []EndedSession, 1)
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		done <- d.endNow(why, reg, aliases)
	}()
	return done
}

// endNow finds the sessions and ends them (endSessions).
func (d *Daemon) endNow(why string, reg []SessionParams, aliases map[string]bool) []EndedSession {
	uid, self := os.Getuid(), os.Getpid()
	found := map[int]sessionTarget{}
	for _, r := range reg {
		p, err := d.procs.Lookup(r.PID)
		if err != nil || p.Start != r.Start || !p.OwnedBy(uid) || p.Exited {
			continue // ended, or the PID is another process's now
		}
		found[r.PID] = sessionTarget{p: p, alias: r.Alias, via: r.Via}
	}
	list, err := d.procs.List(uid)
	if err != nil && !errors.Is(err, procs.ErrUnsupported) {
		d.logf("ending ssh sessions: the processes can't be read, so only those hop started are ended: %v", err)
	}
	m := sshMatch{uid: uid, agent: d.agent.Path(), config: filepath.Join(d.opts.Paths.ConfigDir, "config"), aliases: aliases}
	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
		m.included = filepath.Clean(d.opts.Paths.ConfigDir) == filepath.Join(home, ".ssh", "hop")
	}
	for _, p := range list {
		if _, ok := found[p.PID]; ok || p.PID == self {
			continue
		}
		if alias, ok := m.match(p); ok {
			found[p.PID] = sessionTarget{p: p, alias: alias, via: "ssh"}
		}
	}

	// Another run may be ending some of them already.
	s := d.sessions
	var targets []sessionTarget
	s.mu.Lock()
	for pid, t := range found {
		if start, busy := s.ending[pid]; busy && start == t.p.Start {
			continue
		}
		s.ending[pid] = t.p.Start
		targets = append(targets, t)
	}
	s.mu.Unlock()
	slices.SortFunc(targets, func(a, b sessionTarget) int { return a.p.PID - b.p.PID })

	ended := d.signalSessions(targets, why)

	s.mu.Lock()
	for _, t := range targets {
		if s.ending[t.p.PID] == t.p.Start {
			delete(s.ending, t.p.PID)
		}
		if r, ok := s.reg[t.p.PID]; ok && r.Start == t.p.Start {
			delete(s.reg, t.p.PID)
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
// ones it signalled: a process gone, or another one, by the first signal
// is not counted. A registered one learns why at its session.end, so why
// is noted before the signal that ends it.
func (d *Daemon) signalSessions(targets []sessionTarget, why string) []EndedSession {
	s := d.sessions
	note := func(t sessionTarget, on bool) {
		if t.via == "ssh" {
			return
		}
		key := SessionParams{PID: t.p.PID, Start: t.p.Start}
		s.mu.Lock()
		defer s.mu.Unlock()
		if !on {
			delete(s.why, key)
			return
		}
		if len(s.why) >= maxSessions {
			clear(s.why) // session.end calls that never came
		}
		s.why[key] = why
	}
	term, kill := d.opts.sessionTerm, d.opts.sessionKill
	if term <= 0 {
		term = sessionTerm
	}
	if kill <= 0 {
		kill = sessionKill
	}
	var ended []EndedSession
	running := map[int]int{} // PID to its index in ended
	for _, t := range targets {
		note(t, true)
		if err := d.procs.Signal(t.p, syscall.SIGHUP); err != nil {
			note(t, false)
			if !errors.Is(err, procs.ErrGone) {
				d.logf("ending ssh session pid %d: %v", t.p.PID, err)
			}
			continue
		}
		running[t.p.PID] = len(ended)
		ended = append(ended, EndedSession{PID: t.p.PID, Alias: t.alias, Via: t.via})
	}
	// Status says so at once, not after the waits.
	s.noteEnded(why, ended)
	byPID := map[int]procs.Proc{}
	for _, t := range targets {
		byPID[t.p.PID] = t.p
	}
	start := time.Now()
	sent := syscall.SIGHUP
	for len(running) > 0 {
		time.Sleep(50 * time.Millisecond)
		for pid := range running {
			if q, err := d.procs.Lookup(pid); err != nil || !byPID[pid].Same(q) {
				delete(running, pid)
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
			for pid := range running {
				d.logf("ssh session pid %d still runs after SIGKILL", pid)
			}
			return ended
		}
		if next == 0 {
			continue
		}
		sent = next
		for pid, i := range running {
			if err := d.procs.Signal(byPID[pid], next); errors.Is(err, procs.ErrGone) {
				delete(running, pid)
			} else if next == syscall.SIGKILL {
				ended[i].Killed = true
				s.noteKilled(pid)
			}
		}
	}
	return ended
}

// hopAliases are the Host aliases hop's ssh config has: the ones in the
// file, and the ones the daemon last wrote. Lower case, as ssh matches
// them.
func (d *Daemon) hopAliases() map[string]bool {
	out := map[string]bool{}
	if st := d.state.Load(); st != nil {
		for _, h := range st.ssh {
			for _, a := range h.Aliases {
				out[strings.ToLower(a)] = true
			}
		}
	}
	for _, a := range configAliases(filepath.Join(d.opts.Paths.ConfigDir, "config")) {
		out[strings.ToLower(a)] = true
	}
	return out
}

// configAliases reads the Host aliases of the ssh config hop generated
// (sshconfig.Write): one "Host <alias>" line each.
func configAliases(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(io.LimitReader(f, maxConfigRead))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if rest, ok := bytes.CutPrefix(line, []byte("Host ")); ok {
			out = append(out, strings.Fields(string(rest))...)
		}
	}
	return out
}

// sshMatch says which processes are plain ssh sessions through hop.
type sshMatch struct {
	uid     int
	agent   string          // hop's agent socket
	config  string          // hop's ssh config
	aliases map[string]bool // its Host aliases, lower case
	// included means an ssh with no -F reads hop's config: it is the one
	// hop setup includes from ~/.ssh/config.
	included bool
}

// match reports whether p is an ssh of this user that uses hop: its
// SSH_AUTH_SOCK is hop's agent, or its destination is one of hop's
// aliases and it reads hop's config (sshMatch.included). alias is the
// destination's host.
func (m sshMatch) match(p procs.Proc) (alias string, ok bool) {
	if !p.OwnedBy(m.uid) || p.Exited || p.Exe != "ssh" {
		return "", false
	}
	dest, cfg := sshDestination(p.Args)
	host := destHost(dest)
	if p.AgentSocket != "" && filepath.Clean(p.AgentSocket) == filepath.Clean(m.agent) {
		return host, true
	}
	switch {
	case host == "":
		return "", false
	case cfg == "" && !m.included:
		return "", false
	case cfg != "" && filepath.Clean(cfg) != filepath.Clean(m.config):
		return "", false
	}
	if m.aliases[strings.ToLower(host)] {
		return host, true
	}
	return "", false
}

// sshArgFlags are the ssh options that take an argument (ssh(1)).
const sshArgFlags = "BbcDEeFIiJLlmOoPpQRSWw"

// sshDestination reads an ssh command line as ssh(1) does up to its
// destination: the first word that is not an option or an option's
// argument, or the one after "--". config is the -F argument, if any.
func sshDestination(args []string) (dest, config string) {
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return args[i+1], config
			}
			return "", config
		}
		if len(a) < 2 || a[0] != '-' {
			return a, config
		}
		for j := 1; j < len(a); j++ {
			if strings.IndexByte(sshArgFlags, a[j]) < 0 {
				continue
			}
			v := a[j+1:]
			if v == "" {
				if i+1 >= len(args) {
					return "", config
				}
				i++
				v = args[i]
			}
			if a[j] == 'F' {
				config = v
			}
			break
		}
	}
	return "", config
}

// destHost is the host of an ssh destination: [user@]host or
// ssh://[user@]host[:port].
func destHost(dest string) string {
	dest = strings.TrimPrefix(dest, "ssh://")
	if i := strings.LastIndexByte(dest, '@'); i >= 0 {
		dest = dest[i+1:]
	}
	if i := strings.IndexAny(dest, ":/"); i >= 0 {
		dest = dest[:i]
	}
	return dest
}

// describeEnded lists sessions for the log: PID, alias and how each was
// started; never a command line.
func describeEnded(ended []EndedSession) string {
	parts := make([]string, 0, len(ended))
	for _, e := range ended {
		s := fmt.Sprintf("pid %d", e.PID)
		if e.Alias != "" {
			s += " " + e.Alias
		}
		s += " (" + e.Via
		if e.Killed {
			s += ", killed"
		}
		parts = append(parts, s+")")
	}
	return strings.Join(parts, ", ")
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

// clip cuts s to at most n bytes, at a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
