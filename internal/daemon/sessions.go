package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

// Ending the ssh sessions hop starts (README, What revocation does).
//
// The daemon signals no process. Each hop process that runs ssh (hop
// <target>, hop exec, hop check, hop mcp's exec and run_snippet, hop key
// rotate) opens a session.watch subscription on the control socket for as
// long as its ssh runs. When this device learns that it was revoked (a
// session the server refused, the server's report, a proven revocation,
// at start too), when the max-offline policy locks it, and on hop lock
// --end-sessions, the daemon answers every subscription with ended, and
// each hop process ends its own ssh child: SIGHUP, then SIGTERM and
// SIGKILL if it still runs. A parent signals a child it has not reaped
// yet, so no other process can have its PID.
//
// A revocation or a max-offline lock stays in effect for new
// subscriptions too: until the vault opens again (reopen), one opened
// later is answered ended at once, so a session that starts as the others
// end is ended as well. hop lock --end-sessions ends the sessions open at
// that moment only. ssh run some other way (plain ssh to a hop alias, scp)
// subscribes to nothing and is never ended.

// OpSessionWatch is the subscription of a hop process that runs ssh. The
// daemon answers at once with a WatchResult, Ended set if this device is
// already revoked or locked by the max-offline policy, and the
// connection then stays open: one more WatchResult, with Ended, comes when
// the session is to end, and the daemon closes the connection. The hop
// process closes it when its ssh is done.
const OpSessionWatch = "session.watch"

// WatchParams is the request for OpSessionWatch. Both are only shown in
// status: Alias is the hop host ssh goes to, PID the hop process.
type WatchParams struct {
	Alias string `json:"alias,omitempty"`
	PID   int    `json:"pid,omitempty"`
}

// WatchResult answers OpSessionWatch. Ended says why the session is to end,
// as EndedSessions.Why does; empty in the first answer means watching.
type WatchResult struct {
	Ended string `json:"ended,omitempty"`
}

// EndedSessions is what status shows of the sessions the daemon told to
// end: those told for the last reason that ended any. Each is a
// termination request sent to the hop process that runs the session; the
// daemon does not learn whether, or when, that process ended its ssh (a
// suspended hop <target> acts on it once it is resumed).
type EndedSessions struct {
	TerminationRequests int            `json:"termination_requests"`
	Why                 string         `json:"why"` // follows "when": "this device was revoked"
	At                  time.Time      `json:"at"`
	Sessions            []EndedSession `json:"sessions"` // the last maxEndedShown
}

// EndedSession is one hop process the daemon told to end its ssh, as that
// process described itself (WatchParams).
type EndedSession struct {
	PID   int    `json:"pid,omitempty"`
	Alias string `json:"alias,omitempty"`
}

// Why the sessions end (EndedSessions.Why).
const (
	whyRevoked = "this device was revoked"
	whyRefused = "the server refused this device a session"
	whyOffline = "the max-offline policy locked the vault"
	whyLock    = "hop lock --end-sessions ran"
)

const (
	// maxWatchers bounds the open subscriptions.
	maxWatchers = 4096
	// maxEndedShown bounds EndedSessions.Sessions.
	maxEndedShown = 64
)

// watcher is one open subscription. ended gets why, once.
type watcher struct {
	s     EndedSession
	ended chan string
}

// sessions is the daemon's record of the subscriptions. In memory only.
type sessions struct {
	mu       sync.Mutex
	watchers map[*watcher]struct{}
	// ending is why a new subscription is answered ended at once: a
	// revocation or the max-offline lock, until the vault opens again.
	ending string
	ended  *EndedSessions
}

func newSessions() *sessions {
	return &sessions{watchers: map[*watcher]struct{}{}}
}

// watch opens a subscription for p. why is set, and w nil, when the
// session is to end at once.
func (s *sessions) watch(p WatchParams) (w *watcher, why string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := EndedSession{PID: p.PID, Alias: p.Alias}
	if s.ending != "" {
		s.noteLocked(s.ending, []EndedSession{e})
		return nil, s.ending, nil
	}
	if len(s.watchers) >= maxWatchers {
		return nil, "", invalidf("%d ssh sessions are watched already", maxWatchers)
	}
	w = &watcher{s: e, ended: make(chan string, 1)}
	s.watchers[w] = struct{}{}
	return w, "", nil
}

func (s *sessions) unwatch(w *watcher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.watchers, w)
}

// reopen is the vault opening again: new subscriptions are watched again.
func (s *sessions) reopen() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ending = ""
}

// noteLocked adds told to what status shows: the sessions told to end for
// why, after any told earlier for the same reason. s.mu is held.
func (s *sessions) noteLocked(why string, told []EndedSession) {
	if len(told) == 0 {
		return
	}
	if s.ended == nil || s.ended.Why != why {
		s.ended = &EndedSessions{Why: why}
	}
	s.ended.At = time.Now()
	s.ended.TerminationRequests += len(told)
	s.ended.Sessions = append(s.ended.Sessions, told...)
	if n := len(s.ended.Sessions); n > maxEndedShown {
		s.ended.Sessions = slices.Clone(s.ended.Sessions[n-maxEndedShown:])
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

// endSessions tells every open subscription that its session is to end,
// for why, and returns them. A revocation or the max-offline lock (any why
// but whyLock) also answers later subscriptions so, until the vault opens
// again. It never waits on a subscriber; the caller may hold d.mu.
func (d *Daemon) endSessions(why string) []EndedSession {
	s := d.sessions
	s.mu.Lock()
	if why != whyLock {
		s.ending = why
	}
	var told []EndedSession
	for w := range s.watchers {
		w.ended <- why // buffered, and sent once: w leaves the map
		delete(s.watchers, w)
		told = append(told, w.s)
	}
	s.noteLocked(why, told)
	s.mu.Unlock()
	if len(told) > 0 {
		d.logf("told %s to end when %s: %s", plural(len(told), "ssh session"), why, describeEnded(told))
	}
	return told
}

// serveWatch answers session.watch on c, the subscription, until the
// session is to end, the subscriber hangs up or the daemon stops.
func (d *Daemon) serveWatch(c net.Conn, enc *json.Encoder, req Request) {
	answer := func(resp Response) {
		c.SetWriteDeadline(time.Now().Add(requestTimeout))
		enc.Encode(resp)
	}
	var p WatchParams
	if len(req.Params) > 0 && string(req.Params) != "null" {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			answer(errorResponse(invalidf("bad params for %s: %v", req.Op, err)))
			return
		}
	}
	w, why, err := d.sessions.watch(p)
	if err != nil {
		answer(errorResponse(err))
		return
	}
	if w == nil {
		d.logf("told %s to end when %s", describeEnded([]EndedSession{{PID: p.PID, Alias: p.Alias}}), why)
		answer(okResponse(WatchResult{Ended: why}))
		return
	}
	defer d.sessions.unwatch(w)
	answer(okResponse(WatchResult{}))
	// The subscriber sends nothing more; a read ends when it hangs up, or
	// when the daemon stops and closes the connection.
	c.SetReadDeadline(time.Time{})
	gone := make(chan struct{})
	go func() {
		io.Copy(io.Discard, c)
		close(gone)
	}()
	select {
	case why := <-w.ended:
		answer(okResponse(WatchResult{Ended: why}))
	case <-gone:
	}
}

func okResponse(result any) Response {
	b, _ := json.Marshal(result)
	return Response{OK: true, Result: b}
}

// describeEnded lists sessions for the log: alias and hop PID.
func describeEnded(ended []EndedSession) string {
	parts := make([]string, 0, len(ended))
	for _, e := range ended {
		var s []string
		if e.Alias != "" {
			s = append(s, e.Alias)
		}
		if e.PID > 0 {
			s = append(s, fmt.Sprintf("hop pid %d", e.PID))
		}
		if len(s) == 0 {
			s = append(s, "unnamed")
		}
		parts = append(parts, strings.Join(s, " "))
	}
	return strings.Join(parts, ", ")
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

// Watch is a hop process's session.watch subscription (OpSessionWatch).
type Watch struct {
	conn net.Conn
	sc   *bufio.Scanner
}

// WatchSessions subscribes at the control socket at path, for the ssh
// session p describes. ctx bounds the dial and the first answer only.
// ended is set, and w nil, when the session is to end at once.
func WatchSessions(ctx context.Context, path string, p WatchParams) (w *Watch, ended string, err error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, "", err
	}
	w = &Watch{conn: conn, sc: bufio.NewScanner(conn)}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	params, _ := json.Marshal(p)
	line, _ := json.Marshal(Request{Op: OpSessionWatch, Params: params})
	if _, err := conn.Write(append(line, '\n')); err != nil {
		conn.Close()
		return nil, "", connError(ctx, err)
	}
	res, err := w.next()
	if err != nil {
		conn.Close()
		return nil, "", connError(ctx, err)
	}
	conn.SetDeadline(time.Time{})
	if res.Ended != "" {
		conn.Close()
		return nil, res.Ended, nil
	}
	return w, "", nil
}

// Wait blocks until the daemon says the session is to end, and says why,
// or until the subscription ends without that (the daemon stopped, or
// Close), with an error.
func (w *Watch) Wait() (ended string, err error) {
	res, err := w.next()
	if err != nil {
		return "", err
	}
	if res.Ended == "" {
		return "", errors.New("daemon: session.watch answered without a reason")
	}
	return res.Ended, nil
}

// Close ends the subscription; a Wait returns.
func (w *Watch) Close() error { return w.conn.Close() }

func (w *Watch) next() (WatchResult, error) {
	var res WatchResult
	if !w.sc.Scan() {
		err := w.sc.Err()
		if err == nil {
			err = errors.New("the daemon closed the connection")
		}
		return res, err
	}
	var resp Response
	if err := json.Unmarshal(w.sc.Bytes(), &resp); err != nil {
		return res, fmt.Errorf("daemon: malformed response: %w", err)
	}
	if !resp.OK {
		if resp.Error == nil {
			return res, errors.New("daemon: request failed")
		}
		return res, resp.Error
	}
	if len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, &res); err != nil {
			return res, fmt.Errorf("daemon: malformed result: %w", err)
		}
	}
	return res, nil
}
