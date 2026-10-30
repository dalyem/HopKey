package cli

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/access"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/sshkeys"
)

// Connections of hop access (crypto spec rev 17, §7.6, §7.7). Every one
// uses a check config like hop key rotate's: ssh reads that file and no
// other, logs in with the host's key from the vault through the daemon's
// agent, and trusts only the host keys it is given: all of the host's pins
// for the preflight that binds a target, and only the bound one after.

// accessSessionTimeout bounds a locked session: the lock wait, the
// client's 30 seconds from the header to the end of the payload, and the
// rest.
var accessSessionTimeout = 2 * time.Minute

// accessDecisionDeadline is the client's deadline from the end of the
// header to the end of the payload (§7.7): the file, the decision and the
// payload all come within it.
var accessDecisionDeadline = 30 * time.Second

// accessAbortGrace is how long a session the client gave up on at its
// deadline may take to end on its own before hop ends the connection: a
// host that is still sending the file, or never ends, doesn't keep the
// run until accessSessionTimeout.
var accessAbortGrace = 5 * time.Second

// accessConn is one host as hop access reaches it.
type accessConn struct {
	e    *Env
	host model.Host
	ssh  rotSSH
	user string // the user the connection logs in as; "" if hop can't tell
	dir  string
	ag   *keyAgent
}

func (c *accessConn) close() {
	if c.ag != nil {
		c.ag.close()
	}
	os.RemoveAll(c.dir)
}

// accessConnect sets up connections to h that trust only pins. It
// refuses a host with no pinned key, or a jump host without one, as
// rotate does.
func (e *Env) accessConnect(ctx context.Context, h model.Host, l *daemon.ListResult, pins []ssh.PublicKey) (*accessConn, string) {
	t, jump, why := e.rotateReach(ctx, h, l)
	if why != "" {
		return nil, why
	}
	var pub ssh.PublicKey
	for _, k := range l.Keys {
		if k.ID == h.KeyID.String() {
			p, err := sshkeys.ParsePublic(k.PublicKey)
			if err != nil {
				return nil, safef("its key %s can't be read: %v", k.Name, err)
			}
			pub = p
		}
	}
	if pub == nil {
		return nil, "it has no key in the vault to log in with; hop access logs in with the host's key"
	}
	if err := os.MkdirAll(e.Paths.RunDir, 0o700); err != nil {
		return nil, safef("%v", err)
	}
	dir, err := os.MkdirTemp(e.Paths.RunDir, "access-")
	if err != nil {
		return nil, safef("%v", err)
	}
	c := &accessConn{e: e, host: h, dir: dir}
	if c.ag, err = serveKeyAgent(filepath.Join(dir, "agent"), pub, daemonKey{sock: e.Paths.AgentSocket(), pub: pub}); err != nil {
		c.close()
		return nil, safef("could not start the agent for the connection: %v", err)
	}
	rh := &rotHost{host: h, t: t, jump: jump, pins: pins}
	addr, _ := chooseAddress(ctx, e, t)
	cfg, err := e.checkConfig(rh, addr, c.ag)
	if err != nil {
		c.close()
		return nil, safef("could not write the ssh config: %v", err)
	}
	c.ssh = rotSSH{e: e, t: t, addr: addr, cfg: cfg, dir: dir}
	c.user = checkUser(rh)
	return c, ""
}

// boundPin is the host's current pin with fingerprint fp, or nil (§7.6,
// the binding check).
func boundPin(h model.Host, fp string) ssh.PublicKey {
	pins, _ := parsePins(h.HostKeys)
	for _, p := range pins {
		if ssh.FingerprintSHA256(p) == fp {
			return p
		}
	}
	return nil
}

// preflight connects with every pin of the host, -vv -E to a new private
// log, runs the read script, and returns the pin the server presented
// (access.BoundKey) and what the read found: the file, or why it can't be
// edited (81, a symbolic link; 82, missing; over 1 MiB), with the key
// still returned, since 81 and 82 are the script's own exits after ssh
// logged the key. Nothing is written anywhere.
func (c *accessConn) preflight(ctx context.Context, pins []ssh.PublicKey) (ssh.PublicKey, []byte, string) {
	logPath := filepath.Join(c.dir, "preflight.log")
	out := &capBuffer{max: akMaxSize}
	res, err := c.ssh.runOpts(ctx, []string{"-vv", "-E", logPath}, sh(akReadScript), nil, out)
	log, cut, lerr := readCapped(logPath, sshLogMax)
	os.Remove(logPath)
	completed := err == nil && res.exited && (res.ExitCode == 0 || res.ExitCode == akExitSymlink || res.ExitCode == akExitMissing)
	if lerr != nil || cut {
		completed = false
	}
	key, berr := access.BoundKey(log, completed, pins)
	if berr != nil {
		if err != nil || !res.exited || res.ExitCode == sshAuthFailed {
			return nil, nil, "could not log in (" + sshFailure(res, err) + "); " + berr.Error()
		}
		return nil, nil, berr.Error()
	}
	switch res.ExitCode {
	case akExitSymlink:
		return key, nil, akFile + " is a symbolic link, which hop doesn't edit"
	case akExitMissing:
		return key, nil, akFile + " doesn't exist for that user"
	}
	if out.over {
		return key, nil, akFile + " is larger than 1 MiB"
	}
	return key, out.buf.Bytes(), ""
}

// sessionSent is what the client sent in a locked session.
type sessionSent int

const (
	sentNothing sessionSent = iota // no decision: the client gave up or never got a header
	sentAbort
	sentWrite
)

// sessionEnd is how a locked session ended.
type sessionEnd struct {
	code   int // the script's exit status, when exited
	exited bool
	sent   sessionSent
	// gotHeader says the header and the whole file arrived and matched;
	// user and content are then what the session read under the lock.
	gotHeader bool
	user      string
	content   []byte
	// decided says the decision came back before the deadline; decision
	// is then what decide returned. A decision that comes later is
	// dropped whole, so nothing it found reaches the planner.
	decided  bool
	decision sessionDecision
	// abortWhy is why the client aborted on its own: a header that didn't
	// match the file, a file over the limit, its deadline. "" when it
	// sent the decision it was given.
	abortWhy string
	why      string // how ssh ended, in a few safe words, when not 0
}

// sessionDecision is the client's answer to a header: abort (to is nil),
// or write to over content. The planner's findings come back with it, in
// the value, so a decision that misses the deadline leaves no trace in
// the planner's variables.
type sessionDecision struct {
	to []byte
	// d is the planner's decision on the file.
	d access.Decision
	// userChanged says the host logged in as another user than the
	// target's.
	userChanged bool
	// fenced is why the pull under the lock refused the run (accessFence);
	// "" when it passed or didn't run.
	fenced string
}

var errSessionDeadline = errors.New("hop's deadline for the session passed")

// session runs one locked session (§7.7) with a new token. decide gets
// the user and the file read under the lock, with a context that ends at
// the client's deadline; it returns the new content, or nil to abort. A
// decision that takes longer than the deadline is replaced by abort, and
// a session the client gave up on that way is ended accessAbortGrace
// later if the host hasn't ended it.
func (c *accessConn) session(ctx context.Context, decide func(ctx context.Context, user string, content []byte) sessionDecision) sessionEnd {
	tok := make([]byte, 16)
	rand.Read(tok)
	script := akSessionScript(hex.EncodeToString(tok))
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var end sessionEnd
	protoDone := make(chan struct{})
	gaveUp := make(chan struct{}, 1)
	go func() {
		defer close(protoDone)
		defer inW.Close()
		if c.protocol(ctx, outR, inW, decide, &end) {
			gaveUp <- struct{}{}
		}
	}()
	go func() {
		select {
		case <-gaveUp:
		case <-sctx.Done():
			return
		}
		t := time.NewTimer(accessAbortGrace)
		defer t.Stop()
		select {
		case <-t.C:
			cancel()
		case <-sctx.Done():
		}
	}()
	res, err := c.ssh.runIO(sctx, accessSessionTimeout, akKeepalive, sh(script), inR, outW)
	outW.Close()
	inR.CloseWithError(io.ErrClosedPipe)
	<-protoDone
	outR.Close()
	end.code, end.exited = res.ExitCode, err == nil && res.exited
	if !end.exited || res.ExitCode != 0 {
		end.why = sshFailure(res, err)
	}
	return end
}

// protocol reads the header and the file, gets the decision, and sends
// it. It records what it sent in end, and reports whether it gave up at
// its deadline. The deadline starts at the end of the header: a host that
// sends the file slowly, a slow decision and a slow payload all count
// against it. Whatever it stops on, the rest of the host's output is read
// and discarded until it ends: the copy from ssh's stdout into out must
// never block, or ssh's end (and a timeout's kill) would wait for it.
func (c *accessConn) protocol(ctx context.Context, out io.Reader, in *io.PipeWriter, decide func(context.Context, string, []byte) sessionDecision, end *sessionEnd) (gaveUp bool) {
	br := bufio.NewReaderSize(out, 256)
	// reading is open while a goroutine still reads the file from br; the
	// drain waits for it, so only one reader at a time uses br.
	var reading chan struct{}
	drain := sync.OnceFunc(func() {
		r := reading
		go func() {
			if r != nil {
				<-r
			}
			io.Copy(io.Discard, br)
		}()
	})
	defer drain()
	abort := func(why string) {
		drain()
		end.abortWhy = why
		fmt.Fprint(in, "abort\n")
		end.sent = sentAbort
	}
	line, err := br.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		// More than 256 bytes without a newline: not a header.
		abort("the host's answer is not a hop session header")
		return false
	case err != nil:
		return false // no header: the script stopped before it (81-85), or the connection did
	}
	f := strings.Fields(string(line))
	if len(f) != 5 || f[0] != "hop-session" || f[1] != "1" {
		abort("the host's answer is not a hop session header")
		return false
	}
	size, serr := strconv.ParseInt(f[4], 10, 64)
	if serr != nil || size < 0 || size > akMaxSize {
		abort(akFile + " is larger than 1 MiB")
		return false
	}
	dctx, stop := context.WithDeadline(ctx, time.Now().Add(accessDecisionDeadline))
	defer stop()
	late := func() bool {
		why := errSessionDeadline.Error()
		if ctx.Err() != nil {
			why = "the run was interrupted"
		}
		abort(why)
		return true
	}
	content := make([]byte, size)
	var rerr error
	reading = make(chan struct{})
	go func(done chan struct{}) {
		defer close(done)
		_, rerr = io.ReadFull(br, content)
	}(reading)
	select {
	case <-reading:
		reading = nil
	case <-dctx.Done():
		return late()
	}
	if rerr != nil {
		return false
	}
	if cksum(content) != f[3]+" "+f[4] {
		// Only a writer that ignores the lock changes the file between
		// the two commands.
		abort(akFile + " changed while hop was reading it")
		return false
	}
	drain()
	user := f[2]
	end.gotHeader, end.user, end.content = true, user, content
	// decide runs in its own goroutine and hands back everything it found
	// in one value; one that comes back after the deadline is dropped, and
	// its context has ended by then.
	ch := make(chan sessionDecision, 1)
	go func() { ch <- decide(dctx, user, content) }()
	var d sessionDecision
	select {
	case d = <-ch:
	case <-dctx.Done():
		return late()
	}
	if dctx.Err() != nil {
		return late()
	}
	end.decided, end.decision = true, d
	if d.to == nil {
		fmt.Fprint(in, "abort\n")
		end.sent = sentAbort
		return false
	}
	cut := context.AfterFunc(dctx, func() { in.CloseWithError(errSessionDeadline) })
	defer cut()
	end.sent = sentWrite
	if _, err := fmt.Fprintf(in, "write %s %s\n", cksum(content), cksum(d.to)); err != nil {
		return false
	}
	in.Write(d.to)
	return false
}

// read reads authorized_keys on a restricted connection, without the
// lock (the read script).
func (c *accessConn) read(ctx context.Context) ([]byte, string) {
	content, why, _ := c.ssh.readAK(ctx)
	return content, why
}
