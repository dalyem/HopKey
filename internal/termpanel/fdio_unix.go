//go:build linux || darwin

package termpanel

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// errStopped is what waiting on a descriptor returns once woken to stop.
var errStopped = errors.New("termpanel: stopped")

// maxFd is the first descriptor select cannot wait on. newProxy checks
// every descriptor waitFd will wait on before a goroutine starts waiting.
// (poll has no such limit, but macOS's does not support terminals.)
const maxFd = 1024

// errFdRange is waitFd's error for a descriptor select cannot wait on.
var errFdRange = errors.New("termpanel: descriptor out of select's range")

// wakePipe wakes a goroutine waiting in select (waitFd).
type wakePipe struct{ r, w int }

func (p wakePipe) signal() { unix.Write(p.w, []byte{0}) }

func (p wakePipe) close() {
	unix.Close(p.r)
	unix.Close(p.w)
}

// waitFd waits until fd can be read (or written, with write), or until
// wake is signalled: then errStopped. Reading and writing only after it
// lets a goroutine that does them be stopped at any time, without a
// read taking input that is not its to take any more.
func waitFd(fd int, write bool, wake int) error {
	if fd >= maxFd || wake >= maxFd {
		return errFdRange
	}
	for {
		var rs, ws unix.FdSet
		rs.Set(wake)
		if write {
			ws.Set(fd)
		} else {
			rs.Set(fd)
		}
		_, err := unix.Select(max(fd, wake)+1, &rs, &ws, nil, nil)
		switch {
		case err == unix.EINTR:
			continue
		case err != nil:
			return err
		case rs.IsSet(wake):
			return errStopped
		}
		return nil
	}
}

// reader reads a descriptor in a goroutine, once started, sending what it
// reads on out until it is stopped or the descriptor fails; then it closes
// out. Each buffer it sends is the receiver's until given back with
// release.
type reader struct {
	fd      int
	wake    wakePipe
	out     chan []byte
	free    chan []byte
	quit    chan struct{}
	done    chan struct{}
	once    sync.Once
	size    int
	started bool
	err     error // once out is closed
}

func newReader(fd, size int) (*reader, error) {
	w, err := newWakePipe()
	if err != nil {
		return nil, err
	}
	return &reader{fd: fd, wake: w, out: make(chan []byte), free: make(chan []byte, 2),
		quit: make(chan struct{}), done: make(chan struct{}), size: size}, nil
}

func (r *reader) start() {
	r.started = true
	go r.run()
}

func (r *reader) run() {
	defer close(r.done)
	defer close(r.out)
	for {
		if err := waitFd(r.fd, false, r.wake.r); err != nil {
			r.err = err
			return
		}
		var buf []byte
		select {
		case buf = <-r.free:
		default:
			buf = make([]byte, r.size)
		}
		n, err := unix.Read(r.fd, buf)
		switch {
		case err == unix.EINTR || err == unix.EAGAIN:
			r.release(buf)
			continue
		case err != nil:
			r.err = err
			return
		case n == 0:
			r.err = io.EOF
			return
		}
		select {
		case r.out <- buf[:n]:
		case <-r.quit:
			return
		}
	}
}

func (r *reader) release(b []byte) {
	select {
	case r.free <- b[:cap(b)]:
	default:
	}
}

// stop stops the goroutine and waits for it to end.
func (r *reader) stop() {
	r.once.Do(func() {
		close(r.quit)
		r.wake.signal()
		if r.started {
			<-r.done
		}
		r.wake.close()
	})
}

// writeLimit is how much input the writer holds for the child, at most:
// the proxy queues no more than room allows, and stops reading the
// terminal while it has input that does not fit, so that a child that
// does not read its input slows the user down rather than hop's memory
// growing.
const writeLimit = 64 << 10

// writer writes to a non-blocking descriptor in a goroutine, once
// started, from a queue that send never blocks on.
type writer struct {
	fd      int
	wake    wakePipe
	mu      sync.Mutex
	q       [][]byte
	n       int
	kick    chan struct{}
	space   chan struct{} // the queue got shorter, and is below writeLimit
	quit    chan struct{}
	done    chan struct{}
	once    sync.Once
	started bool
}

func newWriter(fd int) (*writer, error) {
	wp, err := newWakePipe()
	if err != nil {
		return nil, err
	}
	return &writer{fd: fd, wake: wp, kick: make(chan struct{}, 1), space: make(chan struct{}, 1),
		quit: make(chan struct{}), done: make(chan struct{})}, nil
}

func (w *writer) start() {
	w.started = true
	go w.run()
}

func (w *writer) send(b []byte) {
	if len(b) == 0 {
		return
	}
	w.mu.Lock()
	w.q = append(w.q, b)
	w.n += len(b)
	w.mu.Unlock()
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

func (w *writer) full() bool { return w.room() == 0 }

// room is how much more the queue takes.
func (w *writer) room() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return max(writeLimit-w.n, 0)
}

func (w *writer) run() {
	defer close(w.done)
	dead := false // the descriptor failed: what comes is dropped
	for {
		w.mu.Lock()
		var b []byte
		if len(w.q) > 0 {
			b = w.q[0]
		}
		w.mu.Unlock()
		if b == nil {
			select {
			case <-w.kick:
				continue
			case <-w.quit:
				return
			}
		}
		for off := 0; off < len(b) && !dead; {
			n, err := unix.Write(w.fd, b[off:])
			off += max(n, 0)
			switch {
			case err == unix.EAGAIN:
				if waitFd(w.fd, true, w.wake.r) == errStopped {
					return
				}
			case err == unix.EINTR, err == nil:
			default:
				dead = true
			}
		}
		w.mu.Lock()
		w.q[0] = nil
		w.q = w.q[1:]
		w.n -= len(b)
		below := w.n < writeLimit
		w.mu.Unlock()
		if below {
			select {
			case w.space <- struct{}{}:
			default:
			}
		}
	}
}

func (w *writer) stop() {
	w.once.Do(func() {
		close(w.quit)
		w.wake.signal()
		if w.started {
			<-w.done
		}
		w.wake.close()
	})
}

// termOut writes to the user's terminal, which may stop taking output
// (a stalled connection to a remote terminal, say) without going away: a
// write waits for it while the session runs, as long as it takes, but
// not once Run is stopping (abort) or the session is ending (end), so
// that Run can still put the terminal's mode back and return. Its writes
// are non-blocking and wait in select, on the terminal and on wake. The
// descriptor is the shell's too, so it is non-blocking only during a
// write.
type termOut struct {
	fd    int
	fl    int // the descriptor's file status flags, as found
	wake  wakePipe
	state atomic.Int32
}

// A termOut's state: the session runs, or it is ending (a write waits at
// most outGrace), or Run is stopping (a write waits no more).
const (
	outRunning int32 = iota
	outEnding
	outAborted
)

// outGrace bounds how long a write waits for the terminal once the
// session is ending, and the writes that give the terminal back to the
// shell before its mode is put back, on a suspend and at the end.
const outGrace = 250 * time.Millisecond

// errStalled is termOut.write's error when it stopped waiting for the
// terminal.
var errStalled = errors.New("termpanel: the terminal takes no output")

func newTermOut(fd int) (*termOut, error) {
	fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return nil, err
	}
	w, err := newWakePipe()
	if err != nil {
		return nil, err
	}
	return &termOut{fd: fd, fl: fl, wake: w}, nil
}

// end says that the session is ending; abort that Run is stopping.
// Either wakes a write waiting for the terminal.
func (o *termOut) end()   { o.set(outEnding) }
func (o *termOut) abort() { o.set(outAborted) }

func (o *termOut) set(st int32) {
	for {
		old := o.state.Load()
		if old >= st {
			return
		}
		if o.state.CompareAndSwap(old, st) {
			o.wake.signal()
			return
		}
	}
}

// write writes b, waiting for the terminal when it is full: at most limit
// when that is not 0, at most outGrace once the session is ending, and
// not at all without a limit once Run is stopping. It returns how much it
// wrote, and errStalled when it stopped waiting.
func (o *termOut) write(b []byte, limit time.Duration) (int, error) {
	if o.fl&unix.O_NONBLOCK == 0 {
		if _, err := unix.FcntlInt(uintptr(o.fd), unix.F_SETFL, o.fl|unix.O_NONBLOCK); err != nil {
			return 0, err
		}
		defer unix.FcntlInt(uintptr(o.fd), unix.F_SETFL, o.fl)
	}
	var deadline time.Time
	if limit > 0 {
		deadline = time.Now().Add(limit)
	}
	off := 0
	for off < len(b) {
		n, err := unix.Write(o.fd, b[off:])
		off += max(n, 0)
		switch {
		case err == nil, err == unix.EINTR:
			continue
		case err != unix.EAGAIN:
			return off, err
		}
		st := o.state.Load()
		switch {
		case st == outAborted && limit == 0:
			return off, errStalled
		case st != outRunning && (deadline.IsZero() || time.Until(deadline) > outGrace):
			deadline = time.Now().Add(outGrace)
		}
		if err := o.wait(deadline, st == outRunning); err != nil {
			return off, err
		}
	}
	return off, nil
}

// wait waits until the terminal can be written, or deadline (when it is
// not zero), or, with wake, until end or abort.
func (o *termOut) wait(deadline time.Time, wake bool) error {
	if o.fd >= maxFd || o.wake.r >= maxFd {
		return errFdRange
	}
	var tv *unix.Timeval
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return errStalled
		}
		t := unix.NsecToTimeval(d.Nanoseconds())
		tv = &t
	}
	var rs, ws unix.FdSet
	ws.Set(o.fd)
	nfd := o.fd
	if wake {
		rs.Set(o.wake.r)
		nfd = max(nfd, o.wake.r)
	}
	_, err := unix.Select(nfd+1, &rs, &ws, nil, tv)
	if err == unix.EINTR {
		return nil
	}
	return err
}
