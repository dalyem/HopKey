package procs

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// root is where /proc is; tests point it at a tree of their own.
var root = "/proc"

// pidfdOpen is pidfd_open(2); tests make it fail.
var pidfdOpen = unix.PidfdOpen

// Lookup reads process pid: its parent, users, start time and program.
// ErrGone means there is no such process.
func Lookup(pid int) (Proc, error) { return read(root, pid) }

// Open pins process pid with a pidfd and reads it. What it reads is the
// pinned process: it was still running once the read was done, so its PID
// had not been reused. ErrGone means there is no such process (or it is a
// zombie); ErrNoPin that the kernel gave no pidfd (before Linux 5.3, or a
// seccomp filter that refuses it), and the process must not be signalled.
func Open(pid int) (*Pin, error) {
	fd, err := pidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil, ErrGone
	}
	if err != nil {
		return nil, fmt.Errorf("%w: pidfd_open: %v", ErrNoPin, err)
	}
	p, err := Lookup(pid)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	pin := &Pin{Proc: p, fd: fd}
	if p.Exited || pin.Exited() {
		pin.Close()
		return nil, ErrGone
	}
	return pin, nil
}

// Signal sends sig to the pinned process, and to no other. ErrGone means
// it has exited (or the Pin is closed).
func (p *Pin) Signal(sig syscall.Signal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fd < 0 {
		return ErrGone
	}
	err := unix.PidfdSendSignal(p.fd, sig, nil, 0)
	if errors.Is(err, unix.ESRCH) {
		return ErrGone
	}
	return err
}

// Exited reports whether the pinned process has exited: its pidfd polls
// readable once it has, zombie or reaped. A closed Pin counts as exited.
func (p *Pin) Exited() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fd < 0 {
		return true
	}
	fds := []unix.PollFd{{Fd: int32(p.fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		// An error leaves it as exited: then it is never signalled.
		return err != nil || (n > 0 && fds[0].Revents != 0)
	}
}

// Close lets the process go.
func (p *Pin) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fd >= 0 {
		unix.Close(p.fd)
		p.fd = -1
	}
}

// PeerPID is the PID of the process that connected c (SO_PEERCRED), as
// the kernel recorded it at connect time.
func PeerPID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, sockErr
	}
	if cred.Pid <= 0 {
		return 0, errors.New("procs: no peer PID")
	}
	return int(cred.Pid), nil
}

// read reads /proc/<pid> under dir: stat for the parent, start time and
// state, status for the users, and exe for the program. A process whose
// exe can't be read (another user's, a kernel thread) has no Exe.
func read(dir string, pid int) (Proc, error) {
	d := filepath.Join(dir, strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(d, "stat"))
	if err != nil {
		return Proc{}, fmt.Errorf("%w (%v)", ErrGone, err)
	}
	st, err := parseStat(stat)
	if err != nil {
		return Proc{}, err
	}
	status, err := os.ReadFile(filepath.Join(d, "status"))
	if err != nil {
		return Proc{}, fmt.Errorf("%w (%v)", ErrGone, err)
	}
	uid, euid, err := parseUids(status)
	if err != nil {
		return Proc{}, err
	}
	p := Proc{PID: pid, PPID: st.ppid, UID: uid, EUID: euid, Start: st.start, Exited: st.state == 'Z' || st.state == 'X'}
	if exe, err := os.Readlink(filepath.Join(d, "exe")); err == nil {
		p.Exe = strings.TrimSuffix(exe, " (deleted)")
	}
	return p, nil
}

type statFields struct {
	state byte
	ppid  int
	start string
}

// parseStat returns the state (field 3), the parent (field 4) and the
// start time (field 22, clock ticks since boot) from /proc/<pid>/stat.
// The command name, field 2, is in parentheses and may hold anything, so
// fields are counted from the last ')'.
func parseStat(b []byte) (statFields, error) {
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return statFields{}, errors.New("procs: malformed stat")
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 || len(f[0]) != 1 {
		return statFields{}, errors.New("procs: malformed stat")
	}
	ppid, err := strconv.Atoi(f[1])
	if err != nil {
		return statFields{}, errors.New("procs: malformed stat")
	}
	return statFields{state: f[0][0], ppid: ppid, start: f[19]}, nil
}

// parseUids returns the real and effective user IDs from
// /proc/<pid>/status.
func parseUids(b []byte) (uid, euid int, err error) {
	for _, line := range strings.Split(string(b), "\n") {
		v, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) < 2 {
			break
		}
		if uid, err = strconv.Atoi(f[0]); err != nil {
			break
		}
		if euid, err = strconv.Atoi(f[1]); err != nil {
			break
		}
		return uid, euid, nil
	}
	return 0, 0, errors.New("procs: no Uid line in status")
}
