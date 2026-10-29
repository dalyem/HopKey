package procs

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// szomb is a zombie's p_stat (SZOMB in sys/proc.h).
const szomb = 5

// Lookup asks the kernel about process pid (sysctl kern.proc.pid): its
// parent, users, start time and state, and its program from the exec path
// of kern.procargs2. ErrGone means there is no such process.
func Lookup(pid int) (Proc, error) {
	if pid <= 0 {
		return Proc{}, ErrGone
	}
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		// A PID with no process answers with no data, which reads as EIO.
		return Proc{}, fmt.Errorf("%w (%v)", ErrGone, err)
	}
	if int(k.Proc.P_pid) != pid {
		return Proc{}, ErrGone
	}
	p := Proc{
		PID:    pid,
		PPID:   int(k.Eproc.Ppid),
		UID:    int(k.Eproc.Pcred.P_ruid),
		EUID:   int(k.Eproc.Ucred.Uid),
		Start:  fmt.Sprintf("%d.%06d", k.Proc.P_starttime.Sec, k.Proc.P_starttime.Usec),
		Exited: k.Proc.P_stat == szomb,
	}
	p.Exe, _ = execPath(pid)
	return p, nil
}

// execPath is the path the kernel recorded when pid last ran exec: the
// first string kern.procargs2 returns, after argc and before the
// arguments.
func execPath(pid int) (string, error) {
	b, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", err
	}
	if len(b) < 5 {
		return "", errors.New("procs: malformed procargs2")
	}
	b = b[4:]
	i := bytes.IndexByte(b, 0)
	if i <= 0 {
		return "", errors.New("procs: malformed procargs2")
	}
	return string(b[:i]), nil
}

// Open reads process pid to signal it. macOS has no handle that holds a
// process, so the Pin checks it again before each signal (Signal).
func Open(pid int) (*Pin, error) {
	p, err := Lookup(pid)
	if err != nil {
		return nil, err
	}
	if p.Exited {
		return nil, ErrGone
	}
	return &Pin{Proc: p, fd: -1}, nil
}

// still reports whether pid is still the process p read: the same start
// time, users and program, not exited.
func (p *Pin) still() bool {
	q, err := Lookup(p.PID)
	return err == nil && p.Same(q) && q.Exe == p.Exe
}

// Signal sends sig to the process if its PID still has the start time and
// program it was read with. Between that check and kill(2) the process
// may end and the PID go to another one; that moment is short, and PIDs
// are not reused at once, but it is not closed.
func (p *Pin) Signal(sig syscall.Signal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.still() {
		return ErrGone
	}
	err := syscall.Kill(p.PID, sig)
	if errors.Is(err, syscall.ESRCH) {
		return ErrGone
	}
	return err
}

// Exited reports whether the process has exited, or its PID names another
// one.
func (p *Pin) Exited() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.still()
}

// Close does nothing here: nothing is held.
func (p *Pin) Close() {}

// PeerPID is the PID of the process that connected c (LOCAL_PEERPID), as
// the kernel recorded it at connect time.
func PeerPID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		pid, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, sockErr
	}
	if pid <= 0 {
		return 0, errors.New("procs: no peer PID")
	}
	return pid, nil
}
