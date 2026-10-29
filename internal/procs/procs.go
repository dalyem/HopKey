// Package procs reads and signals this machine's processes for the
// daemon, which ends the ssh sessions that registered through hop's ssh
// config when a device is revoked (daemon/sessions.go): who connected to
// a socket, who runs a process, its parent, when it started and the
// program it runs, as the kernel says, never as the process's own
// command line says.
//
// A process is named by its PID and its start time together. A PID is
// reused once its process is gone, the start time is not. A Pin holds one
// process to signal: on Linux a pidfd, which the kernel ties to that
// process, so a signal can't reach another one that took the PID. macOS
// has no such handle: there a Pin checks the start time and the program
// again right before each signal, and a reuse of the PID in the moment
// between that check and kill(2) is still possible.
//
// Linux reads /proc. macOS asks the kernel with sysctl (kern.proc.pid and
// kern.procargs2). Other systems have none of it (ErrUnsupported).
package procs

import (
	"errors"
	"sync"
)

var (
	// ErrGone means the process exited, or its PID now names another
	// process.
	ErrGone = errors.New("procs: the process is gone")
	// ErrUnsupported means this system's processes can't be read.
	ErrUnsupported = errors.New("procs: not supported on this system")
	// ErrNoPin means the process can't be held so that a signal reaches
	// it and no other (no pidfd on this Linux): it must not be signalled.
	ErrNoPin = errors.New("procs: the process can't be pinned")
)

// Proc is one process.
type Proc struct {
	PID int
	// PPID is its parent's PID.
	PPID int
	// UID is the real user ID and EUID the effective one.
	UID, EUID int
	// Start is when the process started, in a form only compared for
	// equality: a reused PID has another.
	Start string
	// Exited means the process is gone but its parent has not reaped it
	// yet (a zombie).
	Exited bool
	// Exe is the path of the program it runs, as the kernel recorded it
	// at exec: /proc/<pid>/exe on Linux (without the " (deleted)" of a
	// binary replaced since), the exec path of kern.procargs2 on macOS.
	// Never the command line. "" when it can't be read.
	Exe string
}

// OwnedBy reports whether uid runs p, as both its real and effective user.
func (p Proc) OwnedBy(uid int) bool { return p.UID == uid && p.EUID == uid }

// Same reports whether q is still the process p was: the same PID and
// start time, run by the same user, and not exited.
func (p Proc) Same(q Proc) bool {
	return p.PID == q.PID && p.Start == q.Start && p.UID == q.UID && p.EUID == q.EUID && !q.Exited
}

// Pin is one process held for signalling (Open). Its Proc is what was
// read once it was held.
type Pin struct {
	Proc

	mu sync.Mutex
	fd int // the pidfd on Linux; -1 when closed, and elsewhere
}

// Pinned reports whether the kernel holds the process for this Pin (a
// pidfd), so that no other process can be signalled through it. False on
// macOS, where Signal checks again before each signal instead.
func (p *Pin) Pinned() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fd >= 0
}
