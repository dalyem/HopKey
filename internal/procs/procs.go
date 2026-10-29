// Package procs reads and signals this machine's processes for the
// daemon, which ends the ssh sessions hop is responsible for when a device
// is revoked (daemon/sessions.go): who runs a process, when it started,
// what it runs, and the agent socket it was given where the system shows
// that.
//
// A process is named by its PID and its start time together. A PID is
// reused once its process is gone, the start time is not, so Signal only
// signals a PID that still has the start time it was found with.
//
// Linux reads /proc. macOS runs ps, which shows no environment, so
// AgentSocket is never set there. Other systems have none of it
// (ErrUnsupported).
package procs

import (
	"errors"
	"path/filepath"
	"strings"
)

var (
	// ErrGone means the process exited, or its PID now names another
	// process.
	ErrGone = errors.New("procs: the process is gone")
	// ErrUnsupported means this system's processes can't be read.
	ErrUnsupported = errors.New("procs: not supported on this system")
)

// Proc is one process.
type Proc struct {
	PID int
	// UID is the real user ID and EUID the effective one.
	UID, EUID int
	// Start is when the process started, in a form only compared for
	// equality: a reused PID has another.
	Start string
	// Exited means the process is gone but its parent has not reaped it
	// yet (a zombie).
	Exited bool
	// Exe is the base name of the program it runs; "" when unknown.
	Exe string
	// Args is its command line. On macOS it is ps's, split at spaces.
	Args []string
	// AgentSocket is SSH_AUTH_SOCK from its environment: "" when it has
	// none or the environment can't be read (always on macOS).
	AgentSocket string
}

// OwnedBy reports whether uid runs p, as both its real and effective user.
func (p Proc) OwnedBy(uid int) bool { return p.UID == uid && p.EUID == uid }

// Same reports whether q is still the process p was: the same PID and
// start time, run by the same user, and not exited.
func (p Proc) Same(q Proc) bool {
	return p.PID == q.PID && p.Start == q.Start && p.UID == q.UID && p.EUID == q.EUID && !q.Exited
}

// Alive reports whether p is still running: its PID has the same start
// time, and it has not exited.
func Alive(p Proc) bool {
	q, err := Lookup(p.PID)
	return err == nil && p.Same(q)
}

// base is the base name of a program path; a binary replaced on disk
// since it started reads "<path> (deleted)" on Linux.
func base(path string) string {
	return filepath.Base(strings.TrimSuffix(path, " (deleted)"))
}
