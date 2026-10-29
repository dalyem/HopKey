package procs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// root is where /proc is; tests point it at a tree of their own.
var root = "/proc"

// Lookup reads process pid: its users, start time, program and command
// line. ErrGone means there is no such process.
func Lookup(pid int) (Proc, error) { return read(root, pid, false) }

// List returns the processes uid runs, as Lookup reads them, with the
// agent socket of each whose environment can be read. Processes that end
// while it reads are left out.
func List(uid int) ([]Proc, error) {
	des, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []Proc
	for _, de := range des {
		pid, err := strconv.Atoi(de.Name())
		if err != nil || pid <= 0 {
			continue
		}
		p, err := read(root, pid, true)
		if err != nil || !p.OwnedBy(uid) {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// Signal sends sig to p's PID only while it is still p (Proc.Same). Where
// the kernel has pidfds the PID is pinned before the check, so the signal
// can't reach a process that took the PID after it; without them a reuse
// in the moment between the check and kill(2) is still possible.
func Signal(p Proc, sig syscall.Signal) error {
	fd, err := unix.PidfdOpen(p.PID, 0)
	if errors.Is(err, unix.ESRCH) {
		return ErrGone
	}
	if err == nil {
		defer unix.Close(fd)
	}
	q, lerr := Lookup(p.PID)
	if lerr != nil || !p.Same(q) {
		return ErrGone
	}
	if err == nil {
		err = unix.PidfdSendSignal(fd, sig, nil, 0)
	} else {
		err = syscall.Kill(p.PID, sig)
	}
	if errors.Is(err, unix.ESRCH) {
		return ErrGone
	}
	return err
}

// read reads /proc/<pid> under dir: stat for the start time and state,
// status for the users, exe (or comm, when exe can't be read) for the
// program, cmdline, and with env the environment.
func read(dir string, pid int, env bool) (Proc, error) {
	d := filepath.Join(dir, strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(d, "stat"))
	if err != nil {
		return Proc{}, fmt.Errorf("%w (%v)", ErrGone, err)
	}
	start, state, err := parseStat(stat)
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
	p := Proc{PID: pid, UID: uid, EUID: euid, Start: start, Exited: state == 'Z' || state == 'X'}
	if exe, err := os.Readlink(filepath.Join(d, "exe")); err == nil {
		p.Exe = base(exe)
	} else if comm, err := os.ReadFile(filepath.Join(d, "comm")); err == nil {
		p.Exe = strings.TrimSpace(string(comm))
	}
	if b, err := os.ReadFile(filepath.Join(d, "cmdline")); err == nil {
		p.Args = splitNUL(b)
	}
	if env {
		if b, err := os.ReadFile(filepath.Join(d, "environ")); err == nil {
			for _, kv := range splitNUL(b) {
				if v, ok := strings.CutPrefix(kv, "SSH_AUTH_SOCK="); ok {
					p.AgentSocket = v
				}
			}
		}
	}
	return p, nil
}

// parseStat returns the start time (field 22, clock ticks since boot) and
// the state (field 3) from /proc/<pid>/stat. The command name, field 2, is
// in parentheses and may hold anything, so fields are counted from the
// last ')'.
func parseStat(b []byte) (start string, state byte, err error) {
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return "", 0, errors.New("procs: malformed stat")
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 || len(f[0]) != 1 {
		return "", 0, errors.New("procs: malformed stat")
	}
	return f[19], f[0][0], nil
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

func splitNUL(b []byte) []string {
	b = bytes.TrimRight(b, "\x00")
	if len(b) == 0 {
		return nil
	}
	return strings.Split(string(b), "\x00")
}
