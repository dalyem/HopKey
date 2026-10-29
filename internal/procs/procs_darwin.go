package procs

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// psColumns are what ps prints for each process: the PID, the effective
// and the real user, the state, the start time (five words in the C
// locale, "Thu Oct 29 10:00:00 2026") and the command line.
var psColumns = []string{"-o", "pid=,uid=,ruid=,stat=,lstart=,command="}

// ps runs ps in the C locale and UTC, so the start time reads the same
// for every caller.
func ps(args ...string) ([]byte, error) {
	cmd := exec.Command("/bin/ps", args...)
	cmd.Env = []string{"LC_ALL=C", "TZ=UTC"}
	return cmd.Output()
}

// Lookup reads process pid with ps. ErrGone means there is no such
// process.
func Lookup(pid int) (Proc, error) {
	out, err := ps(append([]string{"-ww", "-p", strconv.Itoa(pid)}, psColumns...)...)
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(bytes.TrimSpace(out)) == 0 {
		return Proc{}, ErrGone
	}
	if err != nil {
		return Proc{}, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if p, ok := parsePS(line); ok && p.PID == pid {
			return p, nil
		}
	}
	return Proc{}, ErrGone
}

// List returns the processes uid runs. ps shows no environment, so
// AgentSocket is never set.
func List(uid int) ([]Proc, error) {
	out, err := ps(append([]string{"-axww"}, psColumns...)...)
	if err != nil {
		return nil, fmt.Errorf("procs: ps: %w", err)
	}
	var list []Proc
	for _, line := range strings.Split(string(out), "\n") {
		if p, ok := parsePS(line); ok && p.OwnedBy(uid) {
			list = append(list, p)
		}
	}
	return list, nil
}

// Signal sends sig to p's PID only while it is still p (Proc.Same). A
// reuse of the PID in the moment between the check and kill(2) is still
// possible.
func Signal(p Proc, sig syscall.Signal) error {
	q, err := Lookup(p.PID)
	if err != nil || !p.Same(q) {
		return ErrGone
	}
	err = syscall.Kill(p.PID, sig)
	if errors.Is(err, syscall.ESRCH) {
		return ErrGone
	}
	return err
}

// parsePS reads one line of ps with psColumns. The command line is split
// at spaces, so an argument with spaces in it reads as several.
func parsePS(line string) (Proc, bool) {
	f := strings.Fields(line)
	if len(f) < 10 {
		return Proc{}, false
	}
	pid, err1 := strconv.Atoi(f[0])
	euid, err2 := strconv.Atoi(f[1])
	uid, err3 := strconv.Atoi(f[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return Proc{}, false
	}
	p := Proc{
		PID: pid, UID: uid, EUID: euid,
		Exited: strings.HasPrefix(f[3], "Z"),
		Start:  strings.Join(f[4:9], " "),
		Args:   f[9:],
	}
	p.Exe = base(p.Args[0])
	return p, true
}
