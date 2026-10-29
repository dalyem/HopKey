//go:build unix

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/dalyem/hopkey/internal/daemon"
)

// Two ways this test binary runs, for hop <target> on a terminal
// (sessions_e2e_test.go):
//
//   - HopMainVar set: as hop, with a machine's paths, the way cmd/hop's
//     main runs it: on this process's own streams, with SIGINT, SIGTERM
//     and SIGHUP cancelling the command's context.
//   - JobShellVar set: as a minimal job-control shell on the terminal it
//     was started on. It runs its arguments as one job, in a process
//     group of its own put in the foreground, and appends to the file
//     JobShellVar names a line for each thing that happens to the job:
//     "pid N", "stopped SIG", "exit N" or "signal SIG". The job is this
//     binary again, run as hop (HopMainVar).
const (
	HopMainVar  = "HOPKEY_TEST_HOP_MAIN"
	JobShellVar = "HOPKEY_TEST_JOBSHELL"
)

// HopMainPaths is HopMainVar's JSON value.
type HopMainPaths struct {
	Home, Data, Run, Config, State string
}

func runTerminalModes() {
	if f := os.Getenv(JobShellVar); f != "" {
		jobShell(f, os.Args[1:])
	}
	if p := os.Getenv(HopMainVar); p != "" {
		hopMain(p, os.Args[1:])
	}
}

// hopMain is cmd/hop's main for a test machine: the same signal handling,
// the machine's paths.
func hopMain(paths string, args []string) {
	var p HopMainPaths
	if err := json.Unmarshal([]byte(paths), &p); err != nil {
		fmt.Fprintln(os.Stderr, "hopMain:", err)
		os.Exit(3)
	}
	exe, _ := os.Executable()
	ctx, cancel := context.WithCancelCause(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sigs
		signal.Stop(sigs)
		cancel(ErrInterrupted)
	}()
	e := &Env{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv,
		Home: p.Home, DataDir: p.Data, Paths: daemon.Paths{RunDir: p.Run, ConfigDir: p.Config, StateDir: p.State},
		StdoutTTY: term.IsTerminal(int(os.Stdout.Fd())), StdinTTY: term.IsTerminal(int(os.Stdin.Fd())),
		Executable: exe, DialTimeout: 5 * time.Second, Exit: os.Exit,
	}
	os.Exit(Run(ctx, args, e))
}

// jobShell runs args as a foreground job on its terminal (stdin), and logs
// to logFile what happens to it, until it exits; then it exits as the job
// did.
func jobShell(logFile string, args []string) {
	logf := func(format string, a ...any) {
		f, err := os.OpenFile(logFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			os.Exit(3)
		}
		fmt.Fprintf(f, format+"\n", a...)
		f.Close()
	}
	// The shell itself is not stopped or ended by what the terminal sends
	// its job. Handled, not ignored: the job gets the defaults back.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP)
	exe, _ := os.Executable()
	cmd := exec.Command(exe, args...)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, JobShellVar+"=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Foreground: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		logf("start %v", err)
		os.Exit(3)
	}
	pid := cmd.Process.Pid
	logf("pid %d", pid)
	for {
		var ws syscall.WaitStatus
		_, err := syscall.Wait4(pid, &ws, syscall.WUNTRACED, nil)
		switch {
		case err == syscall.EINTR:
		case err != nil:
			logf("wait %v", err)
			os.Exit(3)
		case ws.Stopped():
			logf("stopped %d", int(ws.StopSignal()))
		case ws.Signaled():
			logf("signal %d", int(ws.Signal()))
			os.Exit(128 + int(ws.Signal()))
		case ws.Exited():
			logf("exit %d", ws.ExitStatus())
			os.Exit(ws.ExitStatus())
		}
	}
}
