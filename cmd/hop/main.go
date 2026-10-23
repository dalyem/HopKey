// Command hop is the HopKey command-line client.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		os.Stderr.WriteString("hop: cannot find your home directory: " + err.Error() + "\n")
		os.Exit(cli.ExitFailure)
	}
	exe, _ := os.Executable()

	// SIGINT and SIGTERM cancel the context; cli.Run decides what else
	// happens (a hop auth flow hands the vault back to the daemon). A
	// second signal is not caught: it ends the process at once.
	ctx, cancel := context.WithCancelCause(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		signal.Stop(sigs)
		cancel(cli.ErrInterrupted)
	}()
	// A prompt may have turned echo off; exiting on a signal turns it on.
	stdinFd := int(os.Stdin.Fd())
	var termState *term.State
	if term.IsTerminal(stdinFd) {
		termState, _ = term.GetState(stdinFd)
	}

	env := &cli.Env{
		Stdin:     os.Stdin,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		Getenv:    os.Getenv,
		Home:      home,
		Paths:     daemon.DefaultPaths(home, os.Getenv),
		StdoutTTY: term.IsTerminal(int(os.Stdout.Fd())),
		StdinTTY:  term.IsTerminal(stdinFd),
		OpenStore: openStore,
		ReadPassword: func(prompt string) ([]byte, error) {
			os.Stderr.WriteString(prompt)
			b, err := term.ReadPassword(stdinFd)
			os.Stderr.WriteString("\n")
			return b, err
		},
		Executable: exe,
		Exit: func(code int) {
			if termState != nil {
				term.Restore(stdinFd, termState)
			}
			os.Exit(code)
		},
	}
	os.Exit(cli.Run(ctx, os.Args[1:], env))
}
