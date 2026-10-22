// Command hop is the HopKey command-line client.
package main

import (
	"context"
	"os"

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
	env := &cli.Env{
		Stdin:     os.Stdin,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		Getenv:    os.Getenv,
		Home:      home,
		Paths:     daemon.DefaultPaths(home, os.Getenv),
		StdoutTTY: term.IsTerminal(int(os.Stdout.Fd())),
		StdinTTY:  term.IsTerminal(int(os.Stdin.Fd())),
		OpenStore: openStore,
		ReadPassword: func(prompt string) ([]byte, error) {
			os.Stderr.WriteString(prompt)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			os.Stderr.WriteString("\n")
			return b, err
		},
		Executable: exe,
	}
	os.Exit(cli.Run(context.Background(), os.Args[1:], env))
}
