package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/dalyem/hopkey/internal/shellcmd"
)

// hop mcp install registers hop mcp with an AI client through that client's
// own CLI, which is its documented way to add an MCP server. hop never
// edits a client's config file itself; for a client without a CLI, it
// prints what to paste.
//
// Checked against Claude Code 2.1.312 (claude mcp add [options] <name>
// <commandOrUrl> [args...], -s/--scope local|user|project) and Codex CLI
// 0.165.0 (codex mcp add <NAME> -- <COMMAND>..., which writes
// ~/.codex/config.toml).

func runMCPInstall(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "mcp install", "hop mcp install [--client claude|codex|print] [--read-only]")
	client := fs.String("client", "print", "claude (Claude Code, for this user), codex (Codex CLI), or print to show the config to paste")
	readOnly := fs.Bool("read-only", false, "register hop mcp --read-only, which offers no tool that runs a command")
	pos, rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 || rest != nil {
		fs.Usage()
		return failf("hop mcp install takes no arguments")
	}
	exe, err := e.hopPath()
	if err != nil {
		return err
	}
	server := []string{exe, "mcp"}
	if *readOnly {
		server = append(server, "--read-only")
	}
	switch *client {
	case "claude":
		return runClientCLI(ctx, e, "Claude Code", append([]string{"claude", "mcp", "add", "--scope", "user", "hop", "--"}, server...),
			"claude mcp remove --scope user hop", server)
	case "codex":
		return runClientCLI(ctx, e, "Codex", append([]string{"codex", "mcp", "add", "hop", "--"}, server...),
			"codex mcp remove hop", server)
	case "print":
		printMCPConfig(e, server)
		return nil
	}
	return failf("unknown client %q: use claude, codex or print", *client)
}

// hopPath is the absolute path of this hop binary for a client to start.
// The hop found on PATH is preferred when it is this same file: a package
// manager's link there outlives the versioned file it points to.
func (e *Env) hopPath() (string, error) {
	exe := e.Executable
	if exe == "" {
		return "", failf("do not know where the hop binary is")
	}
	exe, err := filepath.Abs(exe)
	if err != nil {
		return "", failf("%v", err)
	}
	if p, err := exec.LookPath("hop"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			a, aerr := os.Stat(abs)
			b, berr := os.Stat(exe)
			if aerr == nil && berr == nil && os.SameFile(a, b) {
				return abs, nil
			}
		}
	}
	return exe, nil
}

func quoteArgv(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = shellcmd.Quote(a)
	}
	return strings.Join(q, " ")
}

// runClientCLI shows the command, runs it, and passes its output on.
func runClientCLI(ctx context.Context, e *Env, name string, argv []string, remove string, server []string) error {
	fmt.Fprintf(e.Stderr, "hop: running %s\n", oneLine(quoteArgv(argv)))
	out, err := e.runCommand(ctx, argv)
	if len(out) > 0 {
		// The client's own output: shown, made display-safe.
		fmt.Fprintf(e.Stderr, "%s\n", displaySafe(strings.TrimRight(string(out), "\n")))
	}
	if errors.Is(err, exec.ErrNotFound) {
		printMCPConfig(e, server)
		return failf("%s is not on PATH; add hop to %s by hand with the config above", argv[0], name)
	}
	if err != nil {
		return failf("%s did not add hop (%v). If hop is already registered, remove it first with: %s", argv[0], err, remove)
	}
	e.printf("hop mcp is registered with %s as %q. Start a new session to load its tools.\n", name, "hop")
	return nil
}

// printMCPConfig prints the commands and config snippets that register
// server (argv: the hop binary, then its arguments).
func printMCPConfig(e *Env, server []string) {
	js := map[string]any{"mcpServers": map[string]any{"hop": map[string]any{"command": server[0], "args": server[1:]}}}
	b, _ := json.MarshalIndent(js, "", "  ")
	tomlArgs := make([]string, len(server)-1)
	for i, a := range server[1:] {
		tomlArgs[i] = tomlString(a)
	}
	e.printf("Claude Code (all projects):\n  %s\n\n", quoteArgv(append([]string{"claude", "mcp", "add", "--scope", "user", "hop", "--"}, server...)))
	e.printf("Codex:\n  %s\n\n", quoteArgv(append([]string{"codex", "mcp", "add", "hop", "--"}, server...)))
	e.printf("A client configured with JSON (mcpServers):\n%s\n\n", escapeJSONControls(b))
	e.printf("Codex's ~/.codex/config.toml, by hand:\n[mcp_servers.hop]\ncommand = %s\nargs = [%s]\n", tomlString(server[0]), strings.Join(tomlArgs, ", "))
}

// tomlString writes s as a TOML basic string. JSON's string escapes are
// valid TOML.
func tomlString(s string) string {
	b, _ := json.Marshal(s)
	return string(escapeJSONControls(b))
}
