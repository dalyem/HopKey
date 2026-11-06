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

// MCPInstallReport is the --json shape of hop mcp install: the server entry a
// client registers, and the client commands that register it. Registered is
// true when hop ran a client's CLI and it added hop; with --client print
// nothing is run and it is false.
type mcpInstallReport struct {
	Client     string            `json:"client"`
	Registered bool              `json:"registered"`
	Server     mcpServerEntry    `json:"server"`
	Commands   map[string]string `json:"commands,omitempty"`
}

type mcpServerEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

func mcpServerJSON(server []string) mcpServerEntry {
	return mcpServerEntry{Command: server[0], Args: append([]string{}, server[1:]...)}
}

// mcpClientCommands maps each client to the shell command that registers
// server with it.
func mcpClientCommands(server []string) map[string]string {
	return map[string]string{
		"claude": quoteArgv(append([]string{"claude", "mcp", "add", "--scope", "user", "hop", "--"}, server...)),
		"codex":  quoteArgv(append([]string{"codex", "mcp", "add", "hop", "--"}, server...)),
	}
}

func runMCPInstall(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "mcp install", "hop mcp install [--client claude|codex|print] [--read-only] [--tag T]... [--json]")
	client := fs.String("client", "print", "claude (Claude Code, for this user), codex (Codex CLI), or print to show the config to paste")
	readOnly := fs.Bool("read-only", false, "register hop mcp --read-only, which offers no tool that runs a command")
	var tags stringList
	fs.Var(&tags, "tag", "register hop mcp --tag T, which shows agents only the hosts with a tag (repeatable)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
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
	scope, err := parseAgentTags(tags.vals)
	if err != nil {
		return err
	}
	for _, t := range scope {
		server = append(server, "--tag", t)
	}
	switch *client {
	case "claude":
		return runClientCLI(ctx, e, *asJSON, "Claude Code", "claude", append([]string{"claude", "mcp", "add", "--scope", "user", "hop", "--"}, server...),
			"claude mcp remove --scope user hop", server)
	case "codex":
		return runClientCLI(ctx, e, *asJSON, "Codex", "codex", append([]string{"codex", "mcp", "add", "hop", "--"}, server...),
			"codex mcp remove hop", server)
	case "print":
		if *asJSON {
			return printJSON(e, mcpInstallReport{Client: "print", Server: mcpServerJSON(server), Commands: mcpClientCommands(server)})
		}
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
func runClientCLI(ctx context.Context, e *Env, asJSON bool, name, client string, argv []string, remove string, server []string) error {
	fmt.Fprintf(e.Stderr, "hop: running %s\n", oneLine(quoteArgv(argv)))
	out, err := e.runCommand(ctx, argv)
	if len(out) > 0 {
		// The client's own output: shown, made display-safe.
		fmt.Fprintf(e.Stderr, "%s\n", displaySafe(strings.TrimRight(string(out), "\n")))
	}
	if errors.Is(err, exec.ErrNotFound) {
		if asJSON {
			// The config is not printed with --json, so point to the
			// command that gives it as JSON: the same server, so the
			// same --read-only and --tag.
			cmd := quoteArgv(append([]string{"hop", "mcp", "install", "--client", "print", "--json"}, server[2:]...))
			if safef("%s", cmd) != cmd {
				// A tag this message can't show as it is: a command with
				// it replaced would register another scope.
				return failf("%s is not on PATH; add hop to %s by hand with the config from hop mcp install --client print --json, given the same --read-only and --tag flags", argv[0], name)
			}
			return failf("%s is not on PATH; add hop to %s by hand with the config from: %s", argv[0], name, cmd)
		}
		printMCPConfig(e, server)
		return failf("%s is not on PATH; add hop to %s by hand with the config above", argv[0], name)
	}
	if err != nil {
		return failf("%s did not add hop (%v). If hop is already registered, remove it first with: %s", argv[0], err, remove)
	}
	if asJSON {
		return printJSON(e, mcpInstallReport{Client: client, Registered: true, Server: mcpServerJSON(server)})
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
