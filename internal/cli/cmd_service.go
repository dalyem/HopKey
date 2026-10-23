package cli

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/dalyem/hopkey/internal/safepath"
)

// hop setup --service installs a user service that runs hop daemon from
// login, so the vault stays in sync before any hop command (design:
// "Always running"): a systemd --user unit on Linux, a launchd agent on
// macOS. The CLI still starts the daemon itself when it is not running.

// serviceMarker opens every file hop setup --service writes; --uninstall
// removes only a file that has it.
const serviceMarker = "Written by hop setup --service"

// serviceEnv is the environment the daemon's paths depend on (sockets,
// log, vault). The service gets the values this shell has, so the daemon
// it runs listens where the CLI looks.
var serviceEnv = []string{"XDG_RUNTIME_DIR", "XDG_STATE_HOME", "XDG_DATA_HOME"}

type serviceSpec struct {
	kind      string // "systemd" or "launchd"
	dir       string
	name      string
	body      string
	install   [][]string // commands that load and start it
	uninstall [][]string // commands that stop and unload it, before the file goes
	reload    [][]string // commands after the file is gone
}

func (s *serviceSpec) path() string { return filepath.Join(s.dir, s.name) }

// ServiceResult is the --json shape of hop setup --service.
type ServiceResult struct {
	Service   string     `json:"service"`
	Path      string     `json:"path"`
	Installed bool       `json:"installed"`
	Changed   bool       `json:"changed"`
	Commands  [][]string `json:"commands"`
	Notes     []string   `json:"notes,omitempty"`
}

func (e *Env) goos() string {
	if e.GOOS != "" {
		return e.GOOS
	}
	return runtime.GOOS
}

func (e *Env) runCommand(ctx context.Context, argv []string) ([]byte, error) {
	if e.RunCommand != nil {
		return e.RunCommand(ctx, argv[0], argv[1:]...)
	}
	return exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
}

// serviceFor builds the unit or agent for this system.
func serviceFor(e *Env) (*serviceSpec, error) {
	exe := e.Executable
	if exe == "" || !filepath.IsAbs(exe) {
		return nil, failf("do not know where the hop binary is, so there is nothing for a service to run")
	}
	if oneLine(exe) != exe {
		return nil, failf("the path of the hop binary has control characters in it: %s", exe)
	}
	var env [][2]string
	for _, k := range serviceEnv {
		if v := e.Getenv(k); filepath.IsAbs(v) && oneLine(v) == v {
			env = append(env, [2]string{k, v})
		}
	}
	switch e.goos() {
	case "linux":
		cfg := e.Getenv("XDG_CONFIG_HOME")
		if !filepath.IsAbs(cfg) {
			cfg = filepath.Join(e.Home, ".config")
		}
		const unit = "hopkey.service"
		var b strings.Builder
		fmt.Fprintf(&b, "# %s: it runs the hop daemon from login, so the vault\n", serviceMarker)
		b.WriteString("# stays in sync before any hop command. Remove it with hop setup --service --uninstall.\n")
		b.WriteString("[Unit]\nDescription=HopKey daemon (hop)\n\n[Service]\nType=simple\n")
		fmt.Fprintf(&b, "ExecStart=%s daemon\n", systemdQuote(exe, true))
		for _, kv := range env {
			fmt.Fprintf(&b, "Environment=%s\n", systemdQuote(kv[0]+"="+kv[1], false))
		}
		b.WriteString("Restart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n")
		return &serviceSpec{
			kind: "systemd", dir: filepath.Join(cfg, "systemd", "user"), name: unit, body: b.String(),
			install: [][]string{
				{"systemctl", "--user", "daemon-reload"},
				{"systemctl", "--user", "enable", "--now", unit},
			},
			uninstall: [][]string{{"systemctl", "--user", "disable", "--now", unit}},
			reload:    [][]string{{"systemctl", "--user", "daemon-reload"}},
		}, nil
	case "darwin":
		const label = "com.github.dalyem.hopkey"
		dir := filepath.Join(e.Home, "Library", "LaunchAgents")
		path := filepath.Join(dir, label+".plist")
		domain := fmt.Sprintf("gui/%d", os.Getuid())
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
		b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
		fmt.Fprintf(&b, "<!-- %s: it runs the hop daemon from login. Remove it with hop setup --service --uninstall. -->\n", serviceMarker)
		b.WriteString("<plist version=\"1.0\">\n<dict>\n")
		fmt.Fprintf(&b, "\t<key>Label</key>\n\t<string>%s</string>\n", label)
		fmt.Fprintf(&b, "\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>%s</string>\n\t\t<string>daemon</string>\n\t</array>\n", xmlText(exe))
		if len(env) > 0 {
			b.WriteString("\t<key>EnvironmentVariables</key>\n\t<dict>\n")
			for _, kv := range env {
				fmt.Fprintf(&b, "\t\t<key>%s</key>\n\t\t<string>%s</string>\n", kv[0], xmlText(kv[1]))
			}
			b.WriteString("\t</dict>\n")
		}
		b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")
		// Restart it when it fails, not when it exits cleanly (as it does
		// when another hop daemon already owns the vault).
		b.WriteString("\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n")
		b.WriteString("\t<key>ProcessType</key>\n\t<string>Background</string>\n")
		fmt.Fprintf(&b, "\t<key>StandardOutPath</key>\n\t<string>%s</string>\n", xmlText(e.Paths.LogFile()))
		fmt.Fprintf(&b, "\t<key>StandardErrorPath</key>\n\t<string>%s</string>\n", xmlText(e.Paths.LogFile()))
		b.WriteString("</dict>\n</plist>\n")
		return &serviceSpec{
			kind: "launchd", dir: dir, name: label + ".plist", body: b.String(),
			install:   [][]string{{"launchctl", "bootstrap", domain, path}},
			uninstall: [][]string{{"launchctl", "bootout", domain, path}},
		}, nil
	}
	return nil, failf("hop setup --service supports systemd on Linux and launchd on macOS, not %s; hop starts the daemon itself when you run a command", e.goos())
}

// systemdQuote quotes s for a unit file: in double quotes, with C-style
// escapes for '\' and '"', '%' doubled so it is not a specifier, and, in a
// command line (cmd), '$' doubled so it is not a variable.
func systemdQuote(s string, cmd bool) string {
	r := []string{`\`, `\\`, `"`, `\"`, "%", "%%"}
	if cmd {
		r = append(r, "$", "$$")
	}
	return `"` + strings.NewReplacer(r...).Replace(s) + `"`
}

func xmlText(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func runService(ctx context.Context, e *Env, yes, uninstall, asJSON bool) error {
	spec, err := serviceFor(e)
	if err != nil {
		return err
	}
	if uninstall {
		return uninstallService(ctx, e, spec, yes, asJSON)
	}
	path := spec.path()
	res := ServiceResult{Service: spec.kind, Path: path, Installed: true, Commands: [][]string{}}
	old, existed, err := readServiceFile(path)
	if err != nil {
		return err
	}
	if existed && old == spec.body {
		if asJSON {
			return printJSON(e, res)
		}
		e.printf("the %s service is already installed: %s\n", spec.kind, oneLine(path))
		return nil
	}
	if existed && !strings.Contains(old, serviceMarker) {
		return failf("%s exists and hop did not write it; move it away first", path)
	}

	cmds := spec.install
	if existed && spec.kind == "launchd" {
		// A loaded agent has to go before the new one can load.
		cmds = append(slices.Clone(spec.uninstall), cmds...)
	}
	fmt.Fprintf(e.Stderr, "hop will write %s, so the hop daemon runs from login, and then run:\n", oneLine(path))
	for _, c := range cmds {
		fmt.Fprintf(e.Stderr, "  %s\n", oneLine(strings.Join(c, " ")))
	}
	ok, err := confirm(e, yes, "Install the service?")
	if err != nil {
		return err
	}
	if !ok {
		return failf("no changes made")
	}
	if spec.kind == "launchd" {
		// launchd opens the log itself, and wants its directory there.
		if _, err := safepath.EnsurePrivateDir(e.Paths.StateDir); err != nil {
			return failf("%v", err)
		}
	}
	if err := writeServiceFile(spec); err != nil {
		return err
	}
	res.Changed = true
	if c, err := dialExisting(ctx, e); err == nil && c != nil {
		c.Close()
		if !existed {
			res.Notes = append(res.Notes, "a hop daemon is already running outside the service: the service runs it from your next login, or now after hop daemon stop and starting the service again")
		}
	}
	for i, c := range cmds {
		out, err := e.runCommand(ctx, c)
		res.Commands = append(res.Commands, c)
		if err != nil {
			if existed && spec.kind == "launchd" && i == 0 {
				continue // the old agent was not loaded
			}
			return failf("wrote %s, but %s failed: %v: %s", path, strings.Join(c, " "), err, printable(strings.TrimSpace(string(out))))
		}
	}
	if asJSON {
		return printJSON(e, res)
	}
	e.printf("installed the %s service: %s\n", spec.kind, oneLine(path))
	for _, n := range res.Notes {
		fmt.Fprintf(e.Stderr, "hop: note: %s\n", n)
	}
	return nil
}

func uninstallService(ctx context.Context, e *Env, spec *serviceSpec, yes, asJSON bool) error {
	path := spec.path()
	res := ServiceResult{Service: spec.kind, Path: path, Commands: [][]string{}}
	old, existed, err := readServiceFile(path)
	if err != nil {
		return err
	}
	if !existed {
		if asJSON {
			return printJSON(e, res)
		}
		e.printf("no %s service is installed (%s)\n", spec.kind, oneLine(path))
		return nil
	}
	if !strings.Contains(old, serviceMarker) {
		return failf("%s was not written by hop setup --service; leaving it alone", path)
	}
	ok, err := confirm(e, yes, safef("Stop the %s service and remove %s?", spec.kind, path))
	if err != nil {
		return err
	}
	if !ok {
		return failf("no changes made")
	}
	for _, c := range spec.uninstall {
		res.Commands = append(res.Commands, c)
		if out, err := e.runCommand(ctx, c); err != nil {
			// It may not be loaded; removing the file is what matters.
			res.Notes = append(res.Notes, safef("%s failed: %v: %s", strings.Join(c, " "), err, printable(strings.TrimSpace(string(out)))))
		}
	}
	if err := os.Remove(path); err != nil {
		return failf("%v", err)
	}
	res.Changed = true
	for _, c := range spec.reload {
		res.Commands = append(res.Commands, c)
		if out, err := e.runCommand(ctx, c); err != nil {
			res.Notes = append(res.Notes, safef("%s failed: %v: %s", strings.Join(c, " "), err, printable(strings.TrimSpace(string(out)))))
		}
	}
	if asJSON {
		return printJSON(e, res)
	}
	e.printf("removed the %s service: %s\n", spec.kind, oneLine(path))
	for _, n := range res.Notes {
		fmt.Fprintf(e.Stderr, "hop: note: %s\n", oneLine(n))
	}
	return nil
}

// readServiceFile reads a service file hop may have written. A symlink or
// anything but a regular file there is refused: hop never writes through
// one.
func readServiceFile(path string) (body string, existed bool, err error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, failf("%v", err)
	}
	if !fi.Mode().IsRegular() {
		return "", true, failf("%s is not a regular file; hop leaves it alone", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", true, failf("%v", err)
	}
	return string(b), true, nil
}

// writeServiceFile writes the unit or agent through a temporary file in a
// directory safepath has checked, so a crash leaves the old file or the
// new one.
func writeServiceFile(spec *serviceSpec) error {
	dir, err := safepath.EnsurePrivateDir(spec.dir)
	if err != nil {
		return failf("%v", err)
	}
	tmp, err := os.CreateTemp(dir, ".hop-service-*")
	if err != nil {
		return failf("%v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(spec.body); err != nil {
		tmp.Close()
		return failf("%v", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return failf("%v", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return failf("%v", err)
	}
	if err := tmp.Close(); err != nil {
		return failf("%v", err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, spec.name)); err != nil {
		return failf("%v", err)
	}
	return nil
}
