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

// The marker opens every file hop setup --service writes; --uninstall
// removes only a file that has it. The plist's is an XML comment, which
// can't hold "--", so it has its own. Plists written before that carry
// unitMarker, and hop still owns them: it replaces or removes them, and
// writes only plistMarker.
const (
	unitMarker  = "Written by hop setup --service"
	plistMarker = "Written by hop setup (service)"
)

// serviceEnv is the environment the daemon's paths depend on (sockets,
// log, vault). The service gets the values this shell has, so the daemon
// it runs listens where the CLI looks.
var serviceEnv = []string{"XDG_RUNTIME_DIR", "XDG_STATE_HOME", "XDG_DATA_HOME"}

type serviceSpec struct {
	kind    string // "systemd" or "launchd"
	dir     string
	name    string
	markers []string // a file with any of these is hop's; the first is the one hop writes
	body    string
	// install runs on every install, in order, whether or not the file
	// changed: it makes the service manager load the file as it is now
	// and run a daemon from it. Any failure fails the run, and the next
	// run starts again from the first step.
	install []serviceStep
	stop    []serviceStep // uninstall: stop and unload it, before the file goes
	reload  [][]string    // uninstall: after the file is gone
	// notLoaded says a failed command failed only because the service
	// manager does not have the service.
	notLoaded func(out []byte, err error) bool
	active    string // what a successful install means, for people
}

// serviceStep is a command; notLoadedOK says it is done when it fails
// because the service is not loaded (nothing to stop).
type serviceStep struct {
	argv        []string
	notLoadedOK bool
}

func (s *serviceSpec) path() string { return filepath.Join(s.dir, s.name) }

func (s *serviceSpec) owns(body string) bool {
	return slices.ContainsFunc(s.markers, func(m string) bool { return strings.Contains(body, m) })
}

// ServiceResult is the --json shape of hop setup --service. Changed says
// the file was written (or removed). Active says the service manager ran
// every step: on install, it loaded the file as it is now and (re)started
// the daemon from it; on uninstall it is false, as the service stopped.
// A run where a step failed prints an error instead.
type ServiceResult struct {
	Service   string     `json:"service"`
	Path      string     `json:"path"`
	Installed bool       `json:"installed"`
	Changed   bool       `json:"changed"`
	Active    bool       `json:"active"`
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
		fmt.Fprintf(&b, "# %s: it runs the hop daemon from login, so the vault\n", unitMarker)
		b.WriteString("# stays in sync before any hop command. Remove it with hop setup --service --uninstall.\n")
		b.WriteString("[Unit]\nDescription=HopKey daemon (hop)\n\n[Service]\nType=simple\n")
		fmt.Fprintf(&b, "ExecStart=%s daemon\n", systemdQuote(exe, true))
		for _, kv := range env {
			fmt.Fprintf(&b, "Environment=%s\n", systemdQuote(kv[0]+"="+kv[1], false))
		}
		b.WriteString("Restart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n")
		return &serviceSpec{
			kind: "systemd", dir: filepath.Join(cfg, "systemd", "user"), name: unit, markers: []string{unitMarker}, body: b.String(),
			active: "reloaded, enabled and restarted",
			// restart starts a stopped service too, and makes a running
			// one run the unit as daemon-reload just read it.
			install: []serviceStep{
				{argv: []string{"systemctl", "--user", "daemon-reload"}},
				{argv: []string{"systemctl", "--user", "enable", unit}},
				{argv: []string{"systemctl", "--user", "restart", unit}},
			},
			// disable --now stops nothing when the unit file is gone, and
			// systemd may still run the unit it loaded: stop does that.
			stop: []serviceStep{
				{argv: []string{"systemctl", "--user", "disable", "--now", unit}, notLoadedOK: true},
				{argv: []string{"systemctl", "--user", "stop", unit}, notLoadedOK: true},
			},
			reload:    [][]string{{"systemctl", "--user", "daemon-reload"}},
			notLoaded: systemdNotLoaded,
		}, nil
	case "darwin":
		const label = "com.github.dalyem.hopkey"
		dir := filepath.Join(e.Home, "Library", "LaunchAgents")
		path := filepath.Join(dir, label+".plist")
		domain := fmt.Sprintf("gui/%d", os.Getuid())
		target := domain + "/" + label
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
		b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
		fmt.Fprintf(&b, "<!-- %s: it runs the hop daemon from login. hop setup removes it with the service and uninstall options. -->\n", plistMarker)
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
		bootout := serviceStep{argv: []string{"launchctl", "bootout", target}, notLoadedOK: true}
		return &serviceSpec{
			kind: "launchd", dir: dir, name: label + ".plist", markers: []string{plistMarker, unitMarker}, body: b.String(),
			// bootstrap refuses a loaded agent and reads the file only when
			// it loads, so the agent goes first; kickstart -k then runs the
			// daemon from what bootstrap loaded, even when the one RunAtLoad
			// started has exited.
			install: []serviceStep{
				bootout,
				{argv: []string{"launchctl", "bootstrap", domain, path}},
				{argv: []string{"launchctl", "kickstart", "-k", target}},
			},
			stop:      []serviceStep{bootout},
			notLoaded: launchdNotLoaded,
			active:    "loaded and started",
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

// launchdNotLoaded: launchctl bootout fails with 3 (ESRCH, "No such
// process") or 113 ("Could not find specified service") when the domain
// has no such service. Only the exit status counts: text alone could come
// with some other failure.
func launchdNotLoaded(_ []byte, err error) bool {
	c := exitStatusOf(err)
	return c == 3 || c == 113
}

// systemdUnit is the unit setup installs.
const systemdUnit = "hopkey.service"

// systemdNotLoaded: systemctl says "Unit file hopkey.service does not
// exist" (disable), "Unit hopkey.service not loaded" (stop) or "Unit
// hopkey.service not found". Only those complete phrases, naming this
// unit, count; any other failure is a failure.
func systemdNotLoaded(out []byte, _ error) bool {
	for _, p := range []string{
		"Unit file " + systemdUnit + " does not exist",
		"Unit " + systemdUnit + " not loaded",
		"Unit " + systemdUnit + " not found",
	} {
		if bytes.Contains(out, []byte(p)) {
			return true
		}
	}
	return false
}

func exitStatusOf(err error) int {
	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) {
		return ec.ExitCode()
	}
	return -1
}

// runSteps runs steps in order and stops at the first that fails, with
// what failed.
func runSteps(ctx context.Context, e *Env, spec *serviceSpec, steps []serviceStep, res *ServiceResult) error {
	for _, st := range steps {
		res.Commands = append(res.Commands, st.argv)
		out, err := e.runCommand(ctx, st.argv)
		if err == nil || st.notLoadedOK && spec.notLoaded(out, err) {
			continue
		}
		return failf("%s failed: %v: %s", strings.Join(st.argv, " "), err, printable(strings.TrimSpace(string(out))))
	}
	return nil
}

func argvs(steps []serviceStep) [][]string {
	out := make([][]string, len(steps))
	for i, st := range steps {
		out[i] = st.argv
	}
	return out
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
	same := existed && old == spec.body
	if existed && !same && !spec.owns(old) {
		return failf("%s exists and hop did not write it; move it away first", path)
	}
	res.Notes = append(res.Notes, safef("the service runs %s by that path: run hop setup --service again after moving or upgrading hop", e.Executable))
	res.Notes = append(res.Notes, "if a hop daemon started some other way owns the vault, the service's daemon exits: run hop daemon stop, then hop setup --service again")

	// The file in place says nothing about what the service manager runs
	// (an earlier run may have failed after writing it, or the daemon may
	// have exited), so every run has it load the file and restart the
	// daemon. Only writing the file needs consent.
	if !same {
		fmt.Fprintf(e.Stderr, "hop will write %s, so the hop daemon runs from login, and then run:\n", oneLine(path))
		for _, c := range argvs(spec.install) {
			fmt.Fprintf(e.Stderr, "  %s\n", oneLine(strings.Join(c, " ")))
		}
		ok, err := confirm(e, yes, "Install the service?")
		if err != nil {
			return err
		}
		if !ok {
			return failf("no changes made")
		}
	}
	if spec.kind == "launchd" {
		// launchd opens the log itself, and wants its directory there.
		if _, err := safepath.EnsurePrivateDir(e.Paths.StateDir); err != nil {
			return failf("%v", err)
		}
	}
	if !same {
		if err := writeServiceFile(spec); err != nil {
			return err
		}
		res.Changed = true
		res.Notes = append(res.Notes, safef("%s is now mode 0700, as hop keeps the directories it writes to", spec.dir))
	}
	if err := runSteps(ctx, e, spec, spec.install, &res); err != nil {
		what := "wrote " + path
		if same {
			what = path + " is in place"
		}
		return failf("%s, but %v; run hop setup --service again to retry", what, err)
	}
	res.Active = true
	if asJSON {
		return printJSON(e, res)
	}
	if same {
		e.printf("the %s service is already installed: %s (%s)\n", spec.kind, oneLine(path), spec.active)
	} else {
		e.printf("installed the %s service: %s (%s)\n", spec.kind, oneLine(path), spec.active)
	}
	for _, n := range res.Notes {
		fmt.Fprintf(e.Stderr, "hop: note: %s\n", oneLine(n))
	}
	return nil
}

// uninstallService stops the service, then removes its file. The file
// goes only once the service manager has stopped it, so a failure leaves
// it in place and running again retries. With no file, it still stops a
// service the manager may have loaded.
func uninstallService(ctx context.Context, e *Env, spec *serviceSpec, yes, asJSON bool) error {
	path := spec.path()
	res := ServiceResult{Service: spec.kind, Path: path, Commands: [][]string{}}
	old, existed, err := readServiceFile(path)
	if err != nil {
		return err
	}
	if existed && !spec.owns(old) {
		return failf("%s was not written by hop setup --service; leaving it alone", path)
	}
	question := safef("Stop the %s service and remove %s?", spec.kind, path)
	if !existed {
		question = safef("There is no %s; stop the %s service in case it is still loaded?", path, spec.kind)
	}
	ok, err := confirm(e, yes, question)
	if err != nil {
		return err
	}
	if !ok {
		return failf("no changes made")
	}
	checked := path
	if existed {
		// The same checks as for writing: the directory is the user's, and
		// nobody else can swap the file hop removes. The file is read again
		// from the checked path before it goes.
		dir, err := safepath.EnsurePrivateDir(spec.dir)
		if err != nil {
			return failf("%v", err)
		}
		checked = filepath.Join(dir, spec.name)
		if old, existed, err = readServiceFile(checked); err != nil {
			return err
		}
		if !existed || !spec.owns(old) {
			return failf("%s changed while hop was removing it; leaving it alone", path)
		}
	}
	if err := runSteps(ctx, e, spec, spec.stop, &res); err != nil {
		if existed {
			return failf("%v; the service may still be running, so hop left %s in place; run hop setup --service --uninstall again to retry", err, path)
		}
		return failf("%v; the service may still be running; run hop setup --service --uninstall again to retry", err)
	}
	if !existed {
		if asJSON {
			return printJSON(e, res)
		}
		e.printf("no %s service is installed (%s), and none is running\n", spec.kind, oneLine(path))
		return nil
	}
	if err := os.Remove(checked); err != nil {
		return failf("%v", err)
	}
	res.Changed = true
	for _, c := range spec.reload {
		res.Commands = append(res.Commands, c)
		if out, err := e.runCommand(ctx, c); err != nil {
			// The service has stopped; the manager forgets the unit at
			// its next reload.
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
