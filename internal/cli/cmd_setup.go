package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// includeLine is the line hop setup puts at the top of ~/.ssh/config.
func includeLine(e *Env) string {
	p := filepath.Join(e.Paths.ConfigDir, "config")
	if p == filepath.Join(e.Home, ".ssh", "hop", "config") {
		return "Include ~/.ssh/hop/config"
	}
	if strings.ContainsAny(p, " \t\"\\") {
		p = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p) + `"`
	}
	return "Include " + p
}

// ensureInclude returns content with the include line at the top. changed is
// false when it is already there, before the first Host or Match line (an
// Include after one would only apply inside that block). A copy further down
// is removed.
func ensureInclude(content, include string, same func(arg string) bool) (out string, changed bool) {
	lines := strings.Split(content, "\n")
	firstBlock := len(lines)
	for i, l := range lines {
		if k, _ := splitDirective(l); k == "host" || k == "match" {
			firstBlock = i
			break
		}
	}
	isOurs := func(l string) bool {
		k, args := splitDirective(l)
		if k != "include" {
			return false
		}
		for _, a := range args {
			if same(a) {
				return true
			}
		}
		return false
	}
	present := false
	for i := 0; i < firstBlock; i++ {
		if isOurs(lines[i]) {
			present = true
		}
	}
	if present {
		return content, false
	}
	var kept []string
	for _, l := range lines {
		if !isOurs(l) {
			kept = append(kept, l)
		}
	}
	rest := strings.Join(kept, "\n")
	head := "# Added by hop setup: the hosts in your HopKey vault.\n" + include + "\n"
	if strings.TrimSpace(rest) != "" {
		head += "\n"
	}
	return head + strings.TrimLeft(rest, "\n"), true
}

func runSetup(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "setup", commands["setup"].usage)
	yes := fs.Bool("yes", false, "do not ask")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		fs.Usage()
		return failf("setup takes no arguments")
	}

	sshDir := filepath.Join(e.Home, ".ssh")
	cfgPath := filepath.Join(sshDir, "config")
	// A dotfiles manager often makes ~/.ssh/config a symlink. Edit what it
	// points at, so the link survives.
	target := cfgPath
	if real, err := filepath.EvalSymlinks(cfgPath); err == nil {
		target = real
	}
	var old []byte
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(target); err == nil {
		mode = fi.Mode().Perm()
		if old, err = os.ReadFile(target); err != nil {
			return failf("reading %s: %v", target, err)
		}
	} else if !os.IsNotExist(err) {
		return failf("%v", err)
	}

	include := includeLine(e)
	ours := map[string]bool{
		"~/.ssh/hop/config":                            true,
		filepath.Join(e.Home, ".ssh", "hop", "config"): true,
		filepath.Join(e.Paths.ConfigDir, "config"):     true,
	}
	updated, changed := ensureInclude(string(old), include, func(a string) bool { return ours[a] })
	result := map[string]any{"path": cfgPath, "include": include, "changed": changed}
	if !changed {
		if *asJSON {
			return printJSON(e, result)
		}
		e.printf("%s already includes %s\n", cfgPath, filepath.Join(e.Paths.ConfigDir, "config"))
		return nil
	}

	fmt.Fprintf(e.Stderr, "hop will add %q at the top of %s", include, cfgPath)
	if len(old) > 0 {
		fmt.Fprintf(e.Stderr, " (a backup is saved first)")
	}
	fmt.Fprintln(e.Stderr)
	ok, err := confirm(e, *yes, "Go ahead?")
	if err != nil {
		return err
	}
	if !ok {
		return failf("no changes made")
	}

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return failf("%v", err)
	}
	if len(old) > 0 {
		backup := fmt.Sprintf("%s.hop-backup-%s", target, time.Now().Format("20060102-150405"))
		if err := os.WriteFile(backup, old, 0o600); err != nil {
			return failf("writing the backup: %v", err)
		}
		result["backup"] = backup
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".config.hop.tmp*")
	if err != nil {
		return failf("%v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(updated); err != nil {
		tmp.Close()
		return failf("%v", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return failf("%v", err)
	}
	if err := tmp.Close(); err != nil {
		return failf("%v", err)
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		return failf("%v", err)
	}
	if *asJSON {
		return printJSON(e, result)
	}
	e.printf("updated %s\n", cfgPath)
	if b, ok := result["backup"]; ok {
		e.printf("backup: %s\n", b)
	}
	e.printf("The hop daemon writes %s the first time you run a hop command.\n", filepath.Join(e.Paths.ConfigDir, "config"))
	return nil
}
