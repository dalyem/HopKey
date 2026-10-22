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
// false when HopKey's path is already the first argument of the first
// directive in the file: ssh keeps the first value it sees for most options,
// so anything read before HopKey's file (another directive, a Host or Match
// line that would scope an Include, another path on the same Include line)
// can override what the generated Host blocks say. Otherwise HopKey's path is
// taken out of wherever it appears, leaving the other arguments of that line
// where they were, and the include goes to the very top.
func ensureInclude(content, include string, same func(arg string) bool) (out string, changed bool) {
	lines := strings.Split(content, "\n")
	isOurs := func(sp argSpan) bool { return same(sp.val) }
	for _, l := range lines {
		spans := directiveSpans(l)
		if len(spans) == 0 {
			continue // blank or comment
		}
		// The first directive decides.
		if strings.EqualFold(spans[0].val, "include") && len(spans) > 1 && isOurs(spans[1]) {
			return content, false
		}
		break
	}

	var kept []string
	for _, l := range lines {
		spans := directiveSpans(l)
		if len(spans) < 2 || !strings.EqualFold(spans[0].val, "include") {
			kept = append(kept, l)
			continue
		}
		rest, removed, empty := withoutArgs(l, spans, isOurs)
		switch {
		case empty:
			// The line held nothing but HopKey's path.
		case removed:
			kept = append(kept, rest)
		default:
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

// withoutArgs removes the arguments of line (spans, from directiveSpans)
// that match drop, and the blanks that separated them, leaving every other
// word as it was written. empty reports that no argument was left.
func withoutArgs(line string, spans []argSpan, drop func(argSpan) bool) (out string, removed, empty bool) {
	var sb strings.Builder
	last, left := 0, 0
	for i, sp := range spans {
		if i == 0 {
			continue
		}
		if !drop(sp) {
			left++
			continue
		}
		removed = true
		sb.WriteString(line[last:sp.start])
		last = sp.end
		// Swallow the blanks after the word so the next one keeps its place.
		for last < len(line) && (line[last] == ' ' || line[last] == '\t') {
			last++
		}
	}
	if !removed {
		return line, false, false
	}
	if left == 0 {
		return "", true, true
	}
	sb.WriteString(line[last:])
	return strings.TrimRight(sb.String(), " \t"), true, false
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
		e.printf("%s already includes %s\n", oneLine(cfgPath), oneLine(filepath.Join(e.Paths.ConfigDir, "config")))
		return nil
	}

	fmt.Fprintf(e.Stderr, "hop will add %q at the top of %s", include, oneLine(cfgPath))
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
	e.printf("updated %s\n", oneLine(cfgPath))
	if b, ok := result["backup"]; ok {
		e.printf("backup: %s\n", oneLine(fmt.Sprint(b)))
	}
	e.printf("The hop daemon writes %s the first time you run a hop command.\n", oneLine(filepath.Join(e.Paths.ConfigDir, "config")))
	return nil
}
