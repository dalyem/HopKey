//go:build hopdev

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAutostartAndDevStore builds the real hop binary with the dev store and
// runs it: the first command that needs the daemon starts it, the daemon keeps
// running after the command exits, state survives a daemon restart, and
// `hop daemon stop` stops it.
func TestAutostartAndDevStore(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "hop")
	cmd := exec.Command(goTool(t), "build", "-tags", "hopdev", "-o", bin, "github.com/dalyem/hopkey/cmd/hop")
	cmd.Dir = "../.."
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}

	base, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	env := append(os.Environ(),
		"HOME="+filepath.Join(base, "home"),
		"XDG_RUNTIME_DIR="+filepath.Join(base, "run"),
		"XDG_STATE_HOME="+filepath.Join(base, "state"),
		"HOPKEY_DEVSTORE="+filepath.Join(base, "state", "dev.json"),
	)
	if err := os.MkdirAll(filepath.Join(base, "run"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	hop := func(args ...string) (int, string, string) {
		t.Helper()
		var so, se bytes.Buffer
		c := exec.Command(bin, args...)
		c.Env = env
		c.Stdout, c.Stderr = &so, &se
		err := c.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("hop %v: %v", args, err)
		}
		return code, so.String(), se.String()
	}
	t.Cleanup(func() { hop("daemon", "stop") })

	if code, out, _ := hop("status"); code != 255 || !strings.Contains(out, "not running") {
		t.Errorf("status before anything runs: code=%d %q (status must not start the daemon)", code, out)
	}
	if code, _, stderr := hop("add", "web-1", "--address", "127.0.0.1", "--user", "deploy"); code != 0 {
		t.Fatalf("add (autostart): %d %s\n%s", code, stderr, logOf(base))
	}
	code, out, _ := hop("status", "--json")
	var st struct {
		Running bool `json:"running"`
		Hosts   int  `json:"hosts"`
		PID     int  `json:"pid"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil || code != 0 || !st.Running || st.Hosts != 1 || st.PID == 0 {
		t.Fatalf("status after add: code=%d %s (%v)", code, out, err)
	}
	if code, out, _ := hop("ls", "--json"); code != 0 || !strings.Contains(out, `"web-1"`) {
		t.Errorf("ls: %d %s", code, out)
	}

	// The dev store file is private and the daemon logged to the state dir.
	devPath := filepath.Join(base, "state", "dev.json")
	if fi, err := os.Stat(devPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("dev store: %v %v", fi, err)
	}
	if b, err := os.ReadFile(filepath.Join(base, "state", "hop", "daemon.log")); err != nil || !strings.Contains(string(b), "serving agent") {
		t.Errorf("daemon log: %q %v", b, err)
	}

	if code, out, _ := hop("daemon", "stop"); code != 0 || !strings.Contains(out, "stopped") {
		t.Errorf("daemon stop: %d %q", code, out)
	}
	if code, _, _ := hop("status"); code != 255 {
		t.Errorf("status after stop: %d", code)
	}
	// A new daemon finds the same hosts.
	if code, out, _ := hop("ls", "--json"); code != 0 || !strings.Contains(out, `"web-1"`) {
		t.Errorf("ls after restart: %d %s", code, out)
	}
	// And the generated ssh config is where the Include points.
	cfg, err := os.ReadFile(filepath.Join(base, "home", ".ssh", "hop", "config"))
	if err != nil {
		t.Fatalf("no generated config: %v", err)
	}
	_ = cfg // web-1 has no key yet, so it has no Host block; the file existing is the point
}

func logOf(base string) string {
	b, _ := os.ReadFile(filepath.Join(base, "state", "hop", "daemon.log"))
	return string(b)
}
