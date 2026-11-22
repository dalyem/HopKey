//go:build hopdev

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// daemonPIDs returns the pids of running `<bin> daemon` processes, read from
// /proc. ok is false where there is no /proc to read.
func daemonPIDs(bin string) (pids []int, ok bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		if args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00"); len(args) == 2 && args[0] == bin && args[1] == "daemon" {
			pids = append(pids, pid)
		}
	}
	return pids, true
}

// TestSimultaneousAutostartsLeaveOneDaemon races two hop commands that both
// find no daemon. Each starts one; the run directory's lock lets only one
// stay, and both commands succeed against it.
func TestSimultaneousAutostartsLeaveOneDaemon(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "hop")
	cmd := exec.Command(goTool(t), "build", "-tags", "hopdev", "-o", bin, "github.com/dalyem/hopkey/cmd/hop")
	cmd.Dir = "../.."
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	if _, ok := daemonPIDs(bin); !ok {
		t.Skip("no /proc to count daemon processes")
	}

	base, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	for _, d := range []string{"home", "run", "state"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(),
		"HOME="+filepath.Join(base, "home"),
		"XDG_RUNTIME_DIR="+filepath.Join(base, "run"),
		"XDG_STATE_HOME="+filepath.Join(base, "state"),
		"HOPKEY_DEVSTORE="+filepath.Join(base, "state", "dev.json"),
	)
	hop := func(args ...string) (code int, stdout, stderr string) {
		var so, se bytes.Buffer
		c := exec.Command(bin, args...)
		c.Env, c.Stdout, c.Stderr = env, &so, &se
		err := c.Run()
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Errorf("hop %v: %v", args, err)
			code = -1
		}
		return code, so.String(), se.String()
	}
	t.Cleanup(func() { hop("daemon", "stop") })

	for round := 1; round <= 5; round++ {
		if code, _, _ := hop("daemon", "stop"); code != 0 {
			t.Fatalf("round %d: stop: %d", round, code)
		}
		waitFor(t, "the previous daemon to exit", func() bool { p, _ := daemonPIDs(bin); return len(p) == 0 })

		var wg sync.WaitGroup
		type result struct {
			code           int
			stdout, stderr string
		}
		results := make([]result, 2)
		start := make(chan struct{})
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				c, so, se := hop("ls", "--json")
				results[i] = result{c, so, se}
			}()
		}
		close(start)
		wg.Wait()
		for i, r := range results {
			if r.code != 0 {
				t.Errorf("round %d: command %d exited %d: %s", round, i, r.code, r.stderr)
			}
		}

		// The loser of the race exits at once; what is left is one daemon,
		// and it stays one.
		waitFor(t, "a single daemon", func() bool { p, _ := daemonPIDs(bin); return len(p) == 1 })
		time.Sleep(200 * time.Millisecond)
		pids, _ := daemonPIDs(bin)
		if len(pids) != 1 {
			t.Fatalf("round %d: %d daemons running: %v", round, len(pids), pids)
		}
		code, out, _ := hop("status", "--json")
		var st struct {
			PID int `json:"pid"`
		}
		if err := json.Unmarshal([]byte(out), &st); code != 0 || err != nil || st.PID != pids[0] {
			t.Errorf("round %d: status does not report the surviving daemon %d: %d %s (%v)", round, pids[0], code, out, err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(base, "state", "hop", "daemon.log")); err != nil {
		t.Error(err)
	} else {
		t.Logf("daemon.log: %d daemons serving, %d turned away as already running over 5 rounds",
			strings.Count(string(b), "serving agent"), strings.Count(string(b), "already running"))
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
