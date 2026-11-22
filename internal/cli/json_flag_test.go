package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/store"
)

// "Every command takes --json" holds for the commands below, which used to
// refuse it with "flag provided but not defined: -json".

func TestInitJSON(t *testing.T) {
	keyring.MockInit()
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	kitFile := filepath.Join(base, "kit.txt")
	var so, se bytes.Buffer
	kitLine := regexp.MustCompile(`(?m)^(Secret Key|Recovery Key): +(\S+)$`)
	env := &cli.Env{
		Stdin: strings.NewReader(""), Stdout: &so, Stderr: &se,
		Getenv: func(string) string { return "" },
		Home:   filepath.Join(base, "home"), DataDir: dataDir, Keyring: store.OSKeyring{},
		Paths: daemon.Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg"), StateDir: filepath.Join(base, "state")},
		ReadPassword: func(p string) ([]byte, error) {
			if strings.HasPrefix(p, "Type the last group of your ") {
				// With --json the kit is on stderr, for the person at the terminal.
				which := strings.TrimSuffix(strings.TrimPrefix(p, "Type the last group of your "), ": ")
				for _, m := range kitLine.FindAllStringSubmatch(se.String(), -1) {
					if m[1] == which {
						return []byte(store.LastGroup(m[2])), nil
					}
				}
				return nil, errors.New("no kit on stderr")
			}
			return []byte("a master password"), nil
		},
	}
	if code := cli.Run(context.Background(), []string{"init", "--json", "--kit-file", kitFile}, env); code != 0 {
		t.Fatalf("hop init --json: exit %d\nstdout: %s\nstderr: %s", code, so.String(), se.String())
	}
	var rep struct {
		DataDir        string `json:"data_dir"`
		DeviceKeyStore string `json:"device_key_store"`
		KitFile        string `json:"kit_file"`
	}
	if err := json.Unmarshal(so.Bytes(), &rep); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, so.String())
	}
	if rep.DataDir != dataDir || rep.KitFile != kitFile || rep.DeviceKeyStore == "" {
		t.Errorf("report = %+v", rep)
	}
	if strings.Contains(so.String(), "Emergency Kit") || !strings.Contains(se.String(), "Emergency Kit") {
		t.Errorf("the kit must be on stderr, not in the JSON on stdout:\nstdout: %s", so.String())
	}
}

func TestMCPInstallJSON(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "hop")
	run := func(args ...string) (int, string, string) {
		var so, se bytes.Buffer
		env := &cli.Env{
			Stdout: &so, Stderr: &se, Getenv: func(string) string { return "" }, Executable: exe,
			RunCommand: func(context.Context, string, ...string) ([]byte, error) { return []byte("Added\n"), nil },
		}
		return cli.Run(context.Background(), append([]string{"mcp", "install", "--json"}, args...), env), so.String(), se.String()
	}
	type report struct {
		Client     string `json:"client"`
		Registered bool   `json:"registered"`
		Server     struct {
			Command string
			Args    []string
		} `json:"server"`
		Commands map[string]string `json:"commands"`
	}

	code, stdout, stderr := run()
	var r report
	if err := json.Unmarshal([]byte(stdout), &r); code != 0 || err != nil {
		t.Fatalf("print: exit %d, %v\nstdout: %s\nstderr: %s", code, err, stdout, stderr)
	}
	if r.Client != "print" || r.Registered || r.Server.Command != exe || len(r.Server.Args) != 1 || r.Server.Args[0] != "mcp" ||
		!strings.Contains(r.Commands["claude"], "claude mcp add") || !strings.Contains(r.Commands["codex"], "codex mcp add") {
		t.Errorf("print report = %+v", r)
	}

	code, stdout, stderr = run("--client", "claude", "--read-only")
	r = report{}
	if err := json.Unmarshal([]byte(stdout), &r); code != 0 || err != nil {
		t.Fatalf("claude: exit %d, %v\nstdout: %s\nstderr: %s", code, err, stdout, stderr)
	}
	if r.Client != "claude" || !r.Registered || len(r.Server.Args) != 2 || r.Server.Args[1] != "--read-only" {
		t.Errorf("claude report = %+v", r)
	}
}

func TestDaemonStopJSON(t *testing.T) {
	base := t.TempDir()
	var so, se bytes.Buffer
	env := &cli.Env{
		Stdout: &so, Stderr: &se, Getenv: func(string) string { return "" },
		Paths: daemon.Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg"), StateDir: filepath.Join(base, "state")},
	}
	if code := cli.Run(context.Background(), []string{"daemon", "stop", "--json"}, env); code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, so.String(), se.String())
	}
	var r struct {
		WasRunning bool `json:"was_running"`
	}
	if err := json.Unmarshal(so.Bytes(), &r); err != nil || r.WasRunning {
		t.Errorf("report = %+v, %v\n%s", r, err, so.String())
	}
}
