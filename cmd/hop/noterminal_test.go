package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Without a terminal on stdin, hop init says it needs one. It used to
// start, then fail on its first prompt with "inappropriate ioctl for device",
// because main always gave the commands a ReadPassword.
func TestInitWithoutATerminalSaysSo(t *testing.T) {
	if testing.Short() {
		t.Skip("builds hop")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "hop")
	build := exec.Command(goTool(t), "build", "-o", bin, "github.com/dalyem/hopkey/cmd/hop")
	build.Dir = "../.." // the module root
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}

	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "init")
	cmd.Env = []string{
		"HOME=" + home, "PATH=" + os.Getenv("PATH"),
		"XDG_RUNTIME_DIR=" + filepath.Join(dir, "run"), "XDG_STATE_HOME=" + filepath.Join(dir, "state"),
		"XDG_DATA_HOME=" + filepath.Join(dir, "data"), "XDG_CONFIG_HOME=" + filepath.Join(dir, "config"),
	}
	cmd.Stdin = strings.NewReader("")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 255 {
		t.Fatalf("hop init: %v, want exit 255\n%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "hop init needs a terminal") || strings.Contains(stderr.String(), "ioctl") {
		t.Errorf("stderr = %q", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "data")); err == nil {
		t.Error("hop init created a data directory")
	}
}
