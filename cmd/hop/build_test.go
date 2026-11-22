package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// devMarker is devstore.Marker. The devstore package has no code without the
// hopdev tag, so the test cannot import the constant; it repeats the text.
const devMarker = "plaintext, development only"

func goTool(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	p := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("cannot find the go tool: %v", err)
	}
	return p
}

func build(t *testing.T, tags string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "hop")
	args := []string{"build", "-o", out}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, "github.com/dalyem/hopkey/cmd/hop")
	cmd := exec.Command(goTool(t), args...)
	cmd.Dir = "../.." // the module root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func deps(t *testing.T, tags string) string {
	t.Helper()
	args := []string{"list", "-deps", "-f", "{{.ImportPath}}"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, "github.com/dalyem/hopkey/cmd/hop")
	cmd := exec.Command(goTool(t), args...)
	cmd.Dir = "../.."
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("go %s: %v", strings.Join(args, " "), err)
	}
	return string(b)
}

// The development store keeps private keys in a plaintext file. It must not
// reach a release binary by accident.
func TestNormalBuildHasNoDevStore(t *testing.T) {
	if testing.Short() {
		t.Skip("builds two binaries")
	}
	const pkg = "internal/model/devstore"

	normal, dev := build(t, ""), build(t, "hopdev")

	// The check can see the dev store when it is there.
	if !bytes.Contains(dev, []byte(devMarker)) || !strings.Contains(deps(t, "hopdev"), pkg) {
		t.Fatal("the hopdev build does not contain the dev store, so this test proves nothing")
	}
	if bytes.Contains(normal, []byte(devMarker)) {
		t.Error("the normal build contains the dev store's text")
	}
	if strings.Contains(deps(t, ""), pkg) {
		t.Error("the normal build links the devstore package")
	}
	if bytes.Contains(normal, []byte("HOPKEY_DEVSTORE")) {
		t.Error("the normal build reads HOPKEY_DEVSTORE")
	}
}
