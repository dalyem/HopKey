package cli_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/store"
)

// vaultE2E drives the real CLI against the encrypted store: hop init
// through the CLI, a daemon in this process over store.Open, the system ssh
// client and an in-process ssh server. The keychain is go-keyring's mock.
type vaultE2E struct {
	base    string
	home    string
	dataDir string
	paths   daemon.Paths
	daemon  *daemon.Daemon
	store   *store.Store

	answers []string      // the next answers to password prompts
	stdout  *bytes.Buffer // of the running command, for type-back prompts
	prompts []string
}

var lastGroupLine = regexp.MustCompile(`(?m)^(Secret Key|Recovery Key): +(\S+)$`)

// prompt answers the CLI's password prompts from the queue, and type-back
// prompts from the kit the command has printed so far.
func (v *vaultE2E) prompt(t *testing.T) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		v.prompts = append(v.prompts, p)
		if strings.HasPrefix(p, "Type the last group of your ") {
			which := strings.TrimSuffix(strings.TrimPrefix(p, "Type the last group of your "), ": ")
			var key string
			for _, m := range lastGroupLine.FindAllStringSubmatch(v.stdout.String(), -1) {
				if m[1] == which {
					key = m[2] // the last kit printed wins
				}
			}
			if key == "" {
				t.Errorf("type-back prompt %q before a kit was printed", p)
				return nil, errors.New("no kit")
			}
			return []byte(store.LastGroup(key)), nil
		}
		if len(v.answers) == 0 {
			t.Errorf("unexpected prompt %q", p)
			return nil, errors.New("no answer")
		}
		a := v.answers[0]
		v.answers = v.answers[1:]
		return []byte(a), nil
	}
}

func (v *vaultE2E) hop(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var so, se bytes.Buffer
	v.stdout = &so
	env := &cli.Env{
		Stdin: strings.NewReader(""), Stdout: &so, Stderr: &se,
		Getenv: func(string) string { return "" },
		Home:   v.home, Paths: v.paths, DataDir: v.dataDir, Keyring: store.OSKeyring{},
		ReadPassword: v.prompt(t), SSHProbeEnv: passwdShimEnv(),
		StartDaemon: func() error {
			t.Error("the CLI tried to start a daemon")
			return errors.New("unexpected daemon start")
		},
		DialTimeout: 5 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	code = cli.Run(ctx, args, env)
	if len(v.answers) != 0 {
		t.Errorf("hop %v left answers unused: %d", args, len(v.answers))
		v.answers = nil
	}
	return code, so.String(), se.String()
}

func (v *vaultE2E) startDaemon(t *testing.T) {
	t.Helper()
	s, err := store.Open(context.Background(), store.Config{DataDir: v.dataDir})
	if err != nil {
		t.Fatal(err)
	}
	d, err := daemon.Start(daemon.Options{Paths: v.paths, Store: s, Version: "test", Tailscale: noTailscale{}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	v.daemon, v.store = d, s
}

func (v *vaultE2E) restartDaemon(t *testing.T) {
	t.Helper()
	if err := v.daemon.Close(); err != nil {
		t.Fatal(err)
	}
	v.startDaemon(t)
}

// redactKit replaces the secret parts of a printed kit.
func redactKit(s string) string {
	return lastGroupLine.ReplaceAllStringFunc(s, func(line string) string {
		m := lastGroupLine.FindStringSubmatch(line)
		return m[1] + ": " + m[2][:3] + strings.Repeat("x", len(m[2])-3)
	})
}

func TestVaultEndToEnd(t *testing.T) {
	requireSSH(t)
	keyring.MockInit()
	base, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	v := &vaultE2E{
		base: base, home: filepath.Join(base, "home"), dataDir: filepath.Join(base, "data"),
		paths: daemon.Paths{
			RunDir:    filepath.Join(base, "run"),
			ConfigDir: filepath.Join(base, "home", ".ssh", "hop"),
			StateDir:  filepath.Join(base, "state"),
		},
	}
	t.Cleanup(func() {
		if v.daemon != nil {
			v.daemon.Close()
		}
	})

	// A real key in a file, as a user would have it.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(base, "id_ed25519")
	filePEM := pem.EncodeToMemory(block)
	if err := os.WriteFile(keyFile, filePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	srv := startSSHServer(t, signer.PublicKey())
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(srv.hostKey)))

	const password, newPassword = "first master password", "second master password"
	const hostName, alias = "vault-web-host", "vault-alias-1"

	// hop init.
	kitFile := filepath.Join(base, "kit.txt")
	v.answers = []string{password, password}
	code, stdout, stderr := v.hop(t, "init", "--kit-file", kitFile)
	if code != 0 {
		t.Fatalf("hop init: exit %d\n%s\n%s", code, stdout, stderr)
	}
	t.Logf("hop init (secrets redacted):\n%s", redactKit(stdout))
	if !strings.Contains(stdout, "HopKey Emergency Kit") || !strings.Contains(stdout, "Keep this offline") {
		t.Errorf("no kit printed:\n%s", stdout)
	}
	if fi, err := os.Stat(kitFile); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("kit file: %v %v", fi, err)
	}
	firstKit := lastGroupLine.FindAllStringSubmatch(stdout, -1)
	// A second init is refused before it asks for anything.
	if code, _, stderr := v.hop(t, "init"); code != 255 || !strings.Contains(stderr, "already exists") {
		t.Errorf("second hop init: exit %d, %q", code, stderr)
	}

	v.startDaemon(t)
	if code, stdout, stderr := v.hop(t, "key", "add", keyFile, "--name", "vault-deploy-key"); code != 0 {
		t.Fatalf("hop key add: %d\n%s%s", code, stdout, stderr)
	}
	if code, stdout, stderr := v.hop(t, "add", hostName, "--address", "127.0.0.1", "--port", strconv.Itoa(srv.port),
		"--user", "deploy", "--key", "vault-deploy-key", "--alias", alias, "--host-key", pin); code != 0 {
		t.Fatalf("hop add: %d\n%s%s", code, stdout, stderr)
	}
	snap, err := v.store.Snapshot(context.Background())
	if err != nil || len(snap.Keys) != 1 {
		t.Fatalf("snapshot: %v %+v", err, snap)
	}
	storedPEM := snap.Keys[0].PrivateKey

	// The vault survives a daemon restart, and ssh works through it.
	v.restartDaemon(t)
	exec := func(want int) (string, string) {
		t.Helper()
		code, stdout, stderr := v.hop(t, "exec", alias, "--", "echo", "ok")
		if code != want {
			t.Fatalf("hop exec: exit %d, want %d\nstdout %q\nstderr %q", code, want, stdout, stderr)
		}
		return stdout, stderr
	}
	if out, _ := exec(0); out != "ok\n" {
		t.Errorf("hop exec stdout %q", out)
	}
	code, stdout, _ = v.hop(t, "status")
	t.Logf("hop status:\n%s", stdout)
	for _, want := range []string{"vault:        unlocked", "device key:   keychain", "log head:     seq 2 ", "keys:         1 in the vault, 1 in the agent"} {
		if code != 0 || !strings.Contains(stdout, want) {
			t.Errorf("hop status lacks %q (exit %d)", want, code)
		}
	}

	// hop lock: secrets gone, agent empty, exec refused.
	if code, _, stderr := v.hop(t, "lock"); code != 0 {
		t.Fatalf("hop lock: %d %s", code, stderr)
	}
	if _, stderr := exec(255); !strings.Contains(stderr, "vault is locked") {
		t.Errorf("exec while locked: %q", stderr)
	}
	code, stdout, _ = v.hop(t, "status")
	t.Logf("hop status while locked:\n%s", stdout)
	if !strings.Contains(stdout, "vault:        locked") || !strings.Contains(stdout, "0 in the agent") {
		t.Errorf("status while locked:\n%s", stdout)
	}
	if code, _, stderr := v.hop(t, "unlock"); code != 0 {
		t.Fatalf("hop unlock: %d %s", code, stderr)
	}
	exec(0)

	// hop passwd: a checkpoint, a new kit typed back.
	v.answers = []string{password, newPassword, newPassword}
	code, stdout, stderr = v.hop(t, "passwd")
	if code != 0 {
		t.Fatalf("hop passwd: %d\n%s\n%s", code, stdout, stderr)
	}
	t.Logf("hop passwd (secrets redacted):\n%s", redactKit(stdout))
	secondKit := lastGroupLine.FindAllStringSubmatch(stdout, -1)
	if len(secondKit) != 2 || len(firstKit) != 2 || secondKit[0][2] == firstKit[0][2] || secondKit[1][2] == firstKit[1][2] {
		t.Errorf("the kit did not change: %v -> %v", len(firstKit), len(secondKit))
	}
	exec(0)

	// After a restart, the old password fails and the new one works.
	v.restartDaemon(t)
	v.answers = []string{password}
	if code, _, stderr := v.hop(t, "unlock", "--password"); code != 255 || !strings.Contains(stderr, "wrong master password") {
		t.Errorf("unlock with the old password: exit %d %q", code, stderr)
	}
	v.answers = []string{newPassword}
	if code, stdout, stderr := v.hop(t, "unlock", "--password"); code != 0 {
		t.Fatalf("unlock with the new password: exit %d %s %s", code, stdout, stderr)
	}
	exec(0)
	// The new device key it stored opens the vault on the next start.
	v.restartDaemon(t)
	exec(0)
	code, stdout, _ = v.hop(t, "status")
	t.Logf("hop status at the end:\n%s", stdout)

	// Nothing secret is on disk under the data directory. The kit file
	// hop init wrote on request (kitFile, outside it) is the one place the
	// Secret Key and Recovery Key are meant to be in the clear.
	needles := []string{hostName, alias, "127.0.0.1", "vault-deploy-key", password, newPassword}
	for _, kit := range [][][]string{firstKit, secondKit} {
		for _, m := range kit {
			needles = append(needles, m[2])
		}
	}
	for _, p := range []string{storedPEM, string(filePEM)} {
		lines := strings.Split(strings.TrimSpace(p), "\n")
		for _, l := range lines[2 : len(lines)-1] {
			if len(l) >= 32 {
				needles = append(needles, l)
			}
		}
	}
	files := 0
	err = filepath.WalkDir(v.dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files++
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range needles {
			if bytes.Contains(b, []byte(n)) {
				t.Errorf("%s contains %q", path, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning %s: %v", v.dataDir, err)
	}
	t.Logf("scanned %d files under %s for %d strings", files, v.dataDir, len(needles))
	if files < 10 {
		t.Errorf("only %d files under the data directory", files)
	}
}
