package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/model/modeltest"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/tailscale"
)

// The kit file is written in full and fsynced, then linked into place and
// its directory fsynced, before showKit reports it saved.
func TestKitFileIsDurable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kit.txt")
	var synced []string
	kitSync = func(f *os.File) error {
		synced = append(synced, f.Name())
		return f.Sync()
	}
	t.Cleanup(func() { kitSync = func(f *os.File) error { return f.Sync() } })

	var out bytes.Buffer
	e := &Env{Stdout: &out, Stderr: &out}
	kit := store.Kit{AccountID: "acct", SecretKey: "H1-SECRET", RecoveryKey: "R1-RECOVERY"}
	if err := showKit(e, kit, path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != kit.Text() {
		t.Fatalf("kit file = %q, %v", b, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if len(synced) != 2 || !strings.HasPrefix(filepath.Base(synced[0]), ".hop-kit-") || synced[1] != dir {
		t.Errorf("synced %q, want the temp file and then %s", synced, dir)
	}
	if !strings.Contains(out.String(), "also written to "+path) {
		t.Errorf("output %q", out.String())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("left behind: %v", ents)
	}

	// An existing file is never replaced.
	if err := showKit(e, kit, path); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("second write: %v", err)
	}
	// A failed fsync is an error, and nothing is reported saved.
	kitSync = func(*os.File) error { return os.ErrInvalid }
	out.Reset()
	if err := showKit(e, kit, filepath.Join(dir, "other.txt")); err == nil || strings.Contains(out.String(), "also written") {
		t.Errorf("failed sync: %v, output %q", err, out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "other.txt")); err == nil {
		t.Error("a kit file whose fsync failed was linked into place")
	}
}

// A daemon that finds the vault owned by another process, with no daemon
// answering on the control socket, fails and says the vault is busy.
func TestDaemonWithTheVaultBusy(t *testing.T) {
	defer func(d time.Duration) { busyWait = d }(busyWait)
	busyWait = 100 * time.Millisecond
	base := shortTempDir(t)
	var stderr bytes.Buffer
	e := &Env{
		Stdout: &stderr, Stderr: &stderr,
		Paths:     daemon.Paths{RunDir: filepath.Join(base, "run")},
		OpenStore: func() (model.Store, error) { return nil, store.ErrVaultBusy },
	}
	err := runDaemon(context.Background(), e, nil)
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != exitVaultBusy || ee.msg != "the vault is busy (another hop process owns it)" {
		t.Fatalf("runDaemon: %v, want a failure saying the vault is busy", err)
	}
	if strings.Contains(stderr.String(), "already running") {
		t.Errorf("stderr %q", stderr.String())
	}
}

// A daemon that finds the vault owned by a daemon that answers on the
// control socket says it is already running and exits cleanly.
func TestDaemonWithTheVaultOwnedByARunningDaemon(t *testing.T) {
	base := shortTempDir(t)
	paths := daemon.Paths{
		RunDir:    filepath.Join(base, "run"),
		ConfigDir: filepath.Join(base, "home", ".ssh", "hop"),
		StateDir:  filepath.Join(base, "state"),
	}
	d, err := daemon.Start(daemon.Options{Paths: paths, Store: modeltest.New(), Version: "test", Tailscale: noTailscale{}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var stderr bytes.Buffer
	e := &Env{
		Stdout: &stderr, Stderr: &stderr, Paths: paths,
		OpenStore: func() (model.Store, error) { return nil, store.ErrVaultBusy },
	}
	if err := runDaemon(context.Background(), e, nil); err != nil {
		t.Fatalf("runDaemon: %v", err)
	}
	if !strings.Contains(stderr.String(), "hop daemon is already running") {
		t.Errorf("stderr %q", stderr.String())
	}
}

// shortTempDir is a temp dir short enough for unix socket paths.
func shortTempDir(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	return base
}

type noTailscale struct{}

func (noTailscale) Status(context.Context) (*tailscale.Status, error) {
	return tailscale.Unavailable("no tailscale in tests"), nil
}

// setKitMove replaces the no-replace rename and the link for one test.
func setKitMove(t *testing.T, rename, link func(string, string) error) {
	t.Helper()
	oldRename, oldLink := kitRename, kitLink
	t.Cleanup(func() { kitRename, kitLink = oldRename, oldLink })
	if rename != nil {
		kitRename = rename
	}
	if link != nil {
		kitLink = link
	}
}

func unsupportedRename(string, string) error { return errNoReplaceUnsupported }

// Round 2, finding B: whichever way the kit file is moved into place, an
// existing file is never replaced, even one that appears after the early
// check in hop init.
func TestKitFileNeverReplacesAFile(t *testing.T) {
	for _, tc := range []struct {
		name         string
		rename, link func(string, string) error
	}{
		{"atomic rename", nil, nil},
		{"hard link", unsupportedRename, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "kit.txt")
			// The destination appears between hop init's check and the move.
			race := func(move func(string, string) error) func(string, string) error {
				return func(oldpath, newpath string) error {
					if err := os.WriteFile(newpath, []byte("precious"), 0o600); err != nil {
						t.Fatal(err)
					}
					return move(oldpath, newpath)
				}
			}
			if tc.rename == nil {
				setKitMove(t, race(renameNoReplace), nil)
			} else {
				setKitMove(t, tc.rename, race(os.Link))
			}
			err := writeKitFile(path, []byte("kit"))
			if err == nil || !strings.Contains(err.Error(), "already exists") {
				t.Errorf("writeKitFile over a file that appeared: %v", err)
			}
			if b, _ := os.ReadFile(path); string(b) != "precious" {
				t.Errorf("the existing file now holds %q", b)
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 1 {
				t.Errorf("left behind: %v", ents)
			}
		})
	}
}

// Round 2, finding B: with neither an atomic no-replace rename nor hard
// links, no kit file is written and the error says what to do. Any other
// link error is returned as it is, with no fallback.
func TestKitFileWithoutAnAtomicMove(t *testing.T) {
	for _, tc := range []struct {
		name    string
		linkErr error
		want    string
	}{
		{"EPERM", syscall.EPERM, "leave out --kit-file and copy the kit from the screen"},
		{"ENOTSUP", syscall.ENOTSUP, "choose a --kit-file path on a filesystem that supports it"},
		{"ENOSYS", syscall.ENOSYS, "no kit file was written"},
		{"EIO", syscall.EIO, "input/output error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "kit.txt")
			setKitMove(t, unsupportedRename, func(oldpath, newpath string) error {
				return &os.LinkError{Op: "link", Old: oldpath, New: newpath, Err: tc.linkErr}
			})
			var out bytes.Buffer
			e := &Env{Stdout: &out, Stderr: &out}
			err := showKit(e, store.Kit{AccountID: "acct", SecretKey: "H1-SECRET", RecoveryKey: "R1-RECOVERY"}, path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want it to say %q", err, tc.want)
			}
			if strings.Contains(out.String(), "also written") {
				t.Errorf("reported saved: %q", out.String())
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 0 {
				t.Errorf("a kit file or temp file was written: %v", ents)
			}
		})
	}
}

var lastGroupLine = regexp.MustCompile(`(?m)^(Secret Key|Recovery Key): +(\S+)$`)

// Rev 15 §11: hop init with an unsealed device key file warns that the
// private keys and the Secret Key are stored unencrypted on disk; sealed,
// it does not.
func TestInitWarnsAboutAnUnsealedDeviceKeyFile(t *testing.T) {
	for _, sealed := range []bool{false, true} {
		t.Run(fmt.Sprintf("sealed=%v", sealed), func(t *testing.T) {
			dir := t.TempDir()
			var stdout, stderr bytes.Buffer
			answers := []string{"correct horse battery staple", "correct horse battery staple"}
			e := &Env{
				Stdout: &stdout, Stderr: &stderr, Home: dir,
				DataDir: filepath.Join(dir, "data"),
				Getenv: func(k string) string {
					if sealed && k == store.PassphraseEnv {
						return "device passphrase 1"
					}
					return ""
				},
				ReadPassword: func(p string) ([]byte, error) {
					if which, ok := strings.CutPrefix(p, "Type the last group of your "); ok {
						for _, m := range lastGroupLine.FindAllStringSubmatch(stdout.String(), -1) {
							if m[1] == strings.TrimSuffix(which, ": ") {
								return []byte(store.LastGroup(m[2])), nil
							}
						}
						return nil, errors.New("no kit printed")
					}
					if len(answers) == 0 {
						return nil, errors.New("unexpected prompt " + p)
					}
					a := answers[0]
					answers = answers[1:]
					return []byte(a), nil
				},
			}
			if err := runInit(context.Background(), e, []string{"--device-key-store=file"}); err != nil {
				t.Fatalf("hop init: %v\nstderr: %s", err, stderr.String())
			}
			keyFile := filepath.Join(dir, "data", "device.key")
			want := "warning: HOP_DEVICE_PASSPHRASE is not set, so this device's private keys and the Secret Key will be stored " +
				"unencrypted on disk in " + keyFile + ", protected only by its file permissions (0600)."
			wantStore := "Device key: file (unsealed: private keys on disk)."
			if sealed {
				if strings.Contains(stderr.String(), "unencrypted") || strings.Contains(stdout.String(), "unencrypted") {
					t.Errorf("sealed, but warned: %q", stderr.String())
				}
				wantStore = "Device key: file (sealed)."
			} else if !strings.Contains(stderr.String(), want) {
				t.Errorf("stderr %q\nwant it to contain %q", stderr.String(), want)
			}
			if !strings.Contains(stdout.String(), wantStore) {
				t.Errorf("stdout does not say %q:\n%s", wantStore, stdout.String())
			}
			if _, err := os.Stat(keyFile); err != nil {
				t.Error(err)
			}
		})
	}
}
