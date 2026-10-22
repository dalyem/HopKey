package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

// Round 3, finding 3: one 2-second deadline covers the dial and the status
// request. A daemon that answers status only after 2.5s counts as not
// answering, so the vault is reported busy.
func TestDaemonThatAnswersTooLateIsBusy(t *testing.T) {
	if busyWait != 2*time.Second {
		t.Fatalf("busyWait = %v, want 2s", busyWait)
	}
	base := shortTempDir(t)
	paths := daemon.Paths{RunDir: filepath.Join(base, "run")}
	if err := os.MkdirAll(paths.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", paths.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				sc := bufio.NewScanner(conn)
				for sc.Scan() {
					time.Sleep(2500 * time.Millisecond)
					if _, err := conn.Write([]byte(`{"ok":true,"result":{}}` + "\n")); err != nil {
						return
					}
				}
			}()
		}
	}()

	var stderr bytes.Buffer
	e := &Env{
		Stdout: &stderr, Stderr: &stderr, Paths: paths,
		OpenStore: func() (model.Store, error) { return nil, store.ErrVaultBusy },
	}
	start := time.Now()
	err = runDaemon(context.Background(), e, nil)
	elapsed := time.Since(start)
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != ExitFailure || ee.msg != "the vault is busy (another hop process owns it)" {
		t.Fatalf("runDaemon: %v (stderr %q), want a failure saying the vault is busy", err, stderr.String())
	}
	if strings.Contains(stderr.String(), "already running") {
		t.Errorf("stderr %q", stderr.String())
	}
	if elapsed > 2400*time.Millisecond {
		t.Errorf("the probe took %v, want it to give up after 2s", elapsed)
	}
}

// Round 3, note 1: a link refused with EPERM is treated as unsupported, but
// the message keeps the error, so a real permission problem shows.
func TestKitFileLinkErrorIsKept(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kit.txt")
	setKitMove(t, unsupportedRename, func(oldpath, newpath string) error {
		return &os.LinkError{Op: "link", Old: oldpath, New: "kit\x1b[2Jfile", Err: syscall.EPERM}
	})
	err := writeKitFile(path, []byte("kit"))
	if err == nil {
		t.Fatal("a refused link wrote the kit file")
	}
	msg := err.Error()
	if !strings.Contains(msg, "operation not permitted") || !strings.Contains(msg, "no kit file was written") {
		t.Errorf("error %q, want it to keep the link error", msg)
	}
	if strings.ContainsRune(msg, '\x1b') {
		t.Errorf("error %q carries a control character", msg)
	}
}
