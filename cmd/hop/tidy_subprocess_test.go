//go:build linux && !hopdev

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/store"
)

// The real hop, on a terminal of its own, on a device whose key file is
// sealed with a typed passphrase: Ctrl-C at a prompt of a command that holds
// the vault, and the plain message of a device with no vault.
func TestSubprocessCtrlCAtAPromptLeavesTheVaultAsItWas(t *testing.T) {
	if _, err := os.Stat("/proc/self/environ"); err != nil {
		t.Skip("no /proc to read a daemon's environment from")
	}
	hopBin, serverBin := buildSubBinaries(t)
	base, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	certFile, keyFile, pool := writeTestCert(t, base)
	origin := startServer(t, serverBin, base, certFile, keyFile, pool)
	inviteCode := strings.TrimSpace(mustRun(t, serverBin, "invite", subEmail, "--data", filepath.Join(base, "server")))
	a := newSubHome(t, hopBin, base, "a", certFile)
	const devicePass = "a typed device passphrase"
	asksDevicePass := "Device passphrase (this machine's key file, not your master password): "

	p := a.startPTY(t, nil, "init", "--device-key-store", "file")
	p.expect(t, "Protect it with a device passphrase? (recommended) [Y/n] ")
	p.send("y")
	p.expect(t, "New device passphrase: ")
	p.send(devicePass)
	p.expect(t, "Repeat the device passphrase: ")
	p.send(devicePass)
	p.expect(t, "Master password: ")
	p.send(subPassword)
	p.expect(t, "Repeat it: ")
	p.send(subPassword)
	out := p.expect(t, "Type the last group of your Secret Key: ")
	sk, rk := subKitKeys(t, out)
	p.send(store.LastGroup(sk))
	p.expect(t, "Type the last group of your Recovery Key: ")
	p.send(store.LastGroup(rk))
	if code := p.wait(t, 60*time.Second); code != 0 {
		t.Fatalf("hop init: exit %d\n%s", code, p.output())
	}
	secrets := []string{"HOP_PASSWORD=" + subPassword, "HOP_SECRET_KEY=" + sk}
	a.must(t, nil, "add", "web", "--address", "203.0.113.10", "--user", "deploy")
	p = a.startPTY(t, secrets, "auth", "signup", "--server", origin, "--email", subEmail, "--code", inviteCode)
	p.expect(t, asksDevicePass)
	p.send(devicePass)
	if code := p.wait(t, 60*time.Second); code != 0 {
		t.Fatalf("hop auth signup: exit %d\n%s", code, p.output())
	}

	locked := func() bool {
		var st struct {
			Vault *struct {
				Locked bool `json:"locked"`
			} `json:"vault"`
		}
		subDecode(t, a.must(t, nil, "status", "--json"), &st)
		if st.Vault == nil {
			t.Fatal("hop status has no vault")
		}
		return st.Vault.Locked
	}
	interruptRotate := func() string {
		before := a.daemonPID(t)
		p := a.startPTY(t, secrets, "auth", "rotate")
		p.expect(t, asksDevicePass)
		p.send(devicePass)
		p.expect(t, "Enter keeps only this device): ")
		if err := p.cmd.Process.Signal(syscall.SIGINT); err != nil {
			t.Fatal(err)
		}
		if code := p.wait(t, 30*time.Second); code != 130 {
			t.Errorf("hop auth rotate after SIGINT: exit %d; want 130\n%s", code, p.output())
		}
		waitUntil(t, 30*time.Second, "the daemon to run again", func() bool { pid := a.daemonPID(t); return pid != 0 && pid != before })
		return p.output()
	}

	// Open before: open after, with no passphrase typed again.
	text := interruptRotate()
	if locked() {
		t.Error("the vault was open before Ctrl-C at the prompt and is locked after it")
	}
	if !strings.Contains(text, "hop: interrupted") {
		t.Errorf("the Ctrl-C text:\n%s", text)
	}
	a.checkNoPassphrase(t, devicePass)

	// Locked before: locked after.
	a.must(t, nil, "lock")
	interruptRotate()
	if !locked() {
		t.Error("the vault was locked before Ctrl-C at the prompt and is open after it")
	}

	// A device with no vault says so in plain words, not with the daemon's log.
	a.must(t, nil, "auth", "logout", "--local-only", "--yes")
	code, _, stderr := a.hop(t, nil, "ls")
	if code == 0 || !strings.Contains(stderr, "there is no vault on this device") || strings.Contains(stderr, "exited as it started") || strings.Contains(stderr, "daemon.log") {
		t.Errorf("hop ls with no vault: exit %d, %q", code, stderr)
	}
}
