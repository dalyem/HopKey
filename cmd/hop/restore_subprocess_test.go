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

// subLocked reports whether h's daemon has the vault locked.
func (h *subHome) subLocked(t *testing.T) bool {
	t.Helper()
	var st struct {
		Vault *struct {
			Locked bool `json:"locked"`
		} `json:"vault"`
	}
	subDecode(t, h.must(t, nil, "status", "--json"), &st)
	if st.Vault == nil {
		t.Fatalf("%s: hop status has no vault", h.name)
	}
	return st.Vault.Locked
}

// subInit makes a local vault on h with its device key in a file, sealed
// with pass, or unsealed when pass is empty.
func subInit(t *testing.T, h *subHome, pass string) []string {
	t.Helper()
	p := h.startPTY(t, nil, "init", "--device-key-store", "file")
	p.expect(t, "Protect it with a device passphrase? (recommended) [Y/n] ")
	if pass == "" {
		p.send("n")
	} else {
		p.send("y")
		p.expect(t, "New device passphrase: ")
		p.send(pass)
		p.expect(t, "Repeat the device passphrase: ")
		p.send(pass)
	}
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
	return []string{"HOP_PASSWORD=" + subPassword, "HOP_SECRET_KEY=" + sk}
}

// interruptAt runs hop args on a terminal, answers the device passphrase
// prompt with pass when it is not empty, and sends SIGINT at prompt: the
// command exits 130, and a daemon other than the one before runs after it.
func (h *subHome) interruptAt(t *testing.T, extra []string, pass, prompt string, args ...string) string {
	t.Helper()
	before := h.daemonPID(t)
	p := h.startPTY(t, extra, args...)
	if pass != "" {
		p.expect(t, "Device passphrase (this machine's key file, not your master password): ")
		p.send(pass)
	}
	p.expect(t, prompt)
	if err := p.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if code := p.wait(t, 60*time.Second); code != 130 {
		t.Errorf("hop %s after SIGINT: exit %d; want 130\n%s", strings.Join(args, " "), code, p.output())
	}
	waitUntil(t, 30*time.Second, "the daemon to run again", func() bool { pid := h.daemonPID(t); return pid != 0 && pid != before })
	return p.output()
}

// The real hop: Ctrl-C at a password prompt of a local hop passwd, which
// opened a locked vault in the daemon with the device passphrase, leaves the
// vault locked.
func TestSubprocessCtrlCAtLocalPasswdKeepsTheVaultLocked(t *testing.T) {
	hopBin, _ := buildSubBinaries(t)
	base, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	a := newSubHome(t, hopBin, base, "a", filepath.Join(base, "no-cert.pem"))
	const devicePass = "a typed device passphrase"
	subInit(t, a, devicePass)
	a.must(t, nil, "lock")

	p := a.startPTY(t, nil, "passwd")
	p.expect(t, "Device passphrase (this machine's key file, not your master password): ")
	p.send(devicePass)
	p.expect(t, "Current master password: ")
	if err := p.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if code := p.wait(t, 30*time.Second); code != 130 {
		t.Errorf("hop passwd after SIGINT: exit %d; want 130\n%s", code, p.output())
	}
	if !a.subLocked(t) {
		t.Error("the vault was locked before Ctrl-C at hop passwd and is open after it")
	}
}

// The real hop and its daemon: Ctrl-C at the confirmation of hop vault fork
// --local leaves the vault as the fork found it. Open with a sealed key
// file: open, with no passphrase typed again. Locked with an unsealed one,
// which the daemon opens by itself: locked.
func TestSubprocessCtrlCAtForkLeavesTheVaultAsItWas(t *testing.T) {
	hopBin, serverBin := buildSubBinaries(t)
	base, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	certFile, keyFile, pool := writeTestCert(t, base)
	origin := startServer(t, serverBin, base, certFile, keyFile, pool)
	const confirm = "Fork this vault into a new local-only vault? [y/N] "

	t.Run("open, sealed", func(t *testing.T) {
		const email = "sealed@example.com"
		invite := strings.TrimSpace(mustRun(t, serverBin, "invite", email, "--data", filepath.Join(base, "server")))
		a := newSubHome(t, hopBin, base, "sealed", certFile)
		const devicePass = "a typed device passphrase"
		secrets := subInit(t, a, devicePass)
		p := a.startPTY(t, secrets, "auth", "signup", "--server", origin, "--email", email, "--code", invite)
		p.expect(t, "Device passphrase (this machine's key file, not your master password): ")
		p.send(devicePass)
		if code := p.wait(t, 60*time.Second); code != 0 {
			t.Fatalf("hop auth signup: exit %d\n%s", code, p.output())
		}
		a.interruptAt(t, nil, devicePass, confirm, "vault", "fork", "--local")
		if a.subLocked(t) {
			t.Error("the vault was open before Ctrl-C at the fork and is locked after it")
		}
		a.checkNoPassphrase(t, devicePass)
	})
	t.Run("locked, unsealed", func(t *testing.T) {
		const email = "unsealed@example.com"
		invite := strings.TrimSpace(mustRun(t, serverBin, "invite", email, "--data", filepath.Join(base, "server")))
		b := newSubHome(t, hopBin, base, "unsealed", certFile)
		secrets := subInit(t, b, "")
		b.must(t, secrets, "auth", "signup", "--server", origin, "--email", email, "--code", invite)
		b.must(t, nil, "lock")
		b.interruptAt(t, nil, "", confirm, "vault", "fork", "--local")
		if !b.subLocked(t) {
			t.Error("the vault was locked before Ctrl-C at the fork and is open after it")
		}
	})
}
