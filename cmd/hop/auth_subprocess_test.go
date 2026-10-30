//go:build linux && !hopdev

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/dalyem/hopkey/internal/store"
)

// The process-boundary test of hop auth: the real hop and hop-server
// binaries, each command its own process, a hop-server process serving
// TLS with a certificate the clients trust through SSL_CERT_FILE, and a
// daemon each hop starts itself, in homes of their own with the device
// key in a file (no keychain). It signs up, signs in on a second home
// with the master password, syncs both ways, checks that no daemon a hop
// auth command started has the auth secrets in its environment, and
// interrupts a hop auth flow with SIGINT at a prompt.

const (
	subEmail    = "me@example.com"
	subPassword = "correct horse battery staple"
)

// The auth secrets each hop auth command gets, the real ones or decoys,
// and that no daemon may inherit.
var subSecretNames = []string{"HOP_PASSWORD", "HOP_NEW_PASSWORD", "HOP_SECRET_KEY", "HOP_RECOVERY_KEY", "HOP_KIT_CONFIRM"}

func TestSubprocessAuthEndToEnd(t *testing.T) {
	if _, err := os.Stat("/proc/self/environ"); err != nil {
		t.Skip("no /proc to read a daemon's environment from")
	}
	bins := t.TempDir()
	hopBin, serverBin := filepath.Join(bins, "hop"), filepath.Join(bins, "hop-server")
	for _, b := range []struct{ out, pkg string }{
		{hopBin, "github.com/dalyem/hopkey/cmd/hop"},
		{serverBin, "github.com/dalyem/hopkey/cmd/hop-server"},
	} {
		cmd := exec.Command(goTool(t), "build", "-o", b.out, b.pkg)
		cmd.Dir = "../.."
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", b.pkg, err, out)
		}
	}

	base, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	certFile, keyFile, pool := writeTestCert(t, base)
	origin := startServer(t, serverBin, base, certFile, keyFile, pool)
	inviteCode := strings.TrimSpace(mustRun(t, serverBin, "invite", subEmail, "--data", filepath.Join(base, "server")))

	a := newSubHome(t, hopBin, base, "a", certFile)
	b := newSubHome(t, hopBin, base, "b", certFile)

	// A: a vault made on a terminal, with a host, then published.
	p := a.startPTY(t, nil, "init", "--device-key-store", "file")
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
	a.must(t, nil, "add", "web", "--address", "203.0.113.10", "--user", "deploy")

	secrets := func(pw, skv string) []string {
		return []string{"HOP_PASSWORD=" + pw, "HOP_NEW_PASSWORD=decoy-new-password", "HOP_SECRET_KEY=" + skv,
			"HOP_RECOVERY_KEY=decoy-recovery-key", "HOP_KIT_CONFIRM=decoy decoy"}
	}
	var su struct {
		Server  string `json:"server"`
		Created bool   `json:"created"`
	}
	subDecode(t, a.must(t, secrets(subPassword, sk), "auth", "signup", "--server", origin, "--email", subEmail, "--code", inviteCode, "--json"), &su)
	if su.Server != origin || su.Created {
		t.Fatalf("signup: %+v", su)
	}
	a.checkDaemonEnv(t, "after signup")

	// B: signed in with the master password and the Secret Key, from the
	// environment, with no terminal.
	var li struct {
		DeviceName string `json:"device_name"`
		Method     string `json:"method"`
	}
	subDecode(t, b.must(t, secrets(subPassword, sk), "auth", "login", "--method", "password", "--server", origin,
		"--email", subEmail, "--name", "b", "--device-key-store", "file", "--json"), &li)
	if li.DeviceName != "b" || li.Method != "password" {
		t.Fatalf("login: %+v", li)
	}
	b.checkDaemonEnv(t, "after login")

	// Both ways, with no sync command.
	waitUntil(t, 30*time.Second, "web on b", func() bool { return b.hasHost(t, "web") })
	b.must(t, nil, "add", "db", "--address", "203.0.113.11")
	waitUntil(t, 30*time.Second, "db on a", func() bool { return a.hasHost(t, "db") })

	// Interrupted: hop auth rotate stopped the daemon and waits at a
	// prompt; SIGINT ends it, and the daemon is running again with the
	// vault unchanged.
	before := a.daemonPID(t)
	p = a.startPTY(t, secrets(subPassword, sk), "auth", "rotate")
	p.expect(t, "Enter keeps only this device): ")
	if pid := a.daemonPID(t); pid != 0 {
		t.Fatalf("the daemon (pid %d) runs while hop auth rotate holds the vault", pid)
	}
	// Meanwhile another hop command does not start a daemon that would
	// take the vault from under the flow.
	if code, _, stderr := a.hop(t, nil, "ls"); code != 255 || !strings.Contains(stderr, "hop auth command (pid") {
		t.Errorf("hop ls during the flow: exit %d, %q", code, stderr)
	}
	if pid := a.daemonPID(t); pid != 0 {
		t.Fatalf("hop ls started a daemon (pid %d) during the flow", pid)
	}
	if err := p.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if code := p.wait(t, 30*time.Second); code != 130 {
		t.Errorf("hop auth rotate after SIGINT: exit %d; want 130\n%s", code, p.output())
	}
	var after int
	waitUntil(t, 30*time.Second, "the daemon to run again", func() bool { after = a.daemonPID(t); return after != 0 })
	if after == before {
		t.Errorf("the daemon pid did not change (%d): it was never stopped", after)
	}
	a.checkDaemonEnv(t, "after the interrupted rotate")
	if _, err := os.Lstat(filepath.Join(a.run, "hop", "auth-hold")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the hold marker is left: %v", err)
	}
	var devs struct {
		Devices []struct {
			Name string `json:"name"`
		} `json:"devices"`
	}
	subDecode(t, a.must(t, nil, "auth", "devices", "--json"), &devs)
	if len(devs.Devices) != 2 {
		t.Errorf("devices after the interrupted rotate: %+v; want both, nothing revoked", devs)
	}
	a.must(t, nil, "add", "cache", "--address", "203.0.113.12")
	waitUntil(t, 30*time.Second, "cache on b", func() bool { return b.hasHost(t, "cache") })
}

// subHome is one machine: a home and XDG directories of its own.
type subHome struct {
	bin, name, home, run, state string
	env                         []string
}

func newSubHome(t *testing.T, bin, base, name, certFile string) *subHome {
	t.Helper()
	dir := filepath.Join(base, name)
	h := &subHome{bin: bin, name: name, home: filepath.Join(dir, "home"), run: filepath.Join(dir, "run"), state: filepath.Join(dir, "state")}
	for _, d := range []string{h.home, h.run, h.state} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	h.env = []string{
		"HOME=" + h.home, "PATH=" + os.Getenv("PATH"),
		"XDG_RUNTIME_DIR=" + h.run, "XDG_STATE_HOME=" + h.state,
		"XDG_DATA_HOME=" + filepath.Join(dir, "data"), "XDG_CONFIG_HOME=" + filepath.Join(dir, "config"),
		"SSL_CERT_FILE=" + certFile, "SSL_CERT_DIR=" + filepath.Join(dir, "no-certs"),
	}
	t.Cleanup(func() {
		h.hop(t, nil, "daemon", "stop")
		if t.Failed() {
			if b, err := os.ReadFile(filepath.Join(h.state, "hop", "daemon.log")); err == nil {
				t.Logf("%s daemon.log:\n%s", name, b)
			}
		}
	})
	return h
}

func (h *subHome) hop(t *testing.T, extra []string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var so, se bytes.Buffer
	c := exec.CommandContext(ctx, h.bin, args...)
	c.Env = append(slices.Clone(h.env), extra...)
	c.Stdout, c.Stderr = &so, &se
	err := c.Run()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		t.Fatalf("%s: hop %v: %v", h.name, args, err)
	}
	t.Logf("%s: hop %s: exit %d\nstderr: %s", h.name, strings.Join(args, " "), code, se.String())
	return code, so.String(), se.String()
}

func (h *subHome) must(t *testing.T, extra []string, args ...string) string {
	t.Helper()
	code, out, stderr := h.hop(t, extra, args...)
	if code != 0 {
		t.Fatalf("%s: hop %v: exit %d: %s", h.name, args, code, stderr)
	}
	return out
}

func (h *subHome) hasHost(t *testing.T, name string) bool {
	t.Helper()
	var hosts []struct {
		Name string `json:"name"`
	}
	subDecode(t, h.must(t, nil, "ls", "--json"), &hosts)
	return slices.ContainsFunc(hosts, func(x struct {
		Name string `json:"name"`
	}) bool {
		return x.Name == name
	})
}

// daemonPID is the running daemon's pid, or 0. hop status never starts
// one.
func (h *subHome) daemonPID(t *testing.T) int {
	t.Helper()
	code, out, _ := h.hop(t, nil, "status", "--json")
	var st struct {
		Running bool `json:"running"`
		PID     int  `json:"pid"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatalf("%s: hop status: exit %d, %q: %v", h.name, code, out, err)
	}
	if !st.Running {
		return 0
	}
	return st.PID
}

// checkDaemonEnv reads the running daemon's environment from /proc: it
// has this home's, and none of the auth secrets.
func (h *subHome) checkDaemonEnv(t *testing.T, when string) {
	t.Helper()
	var pid int
	waitUntil(t, 20*time.Second, h.name+"'s daemon "+when, func() bool { pid = h.daemonPID(t); return pid != 0 })
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		t.Fatal(err)
	}
	if args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00"); len(args) != 2 || args[0] != h.bin || args[1] != "daemon" {
		t.Fatalf("%s: pid %d is %q, not the hop daemon", h.name, pid, args)
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		t.Fatal(err)
	}
	environ := strings.Split(string(b), "\x00")
	if !slices.Contains(environ, "HOME="+h.home) {
		t.Fatalf("%s: the daemon's environment is not this home's: %d entries", h.name, len(environ))
	}
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if slices.Contains(subSecretNames, name) {
			t.Errorf("%s: the daemon %s has %s in its environment", h.name, when, name)
		}
	}
	for _, v := range []string{subPassword, "decoy-new-password", "decoy-recovery-key"} {
		if bytes.Contains(b, []byte(v)) {
			t.Errorf("%s: the daemon %s has a secret value in its environment", h.name, when)
		}
	}
}

// ptyProc is a hop command on a pseudo-terminal of its own.
type ptyProc struct {
	cmd    *exec.Cmd
	master *os.File
	mu     sync.Mutex
	out    bytes.Buffer
	pos    int
	done   chan struct{}
	code   int
}

func (p *ptyProc) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.Write(b)
}

func (p *ptyProc) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.ReplaceAll(p.out.String(), "\r", "")
}

func (h *subHome) startPTY(t *testing.T, extra []string, args ...string) *ptyProc {
	t.Helper()
	master, slave := openPTY(t)
	p := &ptyProc{master: master, done: make(chan struct{})}
	p.cmd = exec.Command(h.bin, args...)
	p.cmd.Env = append(slices.Clone(h.env), extra...)
	p.cmd.Stdin, p.cmd.Stdout, p.cmd.Stderr = slave, slave, slave
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	slave.Close()
	go io.Copy(p, master) // ends (EIO) once the command has exited
	go func() {
		err := p.cmd.Wait()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			p.code = ee.ExitCode()
		} else if err != nil {
			p.code = -1
		}
		close(p.done)
	}()
	t.Cleanup(func() {
		p.cmd.Process.Kill()
		<-p.done
		master.Close()
		t.Logf("%s: hop %s on a terminal:\n%s", h.name, strings.Join(args, " "), redactKit(p.output()))
	})
	return p
}

// expect waits for prompt in what the command wrote after the last
// prompt, and returns everything it wrote so far.
func (p *ptyProc) expect(t *testing.T, prompt string) string {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		out := p.output()
		if i := strings.Index(out[min(p.pos, len(out)):], prompt); i >= 0 {
			p.pos += i + len(prompt)
			return out
		}
		select {
		case <-p.done:
			t.Fatalf("the command exited (%d) before asking %q:\n%s", p.code, prompt, redactKit(out))
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %q:\n%s", prompt, redactKit(out))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (p *ptyProc) send(line string) {
	p.master.Write([]byte(line + "\n"))
}

func (p *ptyProc) wait(t *testing.T, d time.Duration) int {
	t.Helper()
	select {
	case <-p.done:
		return p.code
	case <-time.After(d):
		t.Fatalf("the command did not exit within %s:\n%s", d, redactKit(p.output()))
		return -1
	}
}

// openPTY opens a pseudo-terminal pair.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("opening a pseudo-terminal: %v", err)
	}
	fd := int(m.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		t.Fatalf("unlocking the pseudo-terminal: %v", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		m.Close()
		t.Fatalf("naming the pseudo-terminal: %v", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		m.Close()
		t.Fatalf("opening the pseudo-terminal's slave: %v", err)
	}
	return m, s
}

var subKitLine = regexp.MustCompile(`(?m)^(Secret Key|Recovery Key): +(\S+)$`)

func subKitKeys(t *testing.T, out string) (sk, rk string) {
	t.Helper()
	for _, g := range subKitLine.FindAllStringSubmatch(out, -1) {
		if g[1] == "Secret Key" {
			sk = g[2]
		} else {
			rk = g[2]
		}
	}
	if sk == "" || rk == "" {
		t.Fatalf("no kit in the output")
	}
	return sk, rk
}

// redactKit keeps the kit's keys out of the test log.
func redactKit(s string) string {
	return subKitLine.ReplaceAllString(s, "$1: [redacted]")
}

func subDecode(t *testing.T, out string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(out), v); err != nil {
		t.Fatalf("decoding %q: %v", out, err)
	}
}

func mustRun(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatalf("%s %v: %v", filepath.Base(bin), args, err)
	}
	return string(out)
}

func waitUntil(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// writeTestCert writes a self-signed certificate for 127.0.0.1 and its key.
func writeTestCert(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hop-server test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

// startServer runs hop-server serve on a free loopback port, with TLS,
// until the test ends.
func startServer(t *testing.T, bin, base, certFile, keyFile string, pool *x509.CertPool) (origin string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	origin = "https://" + addr
	var log bytes.Buffer
	var mu sync.Mutex
	cmd := exec.Command(bin, "serve", "--listen", addr, "--data", filepath.Join(base, "server"), "--origin", origin,
		"--tls-cert", certFile, "--tls-key", keyFile)
	w := writerFunc(func(b []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return log.Write(b) })
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
			<-exited
		}
		if t.Failed() {
			mu.Lock()
			t.Logf("hop-server log:\n%s", log.String())
			mu.Unlock()
		}
	})
	waitUntil(t, 20*time.Second, "hop-server to serve TLS", func() bool {
		select {
		case <-exited:
			mu.Lock()
			defer mu.Unlock()
			t.Fatalf("hop-server exited:\n%s", log.String())
		default:
		}
		c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool})
		if err != nil {
			return false
		}
		c.Close()
		return true
	})
	return origin
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }
