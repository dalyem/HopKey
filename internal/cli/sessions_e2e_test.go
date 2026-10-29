package cli_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
)

// sessionKey writes a new ed25519 key to a file hop key add reads, and
// returns the file and its signer.
func sessionKey(t *testing.T) (string, ssh.Signer) {
	t.Helper()
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
	f := filepath.Join(shortTemp(t), "deploy")
	if err := os.WriteFile(f, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return f, signer
}

// longExec runs hop exec web-1 -- sleep on m in the background: the
// server holds that command for 30 seconds. It returns once the server
// has the command, and the channel gets hop's exit code and result.
type execEnd struct {
	code int
	res  cli.ExecResult
	at   time.Time
}

func longExec(t *testing.T, m *machine, srv *sshServer) <-chan execEnd {
	t.Helper()
	srv.reset()
	out := make(chan execEnd, 1)
	go func() {
		s := &session{}
		code := m.hop(t, s, "exec", "web-1", "--json", "--", "sleep")
		var r cli.ExecResult
		decodeJSON(t, s.stdout.String(), &r)
		out <- execEnd{code: code, res: r, at: time.Now()}
	}()
	deadline := time.Now().Add(30 * time.Second)
	for !slices.Contains(srv.commands(), "sleep") {
		if time.Now().After(deadline) {
			t.Fatal("hop exec never reached the server")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return out
}

// stopped says the daemon ended the session (ssh exits 255 on its SIGHUP),
// long before the server would end the command, and hop exec says why.
func stopped(e execEnd, why string) bool {
	return e.code == 255 && e.res.ExitCode == 255 && e.res.DurationMS < 25_000 &&
		e.res.Error == "the hop daemon ended this ssh session when "+why
}

// A device revoked while it is online ends the ssh sessions hop started:
// a hop exec in progress ends within seconds of the revocation, well
// before its command would, and hop status and hop auth status say so.
func TestRevokeEndsTheSessionsHopStarted(t *testing.T) {
	requireSSH(t)
	w := newAuthWorld(t)
	m1, m2 := newMachine(t, w, "m1"), newMachine(t, w, "m2")
	initS := &session{secrets: map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}}
	if code := m1.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	sk, _ := kitKeys(t, initS.stdout.String())
	m1.must(t, nil, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t), "--json")
	m2.must(t, map[string]string{"HOP_PASSWORD": resolvePassword, "HOP_SECRET_KEY": sk},
		"login", "--method", "password", "--server", w.origin, "--email", authEmail, "--name", "m2", "--json")

	keyFile, signer := sessionKey(t)
	srv := startSSHServer(t, signer.PublicKey())
	m1.must(t, nil, "key", "add", keyFile, "--name", "deploy-key")
	m1.must(t, nil, "add", "web-1", "--address", "127.0.0.1", "--port", strconv.Itoa(srv.port),
		"--user", "deploy", "--key", "deploy-key", "--host-key", authorizedKeysLine(srv.hostKey))
	m1.must(t, nil, "sync")
	deadline := time.Now().Add(30 * time.Second)
	for {
		m2.must(t, nil, "sync")
		if _, ok := m2.hosts(t)["web-1"]; ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("web-1 never reached m2")
		}
		time.Sleep(200 * time.Millisecond)
	}

	ended := longExec(t, m2, srv)
	s := &session{
		tty:     true,
		secrets: map[string]string{"Current master password: ": resolvePassword},
		answer: func(prompt string) string {
			switch {
			case strings.Contains(prompt, "Rotate them now?"):
				return "n"
			case strings.HasSuffix(prompt, "[y/N] "):
				return "y"
			}
			return "" // keep only this device
		},
	}
	if code := m1.hop(t, s, "auth", "devices", "revoke", "m2"); code != 0 {
		t.Fatalf("revoke: exit %d: %s", code, s.stderr.String())
	}
	revoked := time.Now()
	var e execEnd
	select {
	case e = <-ended:
	case <-time.After(45 * time.Second):
		t.Fatal("hop exec on the revoked device still runs 45s after the revoke")
	}
	if !stopped(e, "this device was revoked") {
		t.Fatalf("hop exec ended %v after the revoke with exit %d, %+v: not stopped by the revocation", e.at.Sub(revoked), e.code, e.res)
	}
	t.Logf("hop exec ended %v after the revoke: %s", e.at.Sub(revoked).Round(time.Millisecond), e.res.Error)

	out := m2.must(t, nil, "status")
	if !strings.Contains(out, "sessions:     ended 1 ssh session when this device was revoked") || !strings.Contains(out, "web-1 (hop exec)") {
		t.Errorf("hop status does not say the session ended:\n%s", out)
	}
	a := m2.authStatus(t)
	if a.EndedSessions == nil || a.EndedSessions.Count != 1 || a.EndedSessions.Sessions[0].Alias != "web-1" {
		t.Errorf("hop auth status --json: ended sessions %+v", a.EndedSessions)
	}
	if out := m2.must(t, nil, "auth", "status"); !strings.Contains(out, "ended 1 ssh session when this device was revoked") {
		t.Errorf("hop auth status does not say the session ended:\n%s", out)
	}
}

// A plain hop lock leaves open sessions running; hop lock --end-sessions
// ends them.
func TestLockEndsSessionsOnlyWhenAsked(t *testing.T) {
	requireSSH(t)
	w := newAuthWorld(t)
	m := newMachine(t, w, "m")
	initS := &session{secrets: map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}}
	if code := m.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	keyFile, signer := sessionKey(t)
	srv := startSSHServer(t, signer.PublicKey())
	m.must(t, nil, "key", "add", keyFile, "--name", "deploy-key")
	m.must(t, nil, "add", "web-1", "--address", "127.0.0.1", "--port", strconv.Itoa(srv.port),
		"--user", "deploy", "--key", "deploy-key", "--host-key", authorizedKeysLine(srv.hostKey))

	ended := longExec(t, m, srv)
	m.must(t, nil, "lock")
	select {
	case e := <-ended:
		t.Fatalf("a plain hop lock ended the session: exit %d, %+v", e.code, e.res)
	case <-time.After(3 * time.Second):
	}

	locked := time.Now()
	out := m.must(t, nil, "lock", "--end-sessions")
	var e execEnd
	select {
	case e = <-ended:
	case <-time.After(15 * time.Second):
		t.Fatal("hop lock --end-sessions left the session running")
	}
	if !stopped(e, "hop lock --end-sessions ran") {
		t.Fatalf("the session ended with exit %d, %+v: not stopped by hop lock --end-sessions", e.code, e.res)
	}
	if d := e.at.Sub(locked); d > 8*time.Second {
		t.Errorf("the session ended %v after hop lock --end-sessions", d)
	}
	if !strings.Contains(out, "ended 1 ssh session") {
		t.Errorf("hop lock --end-sessions says:\n%s", out)
	}
	if out := m.must(t, nil, "status"); !strings.Contains(out, "ended 1 ssh session when hop lock --end-sessions ran") {
		t.Errorf("hop status:\n%s", out)
	}
}
