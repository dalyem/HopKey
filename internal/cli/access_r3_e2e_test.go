package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/model"
)

// hop access check against akServer, for round 3 of the review of D2:
// every connection check makes trusts only pins it found in the host
// records read again right before it.

type checkRun struct {
	code    int
	out, se string
}

// checkAsync runs hop access check --json in the background.
func (w *accessWorld) checkAsync(t *testing.T, args ...string) <-chan checkRun {
	t.Helper()
	ch := make(chan checkRun, 1)
	go func() {
		var so, se bytes.Buffer
		env := w.env(t, strings.NewReader(""), &so, &se)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		code := cli.Run(ctx, append([]string{"access", "check", "--json"}, args...), env)
		ch <- checkRun{code: code, out: so.String(), se: se.String()}
	}()
	return ch
}

func waitCheck(t *testing.T, ch <-chan checkRun) (int, []cli.AccessFinding) {
	t.Helper()
	select {
	case r := <-ch:
		var fs []cli.AccessFinding
		if err := json.Unmarshal([]byte(r.out), &fs); err != nil {
			t.Fatalf("check output %q %q: %v", r.out, r.se, err)
		}
		t.Logf("hop access check: exit %d %+v\n%s", r.code, fs, r.se)
		return r.code, fs
	case <-time.After(100 * time.Second):
		t.Fatal("check did not finish")
	}
	return 0, nil
}

// countLogins counts the keys clients offer s from now on: any connection
// that gets past the host key check.
func countLogins(s *akServer) *atomic.Int32 {
	n := &atomic.Int32{}
	s.setOnAuth(func(ssh.ConnMetadata, ssh.PublicKey) { n.Add(1) })
	return n
}

// Review r3 #1: while check's read of the first target's file is held,
// another device's change removes the second target's bound pin. check
// reads the host records again before it connects there: it never
// connects, and reports the file it couldn't read (exit status 2).
func TestAccessCheckRechecksThePinBeforeEachRead(t *testing.T) {
	w := newAccessWorld(t, 2)
	if code, _, _ := w.add(t, "alice", "web-1", "web-2"); code != 0 {
		t.Fatal("add")
	}
	a := w.record(t, "alice")
	// check reads the targets in the record's order: the first read is
	// held, the second target's pin goes meanwhile.
	second := a.Targets[1]
	name := w.hostName(t, second.HostItemID)
	srv := w.srv[0]
	if name == "web-2" {
		srv = w.srv[1]
	}
	logins := countLogins(srv)
	h := installHooks(t)
	g := h.at("before-check-read", a.RecordID)
	ch := w.checkAsync(t)
	g.await(t, "the first read")
	hr := w.host(t, name)
	hr.HostKeys = []string{authorizedKeysLine(newSigner(t).PublicKey())}
	if _, err := w.store.PutHost(context.Background(), hr); err != nil {
		t.Fatal(err)
	}
	close(g.open)
	code, fs := waitCheck(t, ch)
	if n := logins.Load(); n != 0 {
		t.Fatalf("check connected to %s %d time(s) with a pin the vault no longer has", name, n)
	}
	want := []cli.AccessFinding{{Kind: "cant-read", Host: name, HostID: second.HostItemID.String(), User: w.user, Binding: second.ServerKeyFP,
		Label: "alice", RecordID: a.RecordID.String(), TargetState: model.AccessInstalled, Unread: true,
		Message: "the host's pinned keys no longer include " + second.ServerKeyFP + ", the key this target is bound to; nothing was changed. " +
			"Use hop access migrate alice " + name + " or hop access rm alice --abandon " + name}}
	if code != 2 || !slices.Equal(fs, want) {
		t.Fatalf("check: %d\n%+v\nwant\n%+v", code, fs, want)
	}
}

// Review r3 #1, a shared pin: web-1b pins web-1's host key and reaches
// another file. While check's read of web-1 is held, web-1b's pin of that
// key goes. web-1b no longer shares the pin when its turn comes: check
// doesn't connect to it, and has nothing to report.
func TestAccessCheckRechecksASharedPinBeforeItsRead(t *testing.T) {
	w := newAccessWorld(t, 1)
	home := filepath.Join(w.base, "remote-twin")
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(w.orig[0]), 0o600)
	s2 := startAKServerKey(t, home, w.srv[0].signer)
	twin := w.host(t, "web-1")
	twin.ItemID, twin.ItemVersion, twin.Name, twin.Port = model.ID{}, 0, "web-1b", uint32(s2.port)
	if _, err := w.store.PutHost(context.Background(), twin); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := w.add(t, "alice", "web-1"); code != 0 {
		t.Fatal("add")
	}
	a := w.record(t, "alice")
	logins := countLogins(s2)
	h := installHooks(t)
	g := h.at("before-check-read", a.RecordID)
	ch := w.checkAsync(t)
	g.await(t, "the read of web-1")
	tr := w.host(t, "web-1b")
	tr.HostKeys = []string{authorizedKeysLine(newSigner(t).PublicKey())}
	if _, err := w.store.PutHost(context.Background(), tr); err != nil {
		t.Fatal(err)
	}
	close(g.open)
	code, fs := waitCheck(t, ch)
	if n := logins.Load(); n != 0 {
		t.Fatalf("check connected to web-1b %d time(s) with a pin the vault no longer has", n)
	}
	if code != 0 || len(fs) != 0 {
		t.Fatalf("check: %d %+v", code, fs)
	}
}
