package cli_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
)

// call makes one control call to the daemon, as another hop command would.
func (w *rotWorld) call(op string, params, result any) error {
	ctx := context.Background()
	c, err := daemon.Dial(ctx, w.paths.ControlSocket())
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Call(ctx, op, params, result)
}

// editHost changes a host's record through the daemon, as another command,
// or a sync from another device, would. It may run in an akServer hook, so
// it returns its error instead of failing the test.
func (w *rotWorld) editHost(name string, f func(*model.Host)) error {
	var l daemon.ListResult
	if err := w.call(daemon.OpList, nil, &l); err != nil {
		return err
	}
	for _, h := range l.Hosts {
		if h.Name == name {
			f(&h)
			return w.call(daemon.OpPutHost, daemon.PutHostParams{Host: h}, nil)
		}
	}
	return os.ErrNotExist
}

// addKey puts a new ed25519 key in the vault and returns it.
func (w *rotWorld) addKey(t *testing.T, name string) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.call(daemon.OpPutKey, daemon.PutKeyParams{Name: name, PrivateKey: string(pem.EncodeToMemory(block))}, nil); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (w *rotWorld) signerOf(t *testing.T, key string) ssh.Signer {
	t.Helper()
	k := w.keyNamed(t, key)
	if k == nil {
		t.Fatalf("no key %s in the vault", key)
	}
	s, err := ssh.ParsePrivateKey([]byte(k.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (w *rotWorld) appendAK(t *testing.T, i int, line string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(w.srv[i].home, ".ssh", "authorized_keys"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

// loseAnswer puts a relay in front of the daemon's control socket that
// passes every request on, and for the first one whose op matches, lets the
// daemon carry it out and then drops the connection instead of passing the
// answer back: hop cannot tell whether the change was made. It returns how
// many matching requests the relay saw.
func (w *rotWorld) loseAnswer(t *testing.T, match func(op string) bool) *atomic.Int32 {
	t.Helper()
	sock := w.paths.ControlSocket()
	real := sock + ".real"
	if err := os.Rename(sock, real); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int32
	relay := func(c net.Conn) {
		defer c.Close()
		d, err := net.Dial("unix", real)
		if err != nil {
			return
		}
		defer d.Close()
		cr, dr := bufio.NewReader(c), bufio.NewReader(d)
		for {
			line, err := cr.ReadBytes('\n')
			if err != nil {
				return
			}
			var req struct {
				Op string `json:"op"`
			}
			json.Unmarshal(line, &req)
			if _, err := d.Write(line); err != nil {
				return
			}
			resp, err := dr.ReadBytes('\n')
			if err != nil {
				return
			}
			if match(req.Op) && n.Add(1) == 1 {
				return
			}
			if _, err := c.Write(resp); err != nil {
				return
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go relay(c)
		}
	}()
	return &n
}

// Another device relinks web-1 from one tailnet node to another while its
// key is rotated: only the record's Tailscale link changes. That decides
// where ssh connects as much as an address does, so hop must not point the
// relinked record at the new key.
func TestKeyRotateDoesNotRepointARelinkedTailscaleHost(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	// Tailscale does not run in the tests, so hop reaches web-1 directly.
	if err := w.editHost("web-1", func(h *model.Host) {
		h.Tailscale = &model.Tailscale{StableNodeID: "nodeA", DNSName: "web-a.tail1234.ts.net.", SSH: "no"}
	}); err != nil {
		t.Fatal(err)
	}
	var writes atomic.Int32
	w.srv[0].setOnExec(func(cmd string) bool {
		if isAKWrite(cmd) && writes.Add(1) == 2 {
			if err := w.editHost("web-1", func(h *model.Host) {
				h.Tailscale = &model.Tailscale{StableNodeID: "nodeB", DNSName: "web-b.tail1234.ts.net.", SSH: "no"}
			}); err != nil {
				t.Errorf("relinking web-1: %v", err)
			}
		}
		return false
	})
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-1", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	if writes.Load() < 2 {
		t.Fatalf("hop made %d edits; the test relinks during the second", writes.Load())
	}
	h := w.hostNamed(t, "web-1")
	if h.Tailscale == nil || h.Tailscale.StableNodeID != "nodeB" {
		t.Fatalf("the relink did not land: %+v", h.Tailscale)
	}
	if h.KeyID != w.keyID {
		t.Error("the relinked record was pointed at the new key")
	}
	st := decodeRotateHosts(t, stdout)["web-1"]
	if code == 0 || st.Status != "needs-attention" || !strings.Contains(st.Reason, "changed") || !strings.Contains(st.Fix, "--new-key") {
		t.Errorf("exit %d, web-1 %+v", code, st)
	}
	// The server hop checked is put back on the old key, which the record
	// still names.
	if err := login(w.srv[0], w.oldKey); err != nil {
		t.Errorf("web-1's server refuses the old key: %v", err)
	}
}

// web-2 is reached through web-1. web-1's record changes after hop checked
// web-2, while web-2's own record does not. hop must not point web-2 at the
// new key over a way to it that it never checked.
func TestKeyRotateDoesNotRepointAfterTheJumpHostChanged(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{jump: true})
	extraPin := authorizedKeysLine(newSigner(t).PublicKey())
	var writes atomic.Int32
	w.srv[1].setOnExec(func(cmd string) bool {
		if isAKWrite(cmd) && writes.Add(1) == 2 {
			if err := w.editHost("web-1", func(h *model.Host) { h.HostKeys = append(h.HostKeys, extraPin) }); err != nil {
				t.Errorf("editing the jump host: %v", err)
			}
		}
		return false
	})
	before := w.hostNamed(t, "web-2")
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-2", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	if writes.Load() < 2 {
		t.Fatalf("hop made %d edits; the test changes the jump host during the second", writes.Load())
	}
	if h := w.hostNamed(t, "web-1"); len(h.HostKeys) != 2 {
		t.Fatalf("the jump host edit did not land: %v", h.HostKeys)
	}
	if h := w.hostNamed(t, "web-2"); h.KeyID != w.keyID || h.ItemVersion != before.ItemVersion {
		t.Errorf("web-2 was written: key %v, version %d (was %d)", h.KeyID, h.ItemVersion, before.ItemVersion)
	}
	st := decodeRotateHosts(t, stdout)["web-2"]
	if code == 0 || st.Status != "needs-attention" || !strings.Contains(st.Reason, "changed") || !strings.Contains(st.Fix, "--hosts web-2") {
		t.Errorf("exit %d, web-2 %+v", code, st)
	}
	if err := login(w.srv[1], w.oldKey); err != nil {
		t.Errorf("web-2's server refuses the old key: %v", err)
	}
}

// earlierRun sets web-1's server up as an earlier run left it: the new key
// added beside the old one. hop's first read of it, over the old key, then
// loses its connection, so the old key looks refused while the new key
// logs in.
func earlierRun(t *testing.T, w *rotWorld) ssh.Signer {
	t.Helper()
	next := w.addKey(t, "deploy-key-next")
	w.appendAK(t, 0, rotOptions+" "+authorizedKeysLine(next.PublicKey())+" hop-rotated earlier")
	var reads atomic.Int32
	w.srv[0].setOnExec(func(cmd string) bool {
		return strings.Contains(cmd, "exec cat") && reads.Add(1) == 1
	})
	return next
}

// already-rotated must mean that the old key is refused: hop removes any
// old line left over the new key and checks, before it says so.
func TestKeyRotateAlreadyRotatedRemovesTheOldKeyLeft(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	next := earlierRun(t, w)
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-1", "--new-key", "deploy-key-next", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	st := decodeRotateHosts(t, stdout)["web-1"]
	if code != 0 || st.Status != "already-rotated" {
		t.Fatalf("exit %d, web-1 %+v", code, st)
	}
	if err := login(w.srv[0], w.oldKey); err == nil {
		t.Errorf("web-1 is reported already-rotated, but its server still takes the old key:\n%s", must(w.authorizedKeys(t, 0)))
	}
	if err := login(w.srv[0], next); err != nil {
		t.Errorf("web-1's server refuses the new key: %v", err)
	}
	if w.hostKeyID(t, "web-1") != w.keyNamed(t, "deploy-key-next").ItemID {
		t.Error("web-1 is not on the new key")
	}
}

// The old key's lines cannot be removed (the file changes under the edit),
// so the old key still logs in: not already-rotated, but needs-attention,
// and the old key stays in the vault.
func TestKeyRotateAlreadyRotatedNeedsAttentionWhileTheOldKeyStays(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	earlierRun(t, w)
	var reads atomic.Int32
	f := filepath.Join(w.srv[0].home, ".ssh", "authorized_keys")
	w.srv[0].setOnExec(func(cmd string) bool {
		if isAKWrite(cmd) {
			b, _ := os.ReadFile(f)
			os.WriteFile(f, append(b, "# changed by someone else\n"...), 0o640)
			return false
		}
		return strings.Contains(cmd, "exec cat") && reads.Add(1) == 1
	})
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-1", "--new-key", "deploy-key-next", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	if err := login(w.srv[0], w.oldKey); err != nil {
		t.Fatalf("the test means the old key to stay: %v", err)
	}
	st := decodeRotateHosts(t, stdout)["web-1"]
	if code == 0 || st.Status != "needs-attention" || !strings.Contains(st.Reason, "old key") || st.Fix == "" {
		t.Errorf("exit %d, web-1 %+v", code, st)
	}
	rk := decodeRotate(t, stdout).Keys[0]
	if rk.OldKey != "kept" || rk.OldKeyReason != "a host needs attention" || w.keyNamed(t, "deploy-key") == nil {
		t.Errorf("the old key: %+v", rk)
	}
}

// The daemon points web-1 at the new key, but its answer is lost. The
// record names the new key and still reaches the server hop checked: the
// rotation is done, and nothing is rolled back.
func TestKeyRotateLostVaultAnswerIsNotRolledBack(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	lost := w.loseAnswer(t, func(op string) bool { return op == daemon.OpPutHost || op == daemon.OpSetHostKey })
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-1", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	if lost.Load() == 0 {
		t.Fatal("no answer was lost")
	}
	res := decodeRotate(t, stdout)
	st := decodeRotateHosts(t, stdout)["web-1"]
	if code != 0 || st.Status != "rotated" {
		t.Fatalf("exit %d, web-1 %+v", code, st)
	}
	next := w.signerOf(t, res.Keys[0].NewKey)
	if w.hostKeyID(t, "web-1") != w.keyNamed(t, res.Keys[0].NewKey).ItemID {
		t.Error("web-1 is not on the new key")
	}
	if err := login(w.srv[0], next); err != nil {
		t.Errorf("web-1's server refuses the new key the record names: %v", err)
	}
	if err := login(w.srv[0], w.oldKey); err == nil {
		t.Error("web-1's server still takes the old key")
	}
}

// Another device points web-1 at the new key, and pins another host key
// for it, while hop rotates it: the record moved. The command hop names
// must work on the record as it is now, and finish the job.
func TestKeyRotateMovedRecordOnTheNewKeyGetsAFixThatWorks(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	extraPin := authorizedKeysLine(newSigner(t).PublicKey())
	var writes atomic.Int32
	w.srv[0].setOnExec(func(cmd string) bool {
		if !isAKWrite(cmd) || writes.Add(1) != 2 {
			return false
		}
		var l daemon.ListResult
		if err := w.call(daemon.OpList, nil, &l); err != nil {
			t.Error(err)
			return false
		}
		for _, k := range l.Keys {
			if strings.HasPrefix(k.Name, "deploy-key-rotated-") {
				id, _ := model.ParseID(k.ID)
				if err := w.editHost("web-1", func(h *model.Host) { h.KeyID = id; h.HostKeys = append(h.HostKeys, extraPin) }); err != nil {
					t.Error(err)
				}
			}
		}
		return false
	})
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-1", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	res := decodeRotate(t, stdout)
	newName := res.Keys[0].NewKey
	if w.hostKeyID(t, "web-1") != w.keyNamed(t, newName).ItemID {
		t.Fatal("the other device's edit did not land")
	}
	st := decodeRotateHosts(t, stdout)["web-1"]
	if code == 0 || st.Status != "needs-attention" || !strings.Contains(st.Reason, "changed") || st.Fix == "" {
		t.Fatalf("exit %d, web-1 %+v", code, st)
	}
	// The record names the new key, so the server keeps it.
	if err := login(w.srv[0], w.signerOf(t, newName)); err != nil {
		t.Errorf("web-1's server refuses the key its record names: %v", err)
	}

	w.srv[0].setOnExec(nil)
	args := append(strings.Fields(st.Fix)[1:], "--yes", "--json")
	code, stdout, stderr = w.hop(t, args...)
	t.Logf("hop %s (exit %d)\n%s\nstderr: %s", strings.Join(args, " "), code, stdout, stderr)
	if h := decodeRotateHosts(t, stdout)["web-1"]; code != 0 || h.Status != "already-rotated" {
		t.Fatalf("the fix: exit %d, web-1 %+v", code, h)
	}
	if err := login(w.srv[0], w.oldKey); err == nil {
		t.Error("after the fix web-1's server still takes the old key")
	}
}

func must(s string, _ os.FileMode) string { return s }
