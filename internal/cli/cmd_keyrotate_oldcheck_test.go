package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// The old key counts as refused only when the ssh log of the check shows
// the server itself turning it away. Anything else leaves the host needing
// attention, on the new key, with the old key kept in the vault.

// afterOldKeyRemoved runs f once the edit that removes the old key's lines
// from s has run: before the check of the old key.
func afterOldKeyRemoved(s *akServer, f func()) {
	var writes atomic.Int32
	s.setOnExec(func(cmd string) bool {
		if isAKWrite(cmd) && writes.Add(1) == 2 {
			f()
		}
		return false
	})
}

func rotateJSON(t *testing.T, w *rotWorld, args ...string) map[string]rotHostJSON {
	t.Helper()
	code, stdout, stderr := w.hop(t, append([]string{"key", "rotate", "deploy-key", "--yes", "--json"}, args...)...)
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	if code == 0 {
		t.Error("exit 0 with a host that needs attention")
	}
	return decodeRotateHosts(t, stdout)
}

// wantAttention checks a host the old-key check could not clear: it needs
// attention for why, is on the new key, and its fix finishes the job.
func wantAttention(t *testing.T, w *rotWorld, hosts map[string]rotHostJSON, name, why string) {
	t.Helper()
	h := hosts[name]
	if h.Status != "needs-attention" || !strings.Contains(h.Reason, why) || !strings.Contains(h.Reason, "both keys stay in the vault") ||
		h.RemoteState != "old_key_removed" || !strings.Contains(h.Fix, "--new-key") {
		t.Errorf("%s: %+v, want needs-attention for %q", name, h, why)
	}
	if w.hostKeyID(t, name) == w.keyID {
		t.Errorf("%s is still on the old key in the vault", name)
	}
	if w.keyNamed(t, "deploy-key") == nil {
		t.Error("the old key was deleted from the vault")
	}
}

// The jump host turns the old key away during the check. Its "Permission
// denied" comes from the ProxyCommand's ssh, not from the server.
func TestKeyRotateJumpHostFailureIsNotARefusal(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{jump: true})
	afterOldKeyRemoved(w.srv[1], func() { w.srv[0].setRefuse("deploy@old") })
	hosts := rotateJSON(t, w, "--hosts", "web-2")
	wantAttention(t, w, hosts, "web-2", "did not get through the jump host web-1")
}

// The server still accepts the old key through authorized_keys2, and hop
// can't sign with it any more (the daemon's agent is gone), so the login
// fails with "Permission denied" all the same.
func TestKeyRotateOldKeyAcceptedButUnsignable(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	writeAK2(t, w.srv[0], w.orig[0])
	afterOldKeyRemoved(w.srv[0], func() { os.Remove(w.paths.AgentSocket()) })
	hosts := rotateJSON(t, w, "--hosts", "web-1")
	wantAttention(t, w, hosts, "web-1", "the server still accepts the old key")
	if h := hosts["web-1"]; !strings.Contains(h.Reason, "could not sign") {
		t.Errorf("web-1: %+v", h)
	}
}

// The server still accepts the old key through authorized_keys2, and it
// logs in: web-1 needs attention, web-2 is rotated, and the old key stays.
func TestKeyRotateOldKeyStillAcceptedElsewhere(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	writeAK2(t, w.srv[0], w.orig[0])
	hosts := rotateJSON(t, w)
	wantAttention(t, w, hosts, "web-1", "the old key still logs in")
	if h := hosts["web-2"]; h.Status != "rotated" {
		t.Errorf("web-2: %+v", h)
	}
}

// writeAK2 gives s an authorized_keys2 with content.
func writeAK2(t *testing.T, s *akServer, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.home, ".ssh", "authorized_keys2"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
