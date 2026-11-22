package cli_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/model"
)

// hop access against akServer, for round 2 of the review of D2: a host
// that stalls inside the session, labels two records match, the
// hand-removed-lock residual of §7.7, and the rows of the check table that
// need a connection.

// Review r2 #2, end to end: a host sends a valid header and then stalls
// in the middle of the file. The client aborts at its deadline and ends
// the connection a grace period later; it doesn't wait for the host, or
// for the session timeout. Nothing is written or stored.
func TestAccessSessionStalledFileEndsAtTheDeadline(t *testing.T) {
	w := newAccessWorld(t, 1)
	cli.SetAccessSessionTimeout(t, 60*time.Second)
	cli.SetAccessDeadlines(t, time.Second, 300*time.Millisecond)
	realCat, err := exec.LookPath("cat")
	if err != nil {
		t.Fatal(err)
	}
	// The session's cat -- FILE sends 10 bytes and stalls; every other cat
	// is the real one. The binding preflight runs before the hook.
	stall := fakeServerBin(t, map[string]string{"cat": `if [ "$1" = "--" ]; then head -c 10 "$2"; sleep 30; exit 0; fi; exec '` + realCat + `' "$@"`})
	h := installHooks(t)
	h.on("before-session", model.ID{}, func() { w.srv[0].setPath(stall) })
	start := time.Now()
	code, res, _ := w.add(t, "alice", "web-1")
	took := time.Since(start)
	w.srv[0].setPath("")
	if took > 20*time.Second {
		t.Fatalf("the run took %v: it waited for the stalled host", took)
	}
	if code == 0 || len(res.Targets) != 1 || res.Targets[0].Recorded || !strings.Contains(res.Targets[0].Message, "hop's deadline for the session passed") {
		t.Fatalf("exit %d %+v", code, res)
	}
	a := w.record(t, "alice")
	if a == nil || a.Targets[0].State != model.AccessPending || a.Targets[0].Gen != 1 || strings.Contains(w.ak(t, 0), "hop-access:") {
		t.Fatalf("record %+v, file %q", a, w.ak(t, 0))
	}
}

// Two live records whose labels match under K_alias, as an older or
// foreign writer could leave them (only writers keep labels unique,
// §5.1): every command that names a record by label refuses, names both
// record IDs, and touches nothing. ls lists both.
func TestAccessAmbiguousLabelRefused(t *testing.T) {
	w := newAccessWorld(t, 1)
	if code, _, _ := w.add(t, "alice", "web-1"); code != 0 {
		t.Fatal("add")
	}
	a := w.record(t, "alice")
	twin := *a
	twin.Label, twin.Targets = "Alice.", slices.Clone(a.Targets)
	twin.RecordID = model.ID{0x5e, 0xc0, 0x4d}
	twin = w.store.InjectAccess(twin)
	before, writes := w.ak(t, 0), w.store.Writes()
	for _, args := range [][]string{
		{"rm", "alice", "--yes", "--json"},
		{"rm", "ALICE", "--abandon", "web-1", "--yes"},
		{"add", "alice", "--json"},
		{"migrate", "alice", "web-1", "--yes"},
		{"forget", "alice", "--yes"},
	} {
		code, _, out := w.run(t, args...)
		if code == 0 || !strings.Contains(out, "two hop access records match the label") ||
			!strings.Contains(out, a.RecordID.String()) || !strings.Contains(out, twin.RecordID.String()) {
			t.Errorf("hop access %s: %d %s", strings.Join(args, " "), code, out)
		}
	}
	if w.ak(t, 0) != before || w.store.Writes() != writes {
		t.Fatal("a refused command changed the file or the vault")
	}
	code, out, _ := w.hop(t, "access", "ls", "alice", "--json")
	var views []cli.AccessView
	if code != 0 || json.Unmarshal([]byte(out), &views) != nil || len(views) != 2 {
		t.Fatalf("ls: %d %s", code, out)
	}
}

// The hand-removed lock of §7.7 (walk-through 5, outside C1), as the
// residual the spec states. An add has passed its second compare and is
// about to rename; someone removes its lock by hand; an rm takes a new
// lock, writes the tombstone and records removed. The add's rename then
// brings the line back and drops the tombstone. The add's release finds
// the lock isn't its own and exits 89 with the lost-lock message, its
// result is dropped, and check reports "line present for a removed
// target" and "tombstone missing".
func TestAccessHandRemovedLockResidual(t *testing.T) {
	w := newAccessWorld(t, 2)
	if code, _, _ := w.add(t, "alice", "web-2"); code != 0 {
		t.Fatal("add web-2")
	}
	realMv, err := exec.LookPath("mv")
	if err != nil {
		t.Fatal(err)
	}
	gate := t.TempDir()
	// The first mv on web-1 waits for the test; every later one runs at
	// once.
	w.srv[0].setPath(fakeServerBin(t, map[string]string{"mv": `g='` + gate + `'; if mkdir "$g/used" 2>/dev/null; then : > "$g/reached"; ` +
		`n=0; until [ -e "$g/go" ]; do sleep 0.1; n=$((n+1)); [ $n -lt 900 ] || break; done; fi; exec '` + realMv + `' "$@"`}))
	addRun := w.runAsync(t, "add", "alice", "web-1", "--json")
	waitFor(t, 60*time.Second, "the add reaches its rename", func() bool {
		_, err := os.Stat(filepath.Join(gate, "reached"))
		return err == nil
	})
	lock := filepath.Join(w.srv[0].home, ".ssh", ".hop-authorized_keys.lock.d")
	if _, err := os.Stat(lock); err != nil {
		t.Fatalf("the add doesn't hold the lock: %v", err)
	}
	os.RemoveAll(lock) // by hand
	code, res, _ := w.run(t, "rm", "alice", "web-1", "--yes", "--json")
	if code != 0 || targetStates(res)["web-1"] != model.AccessRemoved {
		t.Fatalf("rm: %d %+v", code, res)
	}
	a := w.record(t, "alice")
	tomb := "# hop-access-removed " + a.RecordID.String() + " 2\n"
	if w.ak(t, 0) != w.orig[0]+tomb {
		t.Fatalf("after rm: %q", w.ak(t, 0))
	}
	os.WriteFile(filepath.Join(gate, "go"), nil, 0o600)
	r := wait(t, addRun, "the add")
	if r.code == 0 || !strings.Contains(r.out, "removed, replaced or unreadable") || len(r.res.Targets) != 1 || r.res.Targets[0].Recorded {
		t.Fatalf("the add: %d %s", r.code, r.out)
	}
	got := w.ak(t, 0)
	if !strings.Contains(got, "hop-access:"+a.RecordID.String()) || strings.Contains(got, "hop-access-removed") {
		t.Fatalf("the add's rename did not bring the line back: %q", got)
	}
	web1 := w.host(t, "web-1").ItemID
	for _, x := range w.record(t, "alice").Targets {
		if x.HostItemID == web1 && (x.State != model.AccessRemoved || x.Gen != 2) {
			t.Fatalf("the vault no longer says removed: %+v", x)
		}
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Errorf("a lock was left: %v", err)
	}
	code, fs := w.check(t)
	if code != 1 || kinds(fs)["line-present-removed"] != 1 || kinds(fs)["tombstone-missing"] != 1 {
		t.Fatalf("check: %d %+v", code, fs)
	}
}

// The rows of the §7.8 table that need a connection, with their --json
// objects: can't read (a binding the pins no longer include, for a live
// and a removed target, and a symlinked file) and a shared pin whose host
// records read different files.
func TestAccessCheckConnectionRowsJSON(t *testing.T) {
	t.Run("can't read", func(t *testing.T) {
		w := newAccessWorld(t, 2)
		if code, _, _ := w.add(t, "alice", "web-1", "web-2"); code != 0 {
			t.Fatal("add")
		}
		if code, _, _ := w.run(t, "rm", "alice", "web-2", "--yes"); code != 0 {
			t.Fatal("rm web-2")
		}
		a := w.record(t, "alice")
		fp1, fp2 := ssh.FingerprintSHA256(w.srv[0].hostKey), ssh.FingerprintSHA256(w.srv[1].hostKey)
		// web-2 now pins another key; web-1's file is a symbolic link.
		h2 := w.host(t, "web-2")
		h2.HostKeys = []string{authorizedKeysLine(newSigner(t).PublicKey())}
		if _, err := w.store.PutHost(context.Background(), h2); err != nil {
			t.Fatal(err)
		}
		ak := filepath.Join(w.srv[0].home, ".ssh", "authorized_keys")
		os.Rename(ak, ak+".real")
		os.Symlink("authorized_keys.real", ak)
		code, fs := w.check(t)
		base := cli.AccessFinding{Kind: "cant-read", User: w.user, Label: "alice", RecordID: a.RecordID.String(), Unread: true}
		want := []cli.AccessFinding{}
		f1 := base
		f1.Host, f1.HostID, f1.Binding, f1.TargetState = "web-1", w.host(t, "web-1").ItemID.String(), fp1, model.AccessInstalled
		f1.Message = "~/.ssh/authorized_keys is a symbolic link"
		f1.Fix = "hop trust web-1, hop access migrate alice web-1 or hop access rm alice --abandon web-1"
		f2 := base
		f2.Host, f2.HostID, f2.Binding, f2.TargetState = "web-2", h2.ItemID.String(), fp2, model.AccessRemoved
		f2.Message = "the host's pinned keys no longer include " + fp2 + ", the key this removed target is bound to, so hop can't read its file"
		f2.Fix = "hop trust web-2 if the machine still presents " + fp2
		for _, x := range a.Targets {
			if x.HostItemID == h2.ItemID {
				want = append(want, f2)
			} else {
				want = append(want, f1)
			}
		}
		if code != 2 || !slices.Equal(fs, want) {
			t.Fatalf("check: %d\n%+v\nwant\n%+v", code, fs, want)
		}
	})
	t.Run("a live target's pin is gone", func(t *testing.T) {
		w := newAccessWorld(t, 1)
		if code, _, _ := w.add(t, "alice", "web-1"); code != 0 {
			t.Fatal("add")
		}
		a := w.record(t, "alice")
		fp := ssh.FingerprintSHA256(w.srv[0].hostKey)
		h := w.host(t, "web-1")
		h.HostKeys = []string{authorizedKeysLine(newSigner(t).PublicKey())}
		if _, err := w.store.PutHost(context.Background(), h); err != nil {
			t.Fatal(err)
		}
		code, fs := w.check(t)
		want := []cli.AccessFinding{{Kind: "cant-read", Host: "web-1", HostID: h.ItemID.String(), User: w.user, Binding: fp, Label: "alice",
			RecordID: a.RecordID.String(), TargetState: model.AccessInstalled, Unread: true,
			Message: "the host's pinned keys no longer include " + fp + ", the key this target is bound to; nothing was changed. " +
				"Use hop access migrate alice web-1 or hop access rm alice --abandon web-1"}}
		if code != 2 || !slices.Equal(fs, want) {
			t.Fatalf("check: %d\n%+v\nwant\n%+v", code, fs, want)
		}
	})
	t.Run("shared pin, different files", func(t *testing.T) {
		w := newAccessWorld(t, 1)
		// web-1b pins web-1's host key, and reaches another machine that
		// presents it.
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
		code, fs := w.check(t)
		want := []cli.AccessFinding{{Kind: "shared-pin-different-files", Host: "web-1", HostID: w.host(t, "web-1").ItemID.String(), User: w.user,
			Binding: ssh.FingerprintSHA256(w.srv[0].hostKey), Label: "alice", RecordID: a.RecordID.String(), TargetState: model.AccessInstalled,
			Message: "these host records reach different machines or accounts with the same host key: web-1 and web-1b",
			Fix:     "for a removal, hop access rm alice --abandon web-1, never --same-machine"}}
		if code != 1 || !slices.Equal(fs, want) {
			t.Fatalf("check: %d\n%+v\nwant\n%+v", code, fs, want)
		}
	})
}
