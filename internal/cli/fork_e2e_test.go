package cli_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/server"
	"github.com/dalyem/hopkey/internal/store"
)

const forkPassword = "the fork's own master password"

// vaultInfo is the daemon's view of m's vault (hop status --json).
func vaultInfo(t *testing.T, m *machine) *store.Info {
	t.Helper()
	var st struct {
		Vault *store.Info `json:"vault"`
	}
	decodeJSON(t, m.must(t, nil, "status", "--json"), &st)
	if st.Vault == nil {
		t.Fatalf("%s: hop status has no vault block", m.name)
	}
	return st.Vault
}

// forkSession answers hop vault fork's prompts: the new master password
// twice, and the type-back from the kit it prints.
func forkSession() *session {
	return &session{tty: true, secrets: map[string]string{"Master password for the new vault: ": forkPassword, "Repeat it: ": forkPassword}}
}

// forkLocal runs hop vault fork --local --yes on m and requires it to
// succeed, then checks that the new vault is unlocked, local-only and
// under new IDs, and that the old one is kept whole in the backup.
func forkLocal(t *testing.T, m *machine, old *store.Info, args ...string) *store.ForkResult {
	t.Helper()
	s := forkSession()
	if code := m.hop(t, s, append([]string{"vault", "fork", "--local", "--yes"}, args...)...); code != 0 {
		t.Fatalf("fork: exit %d: %s", code, s.stderr.String())
	}
	if out := s.stdout.String(); !strings.Contains(out, "Forked: ") || !strings.Contains(out, "new local-only vault") {
		t.Errorf("fork output: %s", out)
	}
	rec, err := store.ForkRecord(m.data)
	if err != nil || rec == nil {
		t.Fatalf("no fork record: %v", err)
	}
	v := vaultInfo(t, m)
	if v.Locked || v.AccountID == old.AccountID || v.DeviceID == old.DeviceID || v.AccountID != rec.New.AccountID.String() {
		t.Errorf("the new vault: %+v; old %s %s", v, old.AccountID, old.DeviceID)
	}
	if rec.Old.AccountID.String() != old.AccountID || rec.Old.DeviceID.String() != old.DeviceID {
		t.Errorf("the record's old IDs %+v; want %s %s", rec.Old, old.AccountID, old.DeviceID)
	}
	if a := m.authStatus(t); a.Vault && a.Server != "" {
		t.Errorf("hop auth status after the fork: %+v", a)
	}
	return rec
}

// keptBackup checks that the old vault is in the backup, intact: it opens
// with the old device key and holds hosts.
func keptBackup(t *testing.T, m *machine, rec *store.ForkResult, hosts int) {
	t.Helper()
	s, err := store.Open(context.Background(), store.Config{DataDir: rec.Backup, Keyring: m.ring, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("the backup does not open: %v", err)
	}
	defer s.Close()
	if id := s.Info().DeviceID; id != rec.Old.DeviceID.String() {
		t.Errorf("the backup's device %s; want %s", id, rec.Old.DeviceID)
	}
	if si, err := s.ServerInfo(); err != nil || si.Server == "" {
		t.Errorf("the backup is not the server-backed vault: %+v %v", si, err)
	}
	if hosts >= 0 && !s.Info().Locked {
		snap, err := s.Snapshot(context.Background())
		if err != nil || len(snap.Hosts) != hosts {
			t.Errorf("the backup's hosts: %v %v", len(snap.Hosts), err)
		}
	}
}

// A3c: the operator deleted the account. The device, locked with its copy
// and a change that never reached the server, forks it into a local-only
// vault through the CLI: every host is there, the vault works as any
// local vault (add, edit, rm, lock, unlock, the daemon), the old vault is
// kept, and hop auth signup publishes the fork to a new server.
func TestForkADeletedAccount(t *testing.T) {
	m := signedUp(t)
	m.w.stop()
	m.must(t, nil, "add", "db", "--address", "203.0.113.11", "--user", "ops")
	old := vaultInfo(t, m)
	deleteAccount(t, m)
	m.w.start()

	rec := forkLocal(t, m, old)
	if rec.Pending != 1 || rec.Hosts != 2 {
		t.Errorf("record: %+v", rec.ForkPlan)
	}
	hs := m.hosts(t)
	if hs["web"].Name == "" || hs["db"].Name == "" || len(hs) != 2 {
		t.Fatalf("hosts after the fork: %v", hs)
	}
	keptBackup(t, m, rec, -1)

	m.must(t, nil, "add", "cache", "--address", "203.0.113.12", "--user", "ops")
	m.must(t, nil, "edit", "db", "--user", "admin")
	m.must(t, nil, "rm", "web", "--yes")
	m.must(t, nil, "lock")
	if v := vaultInfo(t, m); !v.Locked {
		t.Error("hop lock did not lock")
	}
	m.must(t, nil, "unlock")
	hs = m.hosts(t)
	if hs["db"].User != "admin" || hs["cache"].Name == "" || hs["web"].Name != "" {
		t.Errorf("after the edits: %v", hs)
	}
	if v := vaultInfo(t, m); v.Locked || v.ServerUnconfirmed || v.AdminLock != nil {
		t.Errorf("the fork is locked: %+v", v)
	}

	// Publish the fork to a fresh server.
	w2 := newAuthWorld(t)
	m.w = w2
	m.must(t, nil, "auth", "signup", "--server", w2.origin, "--email", authEmail, "--code", w2.invite(t), "--json")
	if a := m.authStatus(t); a.Server != w2.origin {
		t.Errorf("auth status after publishing the fork: %+v", a)
	}
	waitFor(t, 20*time.Second, "the published fork syncs", func() bool { st := m.syncState(t); return st.Pending == 0 && st.Held == 0 })
	if hs := m.hosts(t); len(hs) != 2 || hs["db"].User != "admin" {
		t.Errorf("hosts after publishing: %v", hs)
	}
}

// The operator disabled the account, so the daemon holds an admin lock.
// The fork still runs: it stops the daemon and opens the vault with the
// device key, and the daemon it starts again holds an unlocked local
// vault.
func TestForkUnderAnAdminLock(t *testing.T) {
	m := signedUp(t)
	old := vaultInfo(t, m) // a locked vault's status names no device
	ctx := context.Background()
	op := server.Operator{Actor: "test", Now: time.Now().UTC()}
	dis, err := server.PlanDisable(ctx, m.w.st, authEmail, op)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.DisableAccount(ctx, m.w.st, op, authEmail, "billing", dis); err != nil {
		t.Fatal(err)
	}
	m.must(t, nil, "lock")
	if code := m.hop(t, nil, "unlock"); code == 0 {
		t.Fatal("hop unlock of a disabled account succeeded")
	}
	if v := vaultInfo(t, m); !v.Locked || v.AdminLock == nil {
		t.Fatalf("setup: no admin lock: %+v", v)
	}
	rec := forkLocal(t, m, old)
	if hs := m.hosts(t); hs["web"].Name == "" {
		t.Errorf("hosts after the fork: %v", hs)
	}
	keptBackup(t, m, rec, 1)
}

// A logout of a deleted account stays pending (RETIRING). The fork takes
// that vault too, and the new vault is not logging out.
func TestForkAPendingLogout(t *testing.T) {
	m := signedUp(t)
	old := vaultInfo(t, m)
	deleteAccount(t, m)
	if code := m.hop(t, nil, "logout", "--yes"); code == 0 {
		t.Fatal("setup: the logout of a deleted account finished")
	}
	rec := forkLocal(t, m, old)
	if rec.Logout != store.StateRetiring {
		t.Errorf("record: %+v", rec.ForkPlan)
	}
	if hs := m.hosts(t); hs["web"].Name == "" {
		t.Errorf("hosts after the fork: %v", hs)
	}
	if v := vaultInfo(t, m); v.Logout != "" {
		t.Errorf("the fork is logging out: %+v", v)
	}
}

// A device the server reported as revoked is not forked: the account
// removed it. Nothing changes.
func TestForkRefusesAReportedRevocation(t *testing.T) {
	m := signedUp(t)
	m.must(t, nil, "daemon", "stop")
	// Any server-revoked.json counts as the report; one that does not
	// verify only changes how it is shown.
	if err := os.WriteFile(filepath.Join(m.data, "vault", "server-revoked.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := forkSession()
	code := m.hop(t, s, "vault", "fork", "--local", "--yes")
	if code != 255 || !strings.Contains(s.stderr.String(), "removed from its account") {
		t.Errorf("fork of a reported device: exit %d: %s", code, s.stderr.String())
	}
	// m.data.lock is the data directory's gate, which every open takes.
	if matches, _ := filepath.Glob(m.data + ".*"); len(slices.DeleteFunc(matches, func(p string) bool { return p == m.data+".lock" })) != 0 {
		t.Errorf("the refused fork wrote %v", matches)
	}
	if rec, _ := store.ForkRecord(m.data); rec != nil {
		t.Error("the refused fork left a record")
	}
}

// hop vault fork needs --local, and refuses --keep-old with --discard-old,
// before it touches the daemon.
func TestForkFlags(t *testing.T) {
	m := signedUp(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"vault", "fork"}, "needs --local"},
		{[]string{"vault", "fork", "--local", "--keep-old", "--discard-old"}, "exclude each other"},
		{[]string{"vault"}, "usage: hop vault fork --local"},
	} {
		s := &session{}
		if code := m.hop(t, s, c.args...); code != 255 || !strings.Contains(s.stderr.String(), c.want) {
			t.Errorf("%v: exit %d: %s", c.args, code, s.stderr.String())
		}
	}
	// Without --yes and without a terminal, it asks for --yes and changes
	// nothing.
	s := &session{secrets: forkSession().secrets}
	if code := m.hop(t, s, "vault", "fork", "--local"); code != 255 || !strings.Contains(s.stderr.String(), "pass --yes") {
		t.Errorf("no terminal: exit %d: %s", code, s.stderr.String())
	}
	if rec, _ := store.ForkRecord(m.data); rec != nil {
		t.Error("a refused fork left a record")
	}
	if v := vaultInfo(t, m); v.Locked {
		t.Errorf("the vault after a refused fork: %+v", v)
	}
}

// --kit-file may not name a file in a directory the fork moves or deletes:
// the data directory (moved into the backup, deleted by --discard-old),
// also through a symlinked ancestor. Nothing changes.
func TestForkRefusesAKitFileItMoves(t *testing.T) {
	m := signedUp(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(m.data, link); err != nil {
		t.Fatal(err)
	}
	for _, kit := range []string{filepath.Join(m.data, "kit.txt"), filepath.Join(link, "kit.txt"), filepath.Join(m.data, "vault", "kit.txt")} {
		s := forkSession()
		code := m.hop(t, s, "vault", "fork", "--local", "--yes", "--discard-old", "--kit-file", kit)
		if code != 255 || !strings.Contains(s.stderr.String(), "--kit-file") {
			t.Errorf("kit %s: exit %d: %s", kit, code, s.stderr.String())
		}
		if _, err := os.Lstat(kit); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("kit %s was written: %v", kit, err)
		}
		if rec, _ := store.ForkRecord(m.data); rec != nil {
			t.Fatal("the refused fork left a record")
		}
		if pending, _ := store.ForkInProgress(m.data); pending {
			t.Fatal("the refused fork is in progress")
		}
	}
	if v := vaultInfo(t, m); v.Locked {
		t.Errorf("the vault after the refused forks: %+v", v)
	}
}
