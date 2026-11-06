package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// The review of A3c: what a fork must refuse or fence between its verified
// copy and the swap, and what recovery must check before it trusts the
// journal.

// oldVaultIn requires dir to hold the old vault, by its device.json.
func oldVaultIn(t *testing.T, dir string, old ids) {
	t.Helper()
	dc := diskDeviceConfig(t, Config{DataDir: dir})
	if dc.AccountID != old.acct || dc.DeviceID != old.dev {
		t.Fatalf("%s holds %v %v, not the old vault", dir, dc.AccountID, dc.DeviceID)
	}
}

// forkBackups lists the fork backups beside dataDir.
func forkBackups(t *testing.T, dataDir string) []string {
	t.Helper()
	m, err := filepath.Glob(dataDir + forkBackupStem + "*")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// lastEntry is the path of the newest entry file of the vault in dir.
func lastEntry(t *testing.T, dir string) string {
	t.Helper()
	l := layout{data: dir}
	seqs, err := l.entrySeqs()
	if err != nil || len(seqs) == 0 {
		t.Fatalf("entries of %s: %v %v", dir, seqs, err)
	}
	return l.entryFile(seqs[len(seqs)-1])
}

// copyTree copies the directory tree src to dst, keeping modes.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(to, info.Mode().Perm())
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(to, b, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

// After the new vault verified, the old vault is fenced: an ordinary open
// is refused with ErrForkPending, so nothing is added to it that the swap
// would put away (P1).
func TestForkFencesTheOldVault(t *testing.T) {
	x := forkFixture(t)
	cfg := x.f.cfg
	crashForkAt(t, cfg, "fork:verified", false)
	if s, err := Open(context.Background(), cfg); !errors.Is(err, ErrForkPending) {
		if err == nil {
			s.Close()
		}
		t.Fatalf("open after a verified fork: %v, want ErrForkPending", err)
	}
	if _, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword)}); !errors.Is(err, ErrForkPending) {
		t.Errorf("init over a fork in progress: %v, want ErrForkPending", err)
	}
	if _, err := ResumeEnrollment(cfg); !errors.Is(err, ErrForkPending) {
		t.Errorf("an enrollment over a fork in progress: %v, want ErrForkPending", err)
	}
	if _, _, err := ResumeFork(context.Background(), cfg, ForkOptions{}); err != nil {
		t.Fatal(err)
	}
	if s := open(t, cfg); s.Info().Locked {
		t.Errorf("the forked vault after the resume: %+v", s.Info())
	}
}

// A revocation recorded in the old vault after the fork verified its copy
// (by a hop that does not know the fence) makes the resume refuse: the
// source no longer matches what was copied (P1).
func TestForkResumeRefusesARevokedSource(t *testing.T) {
	x := forkFixture(t)
	cfg := x.f.cfg
	old := idsOf(t, cfg)
	crashForkAt(t, cfg, "fork:verified", false)
	if err := writeFileAtomic(layout{data: cfg.DataDir}.revokedFile(), []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResumeFork(context.Background(), cfg, ForkOptions{}); !errors.Is(err, ErrForkStale) {
		t.Fatalf("the resume after a revocation: %v, want ErrForkStale", err)
	}
	oldVaultIn(t, cfg.DataDir, old)
	if b := forkBackups(t, cfg.DataDir); len(b) != 0 {
		t.Errorf("backups: %v", b)
	}
	if _, err := os.Lstat(cfg.DataDir + forkNewSuffix); err != nil {
		t.Errorf("the staging directory: %v", err)
	}
}

// A staging directory damaged after it verified is not swapped in, and
// nothing is deleted (P1).
func TestForkResumeRefusesDamagedStaging(t *testing.T) {
	x := forkFixture(t)
	cfg := x.f.cfg
	old := idsOf(t, cfg)
	crashForkAt(t, cfg, "fork:verified", false)
	staging := cfg.DataDir + forkNewSuffix
	if err := os.Remove(lastEntry(t, staging)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResumeFork(context.Background(), cfg, ForkOptions{}); !errors.Is(err, ErrForkDamaged) {
		t.Fatalf("a damaged staging directory: %v, want ErrForkDamaged", err)
	}
	oldVaultIn(t, cfg.DataDir, old)
	if _, err := os.Lstat(staging); err != nil {
		t.Errorf("the staging directory: %v", err)
	}
	if b := forkBackups(t, cfg.DataDir); len(b) != 0 {
		t.Errorf("backups: %v", b)
	}
}

// A fork's directories copied elsewhere do not resume against the paths
// their journal names: recovery derives them from the directory asked for
// (P1).
func TestForkResumeRefusesARelocatedJournal(t *testing.T) {
	x := forkFixture(t)
	cfg := x.f.cfg
	old := idsOf(t, cfg)
	crashForkAt(t, cfg, "fork:verified", false)
	other := filepath.Join(t.TempDir(), "elsewhere")
	copyTree(t, cfg.DataDir, other)
	copyTree(t, cfg.DataDir+forkNewSuffix, other+forkNewSuffix)
	ocfg := cfg
	ocfg.DataDir = other
	if _, _, err := ResumeFork(context.Background(), ocfg, ForkOptions{}); !errors.Is(err, ErrForkDamaged) {
		t.Errorf("a relocated journal: %v, want ErrForkDamaged", err)
	}
	if _, err := AbandonFork(context.Background(), ocfg); !errors.Is(err, ErrForkDamaged) {
		t.Errorf("abandoning a relocated journal: %v, want ErrForkDamaged", err)
	}
	oldVaultIn(t, cfg.DataDir, old)
	if b := forkBackups(t, cfg.DataDir); len(b) != 0 {
		t.Errorf("the original was moved: %v", b)
	}
	// The original still resumes.
	if res, _, err := ResumeFork(context.Background(), cfg, ForkOptions{}); err != nil || res == nil {
		t.Fatalf("the original's resume: %+v %v", res, err)
	}
}

// A journal whose new identity was altered is refused.
func TestForkResumeRefusesAnAlteredJournal(t *testing.T) {
	x := forkFixture(t)
	cfg := x.f.cfg
	old := idsOf(t, cfg)
	crashForkAt(t, cfg, "fork:verified", false)
	staging := cfg.DataDir + forkNewSuffix
	j, err := readForkJournal(staging)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	if j.New.DeviceID, err = vaultlog.NewID(); err != nil {
		t.Fatal(err)
	}
	if err := writeForkJournal(staging, j); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResumeFork(context.Background(), cfg, ForkOptions{}); !errors.Is(err, ErrForkDamaged) {
		t.Errorf("an altered journal: %v, want ErrForkDamaged", err)
	}
	oldVaultIn(t, cfg.DataDir, old)
}

// The backup is deleted only once the new vault in the data directory
// verifies: a crash after the swap, then damage to the new vault, keeps the
// backup (P1).
func TestForkKeepsTheBackupUnlessTheNewVaultVerifies(t *testing.T) {
	x := forkFixture(t)
	cfg := x.f.cfg
	old := idsOf(t, cfg)
	crashForkAt(t, cfg, "fork:moved-new", true)
	if err := os.Remove(lastEntry(t, cfg.DataDir)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResumeFork(context.Background(), cfg, ForkOptions{}); !errors.Is(err, ErrForkDamaged) {
		t.Errorf("a damaged new vault: %v, want ErrForkDamaged", err)
	}
	b := forkBackups(t, cfg.DataDir)
	if len(b) != 1 {
		t.Fatalf("backups: %v", b)
	}
	oldVaultIn(t, b[0], old)
	if _, err := cfg.Keyring.Get(keychainService, slotOf(old.acct, old.dev)); err != nil {
		t.Errorf("the old device key: %v", err)
	}
	// Without a staging directory, a journal in a data directory that holds
	// no vault is refused the same way.
	if err := os.RemoveAll(layout{data: cfg.DataDir}.vault()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResumeFork(context.Background(), cfg, ForkOptions{}); !errors.Is(err, ErrForkDamaged) {
		t.Errorf("a data directory with no vault: %v, want ErrForkDamaged", err)
	}
	if len(forkBackups(t, cfg.DataDir)) != 1 {
		t.Error("the backup was deleted")
	}
}

// A data directory reached through a symlink: a crash after the old
// directory moved leaves the link dangling, and the fork is still found
// and finished through it (P2).
func TestForkResumeThroughASymlink(t *testing.T) {
	x := forkFixture(t)
	real := x.f.cfg
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real.DataDir, link); err != nil {
		t.Fatal(err)
	}
	release(real)
	cfg := real
	cfg.DataDir = link
	crashForkAt(t, cfg, "fork:moved-old", false)
	if _, err := os.Stat(link); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("setup: the link should dangle: %v", err)
	}
	if pending, err := ForkInProgress(link); err != nil || !pending {
		t.Errorf("in progress through the link: %v %v", pending, err)
	}
	res, _, err := ResumeFork(context.Background(), cfg, ForkOptions{})
	if err != nil || res == nil {
		t.Fatalf("resume through the link: %+v %v", res, err)
	}
	// hop opens a data directory by its real path (safepath refuses a
	// symlink there); the link names the new vault again.
	if s := open(t, real); s.Info().Locked || s.Info().AccountID != res.New.AccountID.String() {
		t.Errorf("the new vault: %+v", s.Info())
	}
	if pending, err := ForkInProgress(link); err != nil || pending {
		t.Errorf("in progress through the link after the resume: %v %v", pending, err)
	}
	if want, _ := filepath.EvalSymlinks(real.DataDir); res.DataDir != want {
		t.Errorf("data dir %s; want %s", res.DataDir, want)
	}
}

// Nothing else can own or make the data directory while the swap has it
// moved aside: an init there is refused, and the swap finishes (P1).
func TestForkOwnsTheDataDirDuringTheSwap(t *testing.T) {
	x := forkFixture(t)
	cfg := x.f.cfg
	release(cfg)
	p, err := PrepareFork(context.Background(), cfg, ForkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.Generate([]byte(forkPassword), ""); err != nil {
		t.Fatal(err)
	}
	var tried []error
	forkHook = func(stage string) error {
		if stage != "fork:moved-old" {
			return nil
		}
		if s, err := Open(context.Background(), cfg); err == nil {
			s.Close()
			tried = append(tried, errors.New("open succeeded"))
		}
		if pi, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword)}); err == nil {
			if s, err := pi.Commit(); err == nil {
				s.Close()
				tried = append(tried, errors.New("init succeeded"))
			}
		}
		return nil
	}
	defer func() { forkHook = nil }()
	res, err := p.Commit(context.Background(), false)
	forkHook = nil
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := tryOpen(t, cfg); !errors.Is(err, ErrVaultBusy) {
		t.Errorf("open while the fork is not closed: %v, want ErrVaultBusy", err)
	}
	p.Close()
	for _, e := range tried {
		t.Error(e)
	}
	if s := open(t, cfg); s.Info().AccountID != res.New.AccountID.String() {
		t.Errorf("the vault after the swap: %+v", s.Info())
	}
}

// A crash after the keychain holds the new device key and before
// device.json names it: the abandoned fork's cleanup finds the key from the
// journal (P3).
func TestForkAbandonFindsAnUnnamedKeychainEntry(t *testing.T) {
	x := forkFixture(t)
	cfg := x.f.cfg
	ring := cfg.Keyring.(*memRing)
	release(cfg)
	p, err := PrepareFork(context.Background(), cfg, ForkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Generate([]byte(forkPassword), ""); err != nil {
		t.Fatal(err)
	}
	p.init.s.testHook = func(stage string) error {
		if stage == "init:device-key" {
			panic(forkCrash{})
		}
		return nil
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(forkCrash); !ok {
					panic(r)
				}
			}
		}()
		p.Commit(context.Background(), false)
		t.Fatal("the fork did not stop between the keychain and device.json")
	}()
	p.Close()
	ring.mu.Lock()
	n := len(ring.m)
	ring.mu.Unlock()
	if n != 2 {
		t.Fatalf("setup: the keychain holds %d entries", n)
	}
	if _, abandoned, err := ResumeFork(context.Background(), cfg, ForkOptions{}); err != nil || !abandoned {
		t.Fatalf("resume: %v %v", abandoned, err)
	}
	ring.mu.Lock()
	n = len(ring.m)
	ring.mu.Unlock()
	if n != 1 {
		t.Errorf("the keychain holds %d entries after the abandon; want only the old device's", n)
	}
}

// forkSnippets is n small snippets for forkWrite.
func forkSnippets(t *testing.T, n int) []crypto.Item {
	t.Helper()
	out := make([]crypto.Item, n)
	for i := range out {
		id, err := vaultlog.NewID()
		if err != nil {
			t.Fatal(err)
		}
		out[i] = &model.Snippet{Header: model.Header{Type: model.TypeSnippet, ItemID: id}, Name: fmt.Sprintf("s%d", i), Command: "true", Params: []string{}}
	}
	return out
}

// entriesSince returns the entries of s's vault after seq.
func entriesSince(t *testing.T, s *Store, seq uint64) []*vaultlog.Wire {
	t.Helper()
	seqs, err := s.l.entrySeqs()
	if err != nil {
		t.Fatal(err)
	}
	var out []*vaultlog.Wire
	for _, n := range seqs {
		if n <= seq {
			continue
		}
		w, err := s.l.readEntry(n)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, w)
	}
	return out
}

// Every entry a fork writes passes the server's admission: puts and
// deletes are split until each fits, at the op limit's boundary, and an
// item too large for any entry is refused by name before anything of it
// is committed (P2).
func TestForkWriteAdmission(t *testing.T) {
	f := newVault(t, testConfig(t))
	s := f.s
	items := forkSnippets(t, maxOpsPerWire+1)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < len(items); i += 2048 {
		if err := s.forkWrite(vaultlog.Changes{Put: items[i:min(i+2048, len(items))]}); err != nil {
			t.Fatal(err)
		}
	}
	ids := make([]model.ID, len(items))
	for i, it := range items {
		ids[i] = header(it).ItemID
	}
	check := func(what string, from uint64, want int) {
		t.Helper()
		ws := entriesSince(t, s, from)
		if len(ws) != want {
			t.Errorf("%s: %d entries, want %d", what, len(ws), want)
		}
		for _, w := range ws {
			if err := admitWire(w); err != nil {
				t.Errorf("%s: entry %d: %v", what, w.Entry.Seq, err)
			}
		}
	}

	// Exactly the op limit is one entry; one more is two.
	head := s.state.Head.Seq
	if err := s.forkWrite(vaultlog.Changes{Delete: ids[:maxOpsPerWire]}); err != nil {
		t.Fatal(err)
	}
	check("8192 deletes", head, 1)
	rest := forkSnippets(t, maxOpsPerWire)
	for i := 0; i < len(rest); i += 2048 {
		if err := s.forkWrite(vaultlog.Changes{Put: rest[i : i+2048]}); err != nil {
			t.Fatal(err)
		}
	}
	head = s.state.Head.Seq
	del := []model.ID{ids[maxOpsPerWire]}
	for _, it := range rest {
		del = append(del, header(it).ItemID)
	}
	if err := s.forkWrite(vaultlog.Changes{Delete: del}); err != nil {
		t.Fatal(err)
	}
	check("8193 deletes", head, 2)

	// One item over 1 MiB fits no entry: refused, by name, and nothing is
	// committed.
	id, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	big := &model.Host{Header: model.Header{Type: model.TypeHost, ItemID: id}, Name: "huge", Addresses: []string{"10.0.0.1"}, Port: 22,
		Route: "auto", AgentAccess: "allow", Tags: manyTags("t", 40000)}
	head = s.state.Head.Seq
	err = s.forkWrite(vaultlog.Changes{Put: []crypto.Item{big}})
	if !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), `host "huge"`) {
		t.Errorf("an item over 1 MiB: %v", err)
	}
	if s.state.Head.Seq != head || len(entriesSince(t, s, head)) != 0 {
		t.Error("the oversize item was committed")
	}
}

// A write to the old vault after the fork verified its copy, by a hop that
// does not know the fence (an older binary), makes the resume refuse; the
// fork is then given up, the old vault keeps the write, and a new fork
// carries it (P1).
func TestForkResumeRefusesAnInterveningWrite(t *testing.T) {
	ctx := context.Background()
	x := forkFixture(t)
	cfg := x.f.cfg
	old := idsOf(t, cfg)
	crashForkAt(t, cfg, "fork:verified", false)
	s, err := openStore(ctx, cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	newCredential(t, s, "added offline")
	s.Close()
	if _, _, err := ResumeFork(ctx, cfg, ForkOptions{}); !errors.Is(err, ErrForkStale) {
		t.Fatalf("resume after a write: %v, want ErrForkStale", err)
	}
	oldVaultIn(t, cfg.DataDir, old)
	if b := forkBackups(t, cfg.DataDir); len(b) != 0 {
		t.Fatalf("backups: %v", b)
	}
	if ok, err := AbandonFork(ctx, cfg); err != nil || !ok {
		t.Fatalf("abandon: %v %v", ok, err)
	}
	if pending, err := ForkInProgress(cfg.DataDir); err != nil || pending {
		t.Fatalf("in progress after the abandon: %v %v", pending, err)
	}
	ring := cfg.Keyring.(*memRing)
	ring.mu.Lock()
	n := len(ring.m)
	ring.mu.Unlock()
	if n != 1 {
		t.Errorf("the keychain holds %d entries; want only the old device's", n)
	}
	o := open(t, cfg)
	if o.Info().AccountID != old.acct.String() {
		t.Fatalf("the vault after the abandon: %+v", o.Info())
	}
	found := false
	for _, c := range snapshot(t, o).Credentials {
		found = found || c.Name == "added offline"
	}
	if !found {
		t.Fatal("the write to the old vault is gone")
	}
	fork(t, cfg, false)
	found = false
	for _, c := range snapshot(t, open(t, cfg)).Credentials {
		found = found || c.Name == "added offline"
	}
	if !found {
		t.Error("the new fork did not carry the write")
	}
}

// A fork abandoned after the swap moved the old vault aside puts it back;
// one whose new vault is in place is not abandoned, and finishes.
func TestForkAbandon(t *testing.T) {
	ctx := context.Background()
	x := forkFixture(t)
	cfg := x.f.cfg
	old := idsOf(t, cfg)
	before := itemsByName(snapshot(t, x.f.s))
	crashForkAt(t, cfg, "fork:moved-old", false)
	if _, err := os.Lstat(cfg.DataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("setup: the data directory: %v", err)
	}
	if ok, err := AbandonFork(ctx, cfg); err != nil || !ok {
		t.Fatalf("abandon: %v %v", ok, err)
	}
	oldVaultIn(t, cfg.DataDir, old)
	if b := forkBackups(t, cfg.DataDir); len(b) != 0 {
		t.Errorf("backups after the abandon: %v", b)
	}
	if _, err := os.Lstat(cfg.DataDir + forkNewSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the staging directory: %v", err)
	}
	if got := itemsByName(snapshot(t, open(t, cfg))); len(got) != len(before) {
		t.Errorf("items %v; before %v", got, before)
	}
	if ok, err := AbandonFork(ctx, cfg); err != nil || ok {
		t.Errorf("abandon with nothing to give up: %v %v", ok, err)
	}

	crashForkAt(t, cfg, "fork:moved-new", false)
	if _, err := AbandonFork(ctx, cfg); !errors.Is(err, ErrForkRefused) {
		t.Errorf("abandon with the new vault in place: %v, want ErrForkRefused", err)
	}
	if res, _, err := ResumeFork(ctx, cfg, ForkOptions{}); err != nil || res == nil {
		t.Fatalf("resume: %+v %v", res, err)
	}
	if b := forkBackups(t, cfg.DataDir); len(b) != 1 {
		t.Errorf("backups: %v", b)
	}
}

// A vault holding an item of a type the fork does not carry is refused.
func TestForkCarriesOnlyKnownTypes(t *testing.T) {
	for _, ty := range []model.Type{model.TypeHost, model.TypeKey, model.TypeCredential, model.TypeSnippet, model.TypePolicy} {
		if !forkCarries(ty) {
			t.Errorf("%s is not carried", ty)
		}
	}
	for _, ty := range []model.Type{model.TypeGrant, "access", ""} {
		if forkCarries(ty) {
			t.Errorf("%q is carried", ty)
		}
	}
}

// Abandoning a staging directory whose journal can't be read and whose
// device.json names the old device never deletes the old device's key.
func TestForkAbandonKeepsTheOldDeviceKey(t *testing.T) {
	x := forkFixture(t)
	cfg := x.f.cfg
	old := idsOf(t, cfg)
	crashForkAt(t, cfg, "fork:verified", false)
	staging := cfg.DataDir + forkNewSuffix
	b, err := os.ReadFile(layout{data: cfg.DataDir}.deviceConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout{data: staging}.deviceConfig(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(forkJournalFile(staging), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResumeFork(context.Background(), cfg, ForkOptions{}); !errors.Is(err, ErrForkDamaged) {
		t.Errorf("resume with an unreadable journal: %v, want ErrForkDamaged", err)
	}
	if ok, err := AbandonFork(context.Background(), cfg); err != nil || !ok {
		t.Fatalf("abandon: %v %v", ok, err)
	}
	if _, err := cfg.Keyring.Get(keychainService, slotOf(old.acct, old.dev)); err != nil {
		t.Errorf("the old device key was deleted: %v", err)
	}
	if s := open(t, cfg); s.Info().Locked || s.Info().AccountID != old.acct.String() {
		t.Errorf("the old vault after the abandon: %+v", s.Info())
	}
}
