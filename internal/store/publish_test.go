package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

const testEmail = "Me@example.com"

var pubOpts = PublishOptions{Server: "https://hop.test", Email: " Me@Example.COM\t", RegistrationCode: "invite-1"}

// publishFixture is a local-only vault with a host, and an empty server
// that has a registration code for it.
func publishFixture(t *testing.T) (*fixture, *fakeServer) {
	t.Helper()
	f := newVault(t, testConfig(t))
	addHost(t, f.s, "web")
	return f, newEmptyServer(testEmail, "invite-1")
}

// crashAfter returns a hook that fails at stage, once, but only after
// first has been reached.
func crashAfter(first, stage string) func(string) error {
	armed, done := first == "", false
	return func(s string) error {
		if s == first {
			armed = true
		}
		if armed && !done && s == stage {
			done = true
			return errCrash
		}
		return nil
	}
}

// sameLog requires the server's log to be exactly the local log.
func sameLog(t *testing.T, cfg Config, srv *fakeServer) {
	t.Helper()
	l := layout{data: cfg.DataDir}
	seqs, err := l.entrySeqs()
	if err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(seqs) != len(srv.hashes) {
		t.Fatalf("local log has %d entries, the server %d", len(seqs), len(srv.hashes))
	}
	for _, seq := range seqs {
		w, err := l.readEntry(seq)
		if err != nil {
			t.Fatal(err)
		}
		h, err := w.Entry.Hash()
		if err != nil {
			t.Fatal(err)
		}
		if !h.Equal(srv.hashes[seq]) {
			t.Errorf("entry %d differs from the server's", seq)
		}
	}
}

func published(t *testing.T, f *fixture, s *Store, srv *fakeServer) {
	t.Helper()
	if !s.ServerBacked() {
		t.Error("the vault is not server-backed after the publication")
	}
	if _, err := os.Stat(filepath.Join(f.cfg.DataDir, "vault", publishRel)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("publish.json is still there: %v", err)
	}
	if p, err := s.Publication(); err != nil || p != nil {
		t.Errorf("publication after it finished: %+v %v", p, err)
	}
	sameLog(t, f.cfg, srv)
}

// §4.3: an existing vault is published as one upload of its whole log,
// with the proof of possession the server verifies; then it is
// server-backed and its writes queue.
func TestPublishExistingVault(t *testing.T) {
	ctx := context.Background()
	f, srv := publishFixture(t)
	head := headOf(t, f.s)
	pub, err := f.s.Publish(ctx, publisher{srv}, pubOpts)
	if err != nil {
		t.Fatal(err)
	}
	if pub.Server != pubOpts.Server || pub.Email != testEmail || pub.Upload != head {
		t.Errorf("result %+v; want the server, %q and head %v", pub, testEmail, head)
	}
	published(t, f, f.s, srv)
	if srv.signups != 1 {
		t.Errorf("%d signups", srv.signups)
	}
	// From now on writes go through the outbox to the server.
	newCredential(t, f.s, "after")
	if len(records(t, f.s)) != 1 {
		t.Fatal("a write after the publication did not queue")
	}
	if res := pushAll(t, f.s, srv.fakeRemote); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	sameLog(t, f.cfg, srv)
	// The publication survives a restart as a server-backed vault.
	s := open(t, f.cfg)
	if !s.ServerBacked() {
		t.Error("not server-backed after a restart")
	}
}

// The registration capability is kept sealed under local_key, never in
// the clear, next to the journal.
func TestPublicationJournalIsSealed(t *testing.T) {
	ctx := context.Background()
	f, srv := publishFixture(t)
	srv.down = errDown
	if _, err := f.s.Publish(ctx, publisher{srv}, pubOpts); err == nil {
		t.Fatal("published to an unreachable server")
	}
	b, err := os.ReadFile(filepath.Join(f.cfg.DataDir, "vault", publishRel))
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"invite-1", testEmail, "hop.test"} {
		if bytes.Contains(b, []byte(needle)) {
			t.Errorf("publish.json holds %q in the clear", needle)
		}
	}
	// Every AAD field matters: another vault ID does not open it.
	var pf publicationFile
	if err := canonjson.Unmarshal(b, &pf); err != nil {
		t.Fatal(err)
	}
	f.s.mu.Lock()
	key, _ := f.s.rec.localKey()
	vid := f.s.state.VaultID
	f.s.mu.Unlock()
	other := vid
	other[0] ^= 1
	if _, err := crypto.OpenAEAD(key, pf.Sealed, publicationAAD(other)); err == nil {
		t.Error("the publication opens under another vault ID")
	}
	if _, err := crypto.OpenAEAD(key, pf.Sealed, append(crypto.LP([]byte(labelOutbox)), crypto.LP(vid[:])...)); err == nil {
		t.Error("the publication opens under another label")
	}
	if _, err := crypto.OpenAEAD(key, pf.Sealed, publicationAAD(vid)); err != nil {
		t.Errorf("the publication does not open: %v", err)
	}
}

// §13: a lost signup response, then recovery. The upload committed but
// the response was lost and the client stopped before resolving: after a
// restart the resolution finds the entry at upload_seq and finishes,
// without posting again.
func TestPublishLostResponseThenRecovery(t *testing.T) {
	ctx := context.Background()
	f, srv := publishFixture(t)
	srv.onSignup = func() (bool, error) { return true, errLostResponse }
	f.s.testHook = crashAt("publish:resolve")
	if _, err := f.s.Publish(ctx, publisher{srv}, pubOpts); !errors.Is(err, errCrash) {
		t.Fatalf("publish: %v", err)
	}
	srv.onSignup = nil
	s := open(t, f.cfg)
	if p, err := s.Publication(); err != nil || p == nil {
		t.Fatalf("pending publication after the restart: %+v %v", p, err)
	}
	if _, err := s.PutHost(ctx, model.Host{Name: "x", Port: 22, Route: "auto", AgentAccess: "allow"}); !errors.Is(err, ErrPublicationPending) {
		t.Errorf("a write while pending: %v", err)
	}
	if _, err := s.ResumePublish(ctx, publisher{srv}); err != nil {
		t.Fatal(err)
	}
	published(t, f, s, srv)
	if srv.signups != 1 {
		t.Errorf("%d signups; the committed upload was posted again", srv.signups)
	}

	// The request was lost before the server saw it: the resolution finds
	// no vault and posts the identical upload again.
	g, srv2 := publishFixture(t)
	srv2.onSignup = func() (bool, error) { return false, errLostResponse }
	g.s.testHook = crashAt("publish:resolve")
	if _, err := g.s.Publish(ctx, publisher{srv2}, pubOpts); !errors.Is(err, errCrash) {
		t.Fatalf("publish: %v", err)
	}
	srv2.onSignup = nil
	s = open(t, g.cfg)
	if _, err := s.ResumePublish(ctx, publisher{srv2}); err != nil {
		t.Fatal(err)
	}
	published(t, g, s, srv2)
	if srv2.signups != 2 {
		t.Errorf("%d signups; want the identical upload posted again", srv2.signups)
	}
}

// §13: the server's head is already past upload_seq (another device signed
// in first): the later entries are verified by transition before the
// switch.
func TestPublishServerHeadPastUploadSeq(t *testing.T) {
	ctx := context.Background()
	f, srv := publishFixture(t)
	f.s.testHook = crashAt("publish:resolve")
	if _, err := f.s.Publish(ctx, publisher{srv}, pubOpts); !errors.Is(err, errCrash) {
		t.Fatalf("publish: %v", err)
	}
	s := open(t, f.cfg)
	upload := headOf(t, s)
	// Another device bootstraps on the server.
	other, info, err := newDeviceRecord(s.devCfg.AccountID, f.kit.SecretKey)
	if err != nil {
		t.Fatal(err)
	}
	other.zero()
	info.Name = "other"
	s.mu.Lock()
	w, _, _, err := vaultlog.BuildBootstrap(s.state, s.sec, info, s.now())
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.commit(w); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResumePublish(ctx, publisher{srv}); err != nil {
		t.Fatal(err)
	}
	published(t, f, s, srv)
	if got := headOf(t, s); got.Seq != upload.Seq+1 {
		t.Errorf("head %d; want %d, past the upload", got.Seq, upload.Seq+1)
	}
	s.mu.Lock()
	_, active := s.state.Devices[info.ID]
	s.mu.Unlock()
	if !active {
		t.Error("the other device's bootstrap was not verified")
	}

	// A later entry that fails verification is not accepted, and the
	// publication stays pending.
	g, srv2 := publishFixture(t)
	g.s.testHook = crashAt("publish:resolve")
	if _, err := g.s.Publish(ctx, publisher{srv2}, pubOpts); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	s = open(t, g.cfg)
	s.mu.Lock()
	bad, _, _, err := vaultlog.BuildBootstrap(s.state, s.sec, info, s.now())
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	bad.Sigs[0].Sig[0] ^= 1
	srv2.mu.Lock()
	b, _ := (&vaultlog.Wire{Entry: bad.Entry, Sigs: bad.Sigs, Objects: []vaultlog.Object{}}).Marshal()
	h, _ := bad.Entry.Hash()
	srv2.entries, srv2.hashes = append(srv2.entries, b), append(srv2.hashes, h)
	for _, o := range bad.Objects {
		srv2.objects[o.SHA256] = o.Body
	}
	srv2.mu.Unlock()
	if _, err := s.ResumePublish(ctx, publisher{srv2}); err == nil {
		t.Fatal("a later entry with a bad signature was accepted")
	}
	if p, _ := s.Publication(); p == nil || s.ServerBacked() {
		t.Error("the publication finished over an entry that fails verification")
	}
}

// §13: local appends are refused while the publication is pending, so the
// uploaded head stays fixed.
func TestAppendsRefusedWhilePublicationPending(t *testing.T) {
	ctx := context.Background()
	f, srv := publishFixture(t)
	srv.down = errDown
	head := headOf(t, f.s)
	if _, err := f.s.Publish(ctx, publisher{srv}, pubOpts); err == nil || errors.Is(err, ErrPublicationPending) {
		t.Fatalf("publish to an unreachable server: %v", err)
	}
	s := f.s
	if p, err := s.Publication(); err != nil || p == nil || p.Email != testEmail || p.Upload != head {
		t.Fatalf("pending publication %+v %v", p, err)
	}
	key, host := model.Key{}, model.Host{}
	for _, h := range snapshot(t, s).Hosts {
		host = h
	}
	key = snapshot(t, s).Keys[0]
	if _, err := s.PutHost(ctx, model.Host{Name: "x", Port: 22, Route: "auto", AgentAccess: "allow"}); !errors.Is(err, ErrPublicationPending) {
		t.Errorf("create: %v", err)
	}
	host.Description = "edited"
	if _, err := s.PutHost(ctx, host); !errors.Is(err, ErrPublicationPending) {
		t.Errorf("put: %v", err)
	}
	if err := s.Delete(ctx, key.ItemID); !errors.Is(err, ErrPublicationPending) {
		t.Errorf("delete: %v", err)
	}
	if _, err := s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword)); !errors.Is(err, ErrPublicationPending) {
		t.Errorf("hop passwd: %v", err)
	}
	if err := s.EnableServerMode(); !errors.Is(err, ErrPublicationPending) {
		t.Errorf("server mode: %v", err)
	}
	if _, err := s.MergeStart(); !errors.Is(err, ErrPublicationPending) {
		t.Errorf("merge: %v", err)
	}
	if _, err := s.Publish(ctx, publisher{srv}, pubOpts); !errors.Is(err, ErrPublicationPending) {
		t.Errorf("a second publish: %v", err)
	}
	if got := headOf(t, s); got != head {
		t.Errorf("head moved from %v to %v", head, got)
	}
	// A password unlock's local bootstrap is an append too.
	if err := s.UnlockWithPassword(ctx, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrPublicationPending) {
		t.Errorf("password unlock: %v", err)
	}
	// After a restart too.
	s = open(t, f.cfg)
	if _, err := s.PutHost(ctx, model.Host{Name: "x", Port: 22, Route: "auto", AgentAccess: "allow"}); !errors.Is(err, ErrPublicationPending) {
		t.Errorf("create after a restart: %v", err)
	}
	srv.down = nil
	if _, err := s.ResumePublish(ctx, publisher{srv}); err != nil {
		t.Fatal(err)
	}
	published(t, f, s, srv)
	if _, err := s.PutHost(ctx, model.Host{Name: "x", Port: 22, Route: "auto", AgentAccess: "allow"}); err != nil {
		t.Errorf("a write after the publication: %v", err)
	}
}

// §13: a different H at upload_seq is an equivocation: the alarm, and the
// publication stays pending. So it is when the server's log also goes on
// past upload_seq.
func TestPublishDifferentHAtUploadSeq(t *testing.T) {
	for _, past := range []int{0, 2} {
		testPublishDifferentH(t, past)
	}
}

func testPublishDifferentH(t *testing.T, past int) {
	ctx := context.Background()
	f, _ := publishFixture(t)
	// A copy of the vault diverges at the next seq; the server holds the
	// copy's log under the same vault ID.
	cfg2 := testConfig(t)
	cfg2.Keyring = f.cfg.Keyring
	copyDir(t, f.cfg.DataDir, cfg2.DataDir)
	other, err := Open(ctx, cfg2)
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg2, other)
	newCredential(t, other, "theirs")
	for i := range past {
		newCredential(t, other, "theirs later "+strings.Repeat("x", i))
	}
	newCredential(t, f.s, "mine")
	srv := newFakeServer(t, newFakeRemote(t, cfg2.DataDir))
	srv.email, srv.code = testEmail, "invite-1"
	srv.mu.Lock()
	srv.upload = append([]crypto.Hash(nil), srv.hashes...)
	srv.mu.Unlock()

	_, err = f.s.Publish(ctx, publisher{srv}, pubOpts)
	var eq *vaultlog.EquivocationError
	if !errors.As(err, &eq) {
		t.Fatalf("publish over a different log: %v; want an equivocation", err)
	}
	p, err := f.s.Publication()
	if err != nil || p == nil || p.Alarm == "" {
		t.Errorf("pending publication %+v %v; want it pending with the alarm", p, err)
	}
	if f.s.ServerBacked() {
		t.Error("server-backed after an equivocation")
	}
	if _, err := f.s.ResumePublish(ctx, publisher{srv}); !errors.As(err, &eq) {
		t.Errorf("resume: %v; want the equivocation again", err)
	}
	if _, err := f.s.PutHost(ctx, model.Host{Name: "x", Port: 22, Route: "auto", AgentAccess: "allow"}); !errors.Is(err, ErrPublicationPending) {
		t.Errorf("a write after the alarm: %v", err)
	}
}

// §13: a crash at each publication state, including every durable step of
// the journal's commit and of the final switch, resumes to one published
// vault whose log is the server's.
func TestPublishCrashAtEachState(t *testing.T) {
	type crash struct {
		name string
		hook func(string) error
	}
	var crashes []crash
	for _, st := range []string{"wal:before", "wal:install", "wal:install:sync", "wal:op:0", "wal:op:0:sync", "wal:applied", "wal:removed",
		"publish:journaled", "publish:post", "publish:resolve", "publish:switch"} {
		crashes = append(crashes, crash{st, crashAt(st)})
	}
	for _, st := range []string{"wal:before", "wal:install:sync", "wal:op:0", "wal:op:0:sync", "wal:op:1", "wal:op:1:sync", "wal:removed"} {
		crashes = append(crashes, crash{"switch " + st, crashAfter("publish:switch", st)})
	}
	for _, c := range crashes {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			f, srv := publishFixture(t)
			f.s.testHook = c.hook
			if _, err := f.s.Publish(ctx, publisher{srv}, pubOpts); !errors.Is(err, errCrash) {
				t.Fatalf("publish: %v", err)
			}
			s := open(t, f.cfg)
			p, err := s.Publication()
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case s.ServerBacked():
				if p != nil {
					t.Error("server-backed with the journal still there")
				}
			case p != nil:
				if _, err := s.ResumePublish(ctx, publisher{srv}); err != nil {
					t.Fatal(err)
				}
			default:
				// The journal never committed: nothing happened.
				if srv.signups != 0 {
					t.Error("posted without a journal")
				}
				if _, err := s.Publish(ctx, publisher{srv}, pubOpts); err != nil {
					t.Fatal(err)
				}
			}
			published(t, f, s, srv)
		})
	}
}

// Preflight (§4.3, plan R9, R14): a checkpoint journal or an
// unacknowledged kit, a published vault, a bad email and an upload past
// the limits are refused before anything is journaled.
func TestPublishPreflight(t *testing.T) {
	ctx := context.Background()
	f, srv := publishFixture(t)
	if _, err := f.s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Publish(ctx, publisher{srv}, pubOpts); !errors.Is(err, ErrCheckpointPending) {
		t.Errorf("with a pending kit: %v", err)
	}
	if err := f.s.AckKit(); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"", "no-at", "a b@example.com", "x@exa_mple.com", "é@example.com", ".a@example.com", strings.Repeat("a", 65) + "@example.com"} {
		opts := pubOpts
		opts.Email = email
		if _, err := f.s.Publish(ctx, publisher{srv}, opts); err == nil {
			t.Errorf("email %q accepted", email)
		}
	}
	if p, _ := f.s.Publication(); p != nil || srv.signups != 0 {
		t.Fatal("a refused publication journaled or posted")
	}
	if _, err := f.s.Publish(ctx, publisher{srv}, pubOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Publish(ctx, publisher{srv}, pubOpts); !errors.Is(err, ErrServerBacked) {
		t.Errorf("publishing twice: %v", err)
	}

	// The size and collection limits.
	g := newVault(t, testConfig(t))
	g.s.mu.Lock()
	unlock, err := g.s.lockFile()
	if err != nil {
		t.Fatal(err)
	}
	wires, err := g.s.assembleUpload(0)
	unlock()
	g.s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	j := &publicationJSON{Email: testEmail, RegistrationCode: "invite-1"}
	if err := checkUpload(j, wires); err != nil {
		t.Fatalf("a genesis-only upload: %v", err)
	}
	many := make([]*vaultlog.Wire, maxSignupWires+1)
	for i := range many {
		many[i] = wires[0]
	}
	if err := checkUpload(j, many); !errors.Is(err, ErrUploadTooLarge) || !strings.Contains(err.Error(), "entries") {
		t.Errorf("%d wires: %v", len(many), err)
	}
	big := *wires[0]
	big.Objects = append([]vaultlog.Object{{SHA256: crypto.Hash{}, Body: canonjson.Raw(`"` + strings.Repeat("a", maxObjectBody) + `"`)}}, wires[0].Objects...)
	if err := checkUpload(j, []*vaultlog.Wire{&big}); !errors.Is(err, ErrUploadTooLarge) {
		t.Errorf("a %d-byte object: %v", maxObjectBody+2, err)
	}
	if d := jsonDepth([]byte(`{"a":[{"b":"[[[{"}]}`)); d != 3 {
		t.Errorf("depth %d, want 3", d)
	}
}

func TestNormalizeEmail(t *testing.T) {
	for in, want := range map[string]string{
		" Me@Example.COM\t":                     "Me@example.com",
		"a.b+c@sub.example.org":                 "a.b+c@sub.example.org",
		"x@xn--bcher-kva.example":               "x@xn--bcher-kva.example",
		"o'brien@example.com":                   "o'brien@example.com",
		"UPPER@localhost":                       "UPPER@localhost",
		"a@b@example.com":                       "",
		"a..b@example.com":                      "",
		"a@-example.com":                        "",
		"\"quoted\"@example.com":                "",
		"a@[127.0.0.1]":                         "",
		"a@example.com\n":                       "",
		"a@exam ple.com":                        "",
		"a@" + strings.Repeat("b", 64) + ".com": "",
	} {
		got, err := normalizeEmail(in)
		if want == "" {
			if err == nil {
				t.Errorf("%q accepted as %q", in, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%q: %q %v; want %q", in, got, err, want)
		}
	}
}
