package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// fakeRemote is an in-memory server log (§5.4): it commits a wire only if
// its prev is the head, treats an identical H as idempotent, and returns a
// *HeadConflictError otherwise. Knobs simulate a lost response, a delayed
// commit and a slow response.
type fakeRemote struct {
	mu      sync.Mutex
	entries [][]byte // bare wires (no objects), index = seq
	hashes  []crypto.Hash
	objects map[crypto.Hash][]byte
	posts   []crypto.Hash // H of every wire posted, in order
	delayed []*vaultlog.Wire

	// onPost, if set, decides each post: whether to commit it and what
	// error to return. A nil error with commit false is not allowed.
	onPost func(w *vaultlog.Wire) (commit bool, err error)
	// onSince, if set, runs before Since answers. It may block.
	onSince func(ctx context.Context)
}

var _ Remote = (*fakeRemote)(nil)

var errLostResponse = errors.New("fake: the response was lost")

// newFakeRemote seeds a server with the log and objects in dataDir.
func newFakeRemote(t *testing.T, dataDir string) *fakeRemote {
	t.Helper()
	f := &fakeRemote{objects: map[crypto.Hash][]byte{}}
	l := layout{data: dataDir}
	seqs, err := l.entrySeqs()
	if err != nil {
		t.Fatal(err)
	}
	for _, seq := range seqs {
		w, err := l.readEntry(seq)
		if err != nil {
			t.Fatal(err)
		}
		f.appendLocked(t, w)
	}
	err = filepath.WalkDir(l.objects(), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".tmp") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		c, err := canonjson.Canonicalize(b)
		if err != nil {
			return err
		}
		f.objects[crypto.SHA256(c)] = c
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fakeRemote) appendLocked(t *testing.T, w *vaultlog.Wire) {
	t.Helper()
	bare := *w
	bare.Objects = []vaultlog.Object{}
	b, err := bare.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	h, err := w.Entry.Hash()
	if err != nil {
		t.Fatal(err)
	}
	f.entries = append(f.entries, b)
	f.hashes = append(f.hashes, h)
}

func (f *fakeRemote) headLocked() vaultlog.Head {
	n := len(f.hashes)
	return vaultlog.Head{Seq: uint64(n - 1), H: f.hashes[n-1]}
}

func (f *fakeRemote) head() vaultlog.Head {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.headLocked()
}

// committed reports whether an entry with H h is in the log.
func (f *fakeRemote) committed(h crypto.Hash) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.ContainsFunc(f.hashes, h.Equal)
}

func (f *fakeRemote) postCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.posts)
}

func (f *fakeRemote) Since(ctx context.Context, after uint64) ([]Committed, vaultlog.Head, error) {
	if f.onSince != nil {
		f.onSince(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Committed
	for seq := after + 1; seq < uint64(len(f.entries)); seq++ {
		w, err := vaultlog.ParseWire(f.entries[seq])
		if err != nil {
			return nil, vaultlog.Head{}, err
		}
		e, err := w.Entry.Marshal()
		if err != nil {
			return nil, vaultlog.Head{}, err
		}
		for h, body := range f.objects {
			if bytes.Contains(e, []byte(h.String())) {
				w.Objects = append(w.Objects, vaultlog.Object{SHA256: h, Body: body})
			}
		}
		slices.SortFunc(w.Objects, func(a, b vaultlog.Object) int { return bytes.Compare(a.SHA256[:], b.SHA256[:]) })
		out = append(out, Committed{Seq: seq, H: f.hashes[seq], Wire: w})
	}
	return out, f.headLocked(), nil
}

func (f *fakeRemote) Post(ctx context.Context, w *vaultlog.Wire) (vaultlog.Head, error) {
	h, err := w.Entry.Hash()
	if err != nil {
		return vaultlog.Head{}, err
	}
	f.mu.Lock()
	f.posts = append(f.posts, h)
	f.mu.Unlock()
	commit, perr := true, error(nil)
	if f.onPost != nil {
		commit, perr = f.onPost(w)
	}
	var head vaultlog.Head
	if commit {
		head, err = f.commit(w)
		if err != nil {
			return vaultlog.Head{}, err
		}
	}
	if perr != nil {
		return vaultlog.Head{}, perr
	}
	return head, nil
}

// commit applies the server's rule: prev must be the head; an identical H
// already committed returns that commit.
func (f *fakeRemote) commit(w *vaultlog.Wire) (vaultlog.Head, error) {
	h, err := w.Entry.Hash()
	if err != nil {
		return vaultlog.Head{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if seq := w.Entry.Seq; seq < uint64(len(f.hashes)) && f.hashes[seq].Equal(h) {
		return vaultlog.Head{Seq: seq, H: h}, nil
	}
	head := f.headLocked()
	if w.Entry.Seq != head.Seq+1 || !w.Entry.Prev.Equal(head.H) {
		return vaultlog.Head{}, &HeadConflictError{Head: head}
	}
	for _, o := range w.Objects {
		c, err := canonjson.Canonicalize(o.Body)
		if err != nil {
			return vaultlog.Head{}, err
		}
		f.objects[o.SHA256] = c
	}
	bare := *w
	bare.Objects = []vaultlog.Object{}
	b, err := bare.Marshal()
	if err != nil {
		return vaultlog.Head{}, err
	}
	f.entries = append(f.entries, b)
	f.hashes = append(f.hashes, h)
	return vaultlog.Head{Seq: w.Entry.Seq, H: h}, nil
}

// deliverDelayed tries to commit every post that was held back, as a
// server that finally processes a delayed request would. It returns the
// errors.
func (f *fakeRemote) deliverDelayed() []error {
	f.mu.Lock()
	ws := f.delayed
	f.delayed = nil
	f.mu.Unlock()
	var errs []error
	for _, w := range ws {
		_, err := f.commit(w)
		errs = append(errs, err)
	}
	return errs
}

// serverVault is a new server-backed vault whose log is on a fake server.
func serverVault(t *testing.T) (*fixture, *fakeRemote) {
	t.Helper()
	f := newVault(t, testConfig(t))
	r := newFakeRemote(t, f.cfg.DataDir)
	if err := f.s.EnableServerMode(); err != nil {
		t.Fatal(err)
	}
	return f, r
}

// copyDir copies a data directory (the vault and device.json).
func copyDir(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// secondDevice enrolls a second device on f's account, in its own data
// directory, by a password unlock whose bootstrap goes through r. f's
// outbox must be empty. f pulls the bootstrap.
func secondDevice(t *testing.T, f *fixture, r *fakeRemote) *fixture {
	t.Helper()
	ctx := context.Background()
	if err := f.s.Pull(ctx, r); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t)
	copyDir(t, f.cfg.DataDir, cfg.DataDir)
	b, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, b)
	if err := b.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Pull(ctx, r); err != nil {
		t.Fatal(err)
	}
	return &fixture{cfg: cfg, kit: f.kit, s: b}
}

// pushAll pushes until the outbox is empty or its head is held, and
// returns the last result.
func pushAll(t *testing.T, s *Store, r Remote) PushResult {
	t.Helper()
	for range 50 {
		res, err := s.PushHead(context.Background(), r)
		if err != nil {
			t.Fatalf("push: %v", err)
		}
		if res.Outcome == PushEmpty || res.Outcome == PushHeld {
			return res
		}
	}
	t.Fatal("the outbox never drained")
	return PushResult{}
}

func pull(t *testing.T, s *Store, r Remote) {
	t.Helper()
	if err := s.Pull(context.Background(), r); err != nil {
		t.Fatalf("pull: %v", err)
	}
}

// direct builds a normal entry from s's verified state, posts it to r as a
// non-outbox write (a grant or deploy command would), and pulls it.
func direct(t *testing.T, s *Store, r *fakeRemote, ch vaultlog.Changes) {
	t.Helper()
	pull(t, s, r)
	s.mu.Lock()
	w, _, _, err := vaultlog.BuildNormal(s.state, s.sec, s.dev, ch, s.now(), objectDir(s.l.objects()))
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Post(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	pull(t, s, r)
}

// records returns the outbox records of s.
func records(t *testing.T, s *Store) []*record {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.readOutbox()
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func hostNamed(t *testing.T, snap model.Snapshot, name string) model.Host {
	t.Helper()
	for _, h := range snap.Hosts {
		if h.Name == name {
			return h
		}
	}
	t.Fatalf("no host %q in %v", name, names(snap))
	return model.Host{}
}

func hostByID(t *testing.T, s *Store, id model.ID) (model.Host, bool) {
	t.Helper()
	for _, h := range snapshot(t, s).Hosts {
		if h.ItemID == id {
			return h, true
		}
	}
	return model.Host{}, false
}

// verifiedHost returns the host in s's verified state.
func verifiedHost(t *testing.T, s *Store, id model.ID) (model.Host, bool) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.sec.Items[id]
	if !ok {
		return model.Host{}, false
	}
	return cloneHost(*p.Item.(*model.Host)), true
}

func headOf(t *testing.T, s *Store) Head {
	t.Helper()
	h, err := s.Head()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// newCredential puts a credential and returns it.
func newCredential(t *testing.T, s *Store, name string) model.Credential {
	t.Helper()
	c, err := s.PutCredential(context.Background(), model.Credential{Name: name, Username: "u-" + name, Password: "p-" + name})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// grantChanges is a grant whose record lists items, with host_key_map.
func grantChanges(t *testing.T, s *Store, items []model.ID, hostKeys map[model.ID]model.ID) vaultlog.Changes {
	t.Helper()
	grantID, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	recID, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	sigPK := ed25519.PublicKey(s.state.Account.SigPK)
	s.mu.Unlock()
	tok, err := crypto.NewToken(grantID, sigPK)
	if err != nil {
		t.Fatal(err)
	}
	kem, err := tok.KEMKey()
	if err != nil {
		t.Fatal(err)
	}
	tauth, err := tok.Auth()
	if err != nil {
		t.Fatal(err)
	}
	ids := slices.Clone(items)
	slices.SortFunc(ids, func(a, b model.ID) int { return bytes.Compare(a[:], b[:]) })
	rec := &model.Grant{
		Header:  model.Header{ItemID: recID, Type: model.TypeGrant},
		GrantID: grantID, Name: "ci", ExpiresAt: model.TimestampOf(time.Now().Add(24 * time.Hour)),
		TokenKEMPK: kem.PublicKey().Bytes(), Items: ids, HostKeyMap: hostKeys, KeyPolicy: "shared",
	}
	return vaultlog.Changes{Grants: []vaultlog.NewGrant{{Record: rec, TAuthSHA256: crypto.SHA256(tauth)}}}
}

// mergeItem encodes a model item for comparisons.
func mergeItem(t *testing.T, v any) *merge.Item {
	t.Helper()
	it, err := merge.ItemOf(v)
	if err != nil {
		t.Fatal(err)
	}
	return it
}
