package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// fakeServer is a fakeRemote with the parts of the phase 2 server that
// slice D2's transactions use: signup with a registration capability and
// proof of possession (plan R3), device sessions that a retirement or a
// checkpoint ends (R2), and retire-status with permanent receipts (§9).
// Every device-auth and signup proof it receives is verified for real.
type fakeServer struct {
	*fakeRemote
	origin string

	smu       sync.Mutex
	published bool
	email     string
	code      string
	upload    []crypto.Hash // the committed upload's hashes
	signups   int
	sessions  map[model.ID]bool

	// onSignup, if set, decides each signup after validation: whether to
	// commit it and the error to return.
	onSignup func() (commit bool, err error)
	// down, if set, makes every call fail as an unreachable server would.
	down error
	// statusCalls counts retire-status calls.
	statusCalls int
}

var errDown = errors.New("fake: the server is unreachable")

// newFakeServer wraps r, whose log is already published, with every
// active device holding a session.
func newFakeServer(t *testing.T, r *fakeRemote) *fakeServer {
	t.Helper()
	f := &fakeServer{fakeRemote: r, origin: "https://hop.test", published: true, sessions: map[model.ID]bool{}}
	pub, _, _ := f.public(t)
	for _, id := range f.activeDevices(t, pub) {
		f.sessions[id] = true
	}
	return f
}

// newEmptyServer is a server with no vault, with a registration code for
// email.
func newEmptyServer(email, code string) *fakeServer {
	return &fakeServer{
		fakeRemote: &fakeRemote{objects: map[crypto.Hash][]byte{}},
		origin:     "https://hop.test", email: email, code: code, sessions: map[model.ID]bool{},
	}
}

// public replays the server's log with ApplyPublic, the server's check,
// and returns the public state, every device the account ever had, and
// the permanent receipts.
func (f *fakeServer) public(t testing.TB) (*vaultlog.PublicState, map[model.ID]ed25519.PublicKey, map[model.ID]DeviceReceipt) {
	t.Helper()
	pub, ever, receipts, err := f.replay()
	if err != nil {
		t.Fatal(err)
	}
	return pub, ever, receipts
}

func (f *fakeServer) replay() (*vaultlog.PublicState, map[model.ID]ed25519.PublicKey, map[model.ID]DeviceReceipt, error) {
	f.mu.Lock()
	entries := slices.Clone(f.entries)
	objs := vaultlog.ObjectMap{}
	for h, b := range f.objects {
		objs[h] = b
	}
	f.mu.Unlock()
	var pub *vaultlog.PublicState
	ever := map[model.ID]ed25519.PublicKey{}
	receipts := map[model.ID]DeviceReceipt{}
	for _, b := range entries {
		w, err := vaultlog.ParseWire(b)
		if err != nil {
			return nil, nil, nil, err
		}
		if pub, err = vaultlog.ApplyPublic(pub, w, objs); err != nil {
			return nil, nil, nil, err
		}
		for _, o := range w.Entry.Ops {
			if d, ok := o.(*vaultlog.DeviceAddOp); ok {
				ever[d.Cert.DeviceID] = ed25519.PublicKey(slices.Clone(d.SigPK))
			}
		}
		for _, d := range pub.Departures() {
			receipts[d.DeviceID] = DeviceReceipt{DeviceID: d.DeviceID, How: string(d.How), Seq: d.Head.Seq, H: d.Head.H}
		}
	}
	return pub, ever, receipts, nil
}

func (f *fakeServer) activeDevices(t testing.TB, pub *vaultlog.PublicState) []model.ID {
	t.Helper()
	_, ever, _ := f.public(t)
	var out []model.ID
	for id := range ever {
		if pub.DeviceActive(id) {
			out = append(out, id)
		}
	}
	return out
}

// verifyAuth checks a device-auth signature for operation over a fresh
// challenge, against every key the device ever had.
func (f *fakeServer) verifyAuth(auth DeviceAuth, operation string, activeOnly bool) error {
	pub, ever, _, err := f.replay()
	if err != nil {
		return err
	}
	pk, ok := ever[auth.DeviceID]
	if !ok {
		return ErrPublicationAbsent
	}
	if activeOnly && !pub.DeviceActive(auth.DeviceID) {
		return ErrSessionEnded
	}
	ch := make([]byte, challengeSize)
	rand.Read(ch)
	sig, err := auth.Sign(f.origin, operation, ch)
	if err != nil {
		return err
	}
	obj := &deviceAuthObject{V: 1, Origin: f.origin, AccountID: auth.AccountID, DeviceID: auth.DeviceID, Operation: operation, Challenge: ch}
	if err := crypto.Verify(pk, labelDeviceAuth, obj, sig); err != nil {
		return fmt.Errorf("fake: device auth: %w", err)
	}
	if pub.AccountID() != auth.AccountID {
		return errors.New("fake: device auth for another account")
	}
	return nil
}

// commitEnding commits w and ends the sessions it ends (R2): every session
// for a checkpoint, the device's own for a retirement or a revocation.
func (f *fakeServer) commitEnding(w *vaultlog.Wire) (vaultlog.Head, error) {
	head, err := f.commit(w)
	if err != nil {
		return head, err
	}
	f.endSessions(w)
	return head, nil
}

func (f *fakeServer) endSessions(w *vaultlog.Wire) {
	f.smu.Lock()
	defer f.smu.Unlock()
	if w.Entry.Kind == vaultlog.KindCheckpoint {
		clear(f.sessions)
	}
	for _, o := range w.Entry.Ops {
		switch o := o.(type) {
		case *vaultlog.DeviceRetireOp:
			delete(f.sessions, o.DeviceID)
		case *vaultlog.DeviceRevokeOp:
			delete(f.sessions, o.DeviceID)
		}
	}
}

func (f *fakeServer) hasSession(id model.ID) bool {
	f.smu.Lock()
	defer f.smu.Unlock()
	return f.sessions[id]
}

// entryAt returns the committed entry at seq with its objects.
func (f *fakeServer) entryAt(seq uint64) (Committed, error) {
	f.mu.Lock()
	n := uint64(len(f.entries))
	f.mu.Unlock()
	if seq >= n {
		return Committed{}, ErrPublicationAbsent
	}
	if seq == 0 {
		cs, _, err := f.sinceFrom(0)
		if err != nil || len(cs) == 0 {
			return Committed{}, errors.Join(err, ErrPublicationAbsent)
		}
		return cs[0], nil
	}
	cs, _, err := f.fakeRemote.Since(context.Background(), seq-1)
	if err != nil || len(cs) == 0 {
		return Committed{}, errors.Join(err, ErrPublicationAbsent)
	}
	return cs[0], nil
}

// sinceFrom is Since from seq first, genesis included.
func (f *fakeServer) sinceFrom(first uint64) ([]Committed, vaultlog.Head, error) {
	if first > 0 {
		return f.fakeRemote.Since(context.Background(), first-1)
	}
	rest, head, err := f.fakeRemote.Since(context.Background(), 0)
	if err != nil {
		return nil, head, err
	}
	f.mu.Lock()
	b := f.entries[0]
	h := f.hashes[0]
	f.mu.Unlock()
	w, err := vaultlog.ParseWire(b)
	if err != nil {
		return nil, head, err
	}
	for _, d := range namedObjects(&w.Entry) {
		f.mu.Lock()
		body := f.objects[d]
		f.mu.Unlock()
		w.Objects = append(w.Objects, vaultlog.Object{SHA256: d, Body: body})
	}
	return append([]Committed{{Seq: 0, H: h, Wire: w}}, rest...), head, nil
}

// appendValidated appends a wire the caller has validated, with its
// objects.
func (f *fakeServer) appendValidated(w *vaultlog.Wire) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, o := range w.Objects {
		c, err := canonjson.Canonicalize(o.Body)
		if err != nil {
			return err
		}
		f.objects[o.SHA256] = c
	}
	bare := *w
	bare.Objects = []vaultlog.Object{}
	b, err := bare.Marshal()
	if err != nil {
		return err
	}
	h, err := w.Entry.Hash()
	if err != nil {
		return err
	}
	f.entries = append(f.entries, b)
	f.hashes = append(f.hashes, h)
	return nil
}

// publisher is the fake server as a Publisher.
type publisher struct{ f *fakeServer }

func (p publisher) Signup(ctx context.Context, req *SignupRequest) (vaultlog.Head, error) {
	f := p.f
	if f.down != nil {
		return vaultlog.Head{}, f.down
	}
	f.smu.Lock()
	f.signups++
	f.smu.Unlock()
	if req.Email != f.email || req.RegistrationCode != f.code {
		return vaultlog.Head{}, errors.New("fake: registration_conflict")
	}
	var hs []crypto.Hash
	for _, w := range req.Wires {
		h, err := w.Entry.Hash()
		if err != nil {
			return vaultlog.Head{}, err
		}
		hs = append(hs, h)
	}
	f.smu.Lock()
	published, upload := f.published, f.upload
	f.smu.Unlock()
	if published {
		if slices.EqualFunc(hs, upload, crypto.Hash.Equal) {
			return vaultlog.Head{Seq: uint64(len(hs) - 1), H: hs[len(hs)-1]}, nil
		}
		return vaultlog.Head{}, errors.New("fake: registration_conflict")
	}
	// Validate every entry's public stage from empty state, with only the
	// objects the upload carries (plan R3).
	var pub *vaultlog.PublicState
	for i, w := range req.Wires {
		objs, err := vaultlog.WireObjects(w)
		if err != nil {
			return vaultlog.Head{}, err
		}
		if pub, err = vaultlog.ApplyPublic(pub, w, objs); err != nil {
			return vaultlog.Head{}, fmt.Errorf("fake: upload entry %d: %w", i, err)
		}
	}
	if pub.Head().Seq != req.UploadSeq || !pub.Head().H.Equal(req.UploadH) || pub.VaultID() != req.VaultID || pub.AccountID() != req.AccountID {
		return vaultlog.Head{}, errors.New("fake: the upload head does not match the request")
	}
	acct, ok := pub.Account()
	if !ok {
		return vaultlog.Head{}, errors.New("fake: no account")
	}
	ch := make([]byte, challengeSize)
	rand.Read(ch)
	sig, err := req.Prove(f.origin, ch)
	if err != nil {
		return vaultlog.Head{}, err
	}
	pop := &signupPoPObject{V: 1, Origin: f.origin, Email: f.email, AccountID: req.AccountID, VaultID: req.VaultID,
		UploadSeq: req.UploadSeq, UploadH: req.UploadH, Challenge: ch}
	if err := crypto.Verify(acct.SigPK, labelSignupPoP, pop, sig); err != nil {
		return vaultlog.Head{}, fmt.Errorf("fake: pop_sig: %w", err)
	}
	commit, perr := true, error(nil)
	if f.onSignup != nil {
		commit, perr = f.onSignup()
	}
	if commit {
		for _, w := range req.Wires {
			if err := f.appendValidated(w); err != nil {
				return vaultlog.Head{}, err
			}
		}
		f.smu.Lock()
		f.published, f.upload = true, hs
		f.smu.Unlock()
	}
	if perr != nil {
		return vaultlog.Head{}, perr
	}
	return vaultlog.Head{Seq: req.UploadSeq, H: req.UploadH}, nil
}

func (p publisher) EntryAt(ctx context.Context, auth DeviceAuth, seq uint64) (Committed, error) {
	f := p.f
	if f.down != nil {
		return Committed{}, f.down
	}
	f.smu.Lock()
	published := f.published
	f.smu.Unlock()
	if !published {
		return Committed{}, ErrPublicationAbsent
	}
	if err := f.verifyAuth(auth, OperationSession, true); err != nil {
		return Committed{}, err
	}
	return f.entryAt(seq)
}

func (p publisher) Since(ctx context.Context, auth DeviceAuth, after uint64) ([]Committed, vaultlog.Head, error) {
	f := p.f
	if f.down != nil {
		return nil, vaultlog.Head{}, f.down
	}
	if err := f.verifyAuth(auth, OperationSession, true); err != nil {
		return nil, vaultlog.Head{}, err
	}
	return f.fakeRemote.Since(ctx, after)
}

// retirer is the fake server as a Retirer.
type retirer struct{ f *fakeServer }

func (r retirer) Since(ctx context.Context, auth DeviceAuth, after uint64) ([]Committed, vaultlog.Head, error) {
	f := r.f
	if f.down != nil {
		return nil, vaultlog.Head{}, f.down
	}
	if !f.hasSession(auth.DeviceID) {
		return nil, vaultlog.Head{}, ErrSessionEnded
	}
	return f.fakeRemote.Since(ctx, after)
}

func (r retirer) Post(ctx context.Context, auth DeviceAuth, w *vaultlog.Wire) (vaultlog.Head, error) {
	f := r.f
	if f.down != nil {
		return vaultlog.Head{}, f.down
	}
	if !f.hasSession(auth.DeviceID) {
		return vaultlog.Head{}, ErrSessionEnded
	}
	if w.Entry.Author != auth.DeviceID {
		return vaultlog.Head{}, errors.New("fake: the session's device is not the author")
	}
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
		if head, err = f.commitEnding(w); err != nil {
			return vaultlog.Head{}, err
		}
	}
	return head, perr
}

func (r retirer) RetireStatus(ctx context.Context, auth DeviceAuth, h crypto.Hash) (RetireStatus, error) {
	f := r.f
	if f.down != nil {
		return RetireStatus{}, f.down
	}
	if err := f.verifyAuth(auth, OperationRetireStatus, false); err != nil {
		return RetireStatus{}, err
	}
	f.smu.Lock()
	f.statusCalls++
	f.smu.Unlock()
	_, _, receipts := f.public(nopTB{})
	st := RetireStatus{Head: f.head()}
	if rc, ok := receipts[auth.DeviceID]; ok {
		st.Receipt = &rc
	}
	f.mu.Lock()
	for seq, x := range f.hashes {
		if x.Equal(h) {
			st.Committed, st.Seq = true, uint64(seq)
		}
	}
	f.mu.Unlock()
	return st, nil
}

func (r retirer) RetirePost(ctx context.Context, auth DeviceAuth, w *vaultlog.Wire) (vaultlog.Head, error) {
	f := r.f
	if f.down != nil {
		return vaultlog.Head{}, f.down
	}
	if err := f.verifyAuth(auth, OperationRetireStatus, true); err != nil {
		return vaultlog.Head{}, err
	}
	if len(w.Entry.Ops) != 1 || w.Entry.Author != auth.DeviceID {
		return vaultlog.Head{}, errors.New("fake: not this device's retirement")
	}
	if o, ok := w.Entry.Ops[0].(*vaultlog.DeviceRetireOp); !ok || o.DeviceID != auth.DeviceID {
		return vaultlog.Head{}, errors.New("fake: not this device's retirement")
	}
	return f.commitEnding(w)
}

func (r retirer) Reauthenticate(ctx context.Context, auth DeviceAuth) error {
	f := r.f
	if f.down != nil {
		return f.down
	}
	if err := f.verifyAuth(auth, OperationSession, true); err != nil {
		return err
	}
	f.smu.Lock()
	f.sessions[auth.DeviceID] = true
	f.smu.Unlock()
	return nil
}

// signInRemote is the fake server as a login or recovery sees it: one
// token (plan R6), bound to the account's credential generation when it
// was issued (R2), which a checkpoint ends. It reads the log and commits
// one bootstrap: the commit consumes it, atomically, and records the entry
// hash; a validation failure or a head conflict does not. An identical
// retry returns the recorded commit, and any other bootstrap is refused.
type signInRemote struct {
	f   *fakeServer
	gen uint32
	lax bool // the token survives a credential change (lenient)

	mu       sync.Mutex
	consumed *vaultlog.Head // the bootstrap commit, once there is one
}

// errTokenInvalid is the fake server's 401 for a login or recovery token.
var errTokenInvalid = errors.New("fake: the login token is not valid")

// login issues a login token for the account on f, at its current
// credential generation.
func (f *fakeServer) login(t testing.TB) *signInRemote {
	t.Helper()
	gen, err := f.credsGen()
	if err != nil {
		t.Fatal(err)
	}
	return &signInRemote{f: f, gen: gen}
}

// valid checks the token against the credential generation now.
func (s *signInRemote) valid() error {
	if s.f.down != nil {
		return s.f.down
	}
	gen, err := s.f.credsGen()
	if err != nil {
		return err
	}
	if gen != s.gen && !s.lax {
		return fmt.Errorf("%w: the credentials changed (gen %d, issued at %d)", errTokenInvalid, gen, s.gen)
	}
	return nil
}

func (s *signInRemote) EntryAt(ctx context.Context, seq uint64) (Committed, error) {
	if err := s.valid(); err != nil {
		return Committed{}, err
	}
	return s.f.entryAt(seq)
}

func (s *signInRemote) Since(ctx context.Context, after uint64) ([]Committed, vaultlog.Head, error) {
	if err := s.valid(); err != nil {
		return nil, vaultlog.Head{}, err
	}
	cs, head, err := s.f.fakeRemote.Since(ctx, after)
	if err != nil {
		return nil, head, err
	}
	// Authorization is checked again before the response goes out (R2).
	if err := s.valid(); err != nil {
		return nil, vaultlog.Head{}, err
	}
	return cs, head, nil
}

func (s *signInRemote) Post(ctx context.Context, w *vaultlog.Wire) (vaultlog.Head, error) {
	if err := s.valid(); err != nil {
		return vaultlog.Head{}, err
	}
	if w.Entry.Kind != vaultlog.KindBootstrap {
		return vaultlog.Head{}, errors.New("fake: a login token posts only a bootstrap")
	}
	h, err := w.Entry.Hash()
	if err != nil {
		return vaultlog.Head{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed != nil {
		if s.consumed.H.Equal(h) {
			return *s.consumed, nil
		}
		return vaultlog.Head{}, fmt.Errorf("%w: its bootstrap is used", errTokenInvalid)
	}
	s.f.mu.Lock()
	s.f.posts = append(s.f.posts, h)
	s.f.mu.Unlock()
	commit, perr := true, error(nil)
	if s.f.onPost != nil {
		commit, perr = s.f.onPost(w)
	}
	var head vaultlog.Head
	if commit {
		if head, err = s.f.commit(w); err != nil {
			return vaultlog.Head{}, err
		}
		s.consumed = &head
	}
	return head, perr
}

// nopTB is a testing.TB stand-in for helpers called off the test
// goroutine; it panics on failure.
type nopTB struct{ testing.TB }

func (nopTB) Helper()               {}
func (nopTB) Fatal(args ...any)     { panic(fmt.Sprint(args...)) }
func (nopTB) Errorf(string, ...any) {}

// rawEqual compares canonical JSON.
func rawEqual(a, b []byte) bool {
	ca, err1 := canonjson.Canonicalize(a)
	cb, err2 := canonjson.Canonicalize(b)
	return err1 == nil && err2 == nil && string(ca) == string(cb)
}
