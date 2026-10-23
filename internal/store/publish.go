package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Publishing an existing local vault (§4.3, rev 16; plan R3, R9, R14). The
// whole verified log, from genesis to the head, is uploaded as one
// publication transaction:
//
//  1. Preflight: no checkpoint journal and no unacknowledged Emergency Kit
//     (§10.1), no login merge, and an upload the server can admit (R9's
//     64 MiB request and 4 MiB singleton-response limits, R8's 1 MiB per
//     object, R14's collection limits).
//  2. Journal: vault/publish.json is written, durably, with the
//     registration capability sealed next to the publication record:
//
//     publication = JCS({"v":1, "server":str, "email":str, "account_id":id, "vault_id":id,
//     "upload_seq":u64s, "upload_h":h, "registration_code":str})
//     file = JCS({"v":1, "vault_id":id, "sealed":AEAD(local_key, publication,
//     aad = lp("hopkey/v1/publication") || lp(vault_id_bytes))})
//
//     From then on the vault is publication-pending: every local append is
//     refused (refuseLocalAppend), so the uploaded head stays fixed.
//  3. Upload: every entry from seq 0 to upload_seq, each with the objects
//     it names, in one Publisher.Signup.
//  4. Resolve: the server's entry at upload_seq, read with device
//     authentication. H = upload_h: the publication committed; any later
//     entries are verified by the transition algorithm, and then the switch
//     to server-backed mode and the deletion of the journal are one durable
//     commit. No vault: the identical upload is posted again. Another H:
//     the equivocation alarm (§5.6), and the vault stays pending.
//
// A crash resumes at step 4 (ResumePublish).

var (
	// ErrPublicationPending means a publication is journaled and not yet
	// resolved: local appends are refused until ResumePublish finishes it.
	ErrPublicationPending = errors.New("store: this vault is being published to a server; run hop auth signup again to finish")
	// ErrNoPublication means there is no publication to resume.
	ErrNoPublication = errors.New("store: no publication is pending")
	// ErrPublicationAbsent is what a Publisher returns when the server has
	// no vault for the publication: the signup never committed.
	ErrPublicationAbsent = errors.New("store: the server has no vault for this publication")
	// ErrCheckpointPending means a checkpoint journal or an unacknowledged
	// Emergency Kit exists (§10.1): confirm the kit with hop passwd first.
	ErrCheckpointPending = errors.New("store: a password change is not finished (its Emergency Kit is not confirmed); run hop passwd first")
	// ErrUploadTooLarge means the publication would exceed a server
	// admission limit (plan R8, R9, R14).
	ErrUploadTooLarge = errors.New("store: the vault is too large to publish")
)

// Admission limits a client can check locally (plan R8, R9, R14).
const (
	maxSignupBody      = 64 << 20
	maxSingletonWire   = 4 << 20
	maxObjectBody      = 1 << 20
	maxSignupWires     = 16384
	maxOpsPerWire      = 8192
	maxObjectsPerWire  = 16384
	maxJSONDepth       = 32
	labelPublication   = "hopkey/v1/publication"
	publishRel         = "publish.json"
	publicationVersion = 1
)

func (l layout) publishFile() string { return filepath.Join(l.vault(), publishRel) }

// Publisher is the server a publication goes to (§4.3, plan R3). Slice E
// implements it over HTTP. Nothing it returns is trusted: the entry at
// upload_seq is compared with the journal, and every later entry is
// verified by the transition algorithm.
type Publisher interface {
	// Signup fetches a signup challenge for req.Email and
	// req.RegistrationCode, has req.Prove sign it, and posts the upload
	// (POST /v1/signup/challenge, POST /v1/signup). It returns the server's
	// acknowledgment, which is not trusted.
	Signup(ctx context.Context, req *SignupRequest) (vaultlog.Head, error)
	// EntryAt returns the committed entry at seq of the published vault,
	// read with device authentication (GET /v1/vaults/{id}/entries/{seq}).
	// It returns an error matching ErrPublicationAbsent when the server has
	// no such vault (the device can't authenticate), or no entry at seq.
	EntryAt(ctx context.Context, auth DeviceAuth, seq uint64) (Committed, error)
	// Since is Remote.Since with device authentication.
	Since(ctx context.Context, auth DeviceAuth, after uint64) ([]Committed, vaultlog.Head, error)
}

// SignupRequest is one publication upload (POST /v1/signup).
type SignupRequest struct {
	Server           string // the origin the publication is journaled for
	Email            string // normalized (plan R4)
	RegistrationCode string
	AccountID        model.ID
	VaultID          model.ID
	UploadSeq        uint64
	UploadH          crypto.Hash
	// Wires are the entries 0..UploadSeq, each with the objects it names,
	// sorted by digest.
	Wires []*vaultlog.Wire
	prove func(origin string, challenge []byte) ([]byte, error)
}

// Prove returns pop_sig = Sig(acct_sig, "hopkey/v1/signup-pop", {"v":1,
// origin, email, account_id, vault_id, upload_seq, upload_h, challenge})
// for the server's challenge, with the account key in effect at the upload
// head (§4.3 addendum, plan R3).
func (r *SignupRequest) Prove(origin string, challenge []byte) ([]byte, error) {
	if r.prove == nil {
		return nil, ErrAuthClosed
	}
	if err := checkChallenge(origin, challenge); err != nil {
		return nil, err
	}
	return r.prove(origin, challenge)
}

// PublishOptions are the choices of hop auth signup for an existing vault.
type PublishOptions struct {
	Server           string // the server's origin, e.g. https://hop.example.com
	Email            string // normalized here (plan R4)
	RegistrationCode string // the registration capability (hop-server invite)
}

// Publication describes a publication, pending or just finished.
type Publication struct {
	Server    string   `json:"server"`
	Email     string   `json:"email"`
	AccountID model.ID `json:"account_id"`
	VaultID   model.ID `json:"vault_id"`
	Upload    Head     `json:"upload"`
	// Alarm is the equivocation the last resolution found, if any.
	Alarm string `json:"alarm,omitempty"`
}

// publicationJSON is the sealed publication record.
type publicationJSON struct {
	V                int         `json:"v"`
	Server           string      `json:"server"`
	Email            string      `json:"email"`
	AccountID        model.ID    `json:"account_id"`
	VaultID          model.ID    `json:"vault_id"`
	UploadSeq        uint64      `json:"upload_seq,string"`
	UploadH          crypto.Hash `json:"upload_h"`
	RegistrationCode string      `json:"registration_code"`
}

type publicationFile struct {
	V       int                 `json:"v"`
	VaultID model.ID            `json:"vault_id"`
	Sealed  crypto.AEADEnvelope `json:"sealed"`
}

func publicationAAD(vaultID model.ID) []byte {
	return append(crypto.LP([]byte(labelPublication)), crypto.LP(vaultID[:])...)
}

func (j *publicationJSON) info() Publication {
	return Publication{Server: j.Server, Email: j.Email, AccountID: j.AccountID, VaultID: j.VaultID,
		Upload: Head{Seq: j.UploadSeq, H: j.UploadH.String()}}
}

func sealPublication(rec *deviceRecord, j *publicationJSON) ([]byte, error) {
	key, err := rec.localKey()
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	pt, err := canonjson.Marshal(j)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	env, err := crypto.SealAEAD(key, pt, publicationAAD(j.VaultID))
	if err != nil {
		return nil, err
	}
	return canonjson.Marshal(publicationFile{V: publicationVersion, VaultID: j.VaultID, Sealed: env})
}

// readPublication opens vault/publish.json, or returns nil if there is
// none. Anything that does not open is ErrCorrupt.
func (s *Store) readPublication(rec *deviceRecord, vaultID model.ID) (*publicationJSON, error) {
	b, err := os.ReadFile(s.l.publishFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	bad := fmt.Errorf("%w: %s does not open", ErrCorrupt, s.l.publishFile())
	var f publicationFile
	if canonjson.Unmarshal(b, &f) != nil || f.V != publicationVersion || f.VaultID != vaultID {
		return nil, bad
	}
	key, err := rec.localKey()
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	pt, err := crypto.OpenAEAD(key, f.Sealed, publicationAAD(vaultID))
	if err != nil {
		return nil, bad
	}
	defer clear(pt)
	var j publicationJSON
	if canonjson.Unmarshal(pt, &j) != nil || j.V != publicationVersion || j.VaultID != vaultID {
		return nil, bad
	}
	return &j, nil
}

// publicationPending reports whether vault/publish.json exists. It reads
// only the name, so it works while the vault is locked.
func (l layout) publicationPending() (bool, error) {
	_, err := os.Lstat(l.publishFile())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// refuseLocalAppend refuses a local append (a direct write, a local
// checkpoint or bootstrap) while a publication is pending (§4.3) or a login
// merge has frozen this vault (§4.4). The caller holds the file lock.
func (s *Store) refuseLocalAppend() error {
	if pending, err := s.l.publicationPending(); err != nil {
		return err
	} else if pending {
		return ErrPublicationPending
	}
	if frozen, err := s.l.mergeExists(); err != nil {
		return err
	} else if frozen {
		return ErrMergeFrozen
	}
	return nil
}

// Publication returns the pending publication, or nil.
func (s *Store) Publication() (*Publication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		if pending, err := s.l.publicationPending(); err != nil || !pending {
			return nil, err
		}
		return nil, s.lockedErr()
	}
	unlock, err := s.lockFile()
	if err != nil {
		return nil, err
	}
	defer unlock()
	j, err := s.readPublication(s.rec, s.state.VaultID)
	if err != nil || j == nil {
		return nil, err
	}
	p := j.info()
	if s.pubAlarm != nil {
		p.Alarm = s.pubAlarm.Error()
	}
	return &p, nil
}

// Publish publishes this local-only vault to a server (§4.3): preflight,
// journal, upload, resolve. On success the vault is server-backed and the
// result names the server and the sign-in email, for the user to add to
// the Emergency Kit. Any error after the journal leaves the publication
// pending: ResumePublish finishes it. An equivocation at upload_seq
// returns a *vaultlog.EquivocationError and leaves it pending.
func (s *Store) Publish(ctx context.Context, p Publisher, opts PublishOptions) (Publication, error) {
	if err := s.lockSync(); err != nil {
		return Publication{}, err
	}
	defer s.syncMu.Unlock()
	j, wires, err := s.beginPublication(opts)
	if err != nil {
		return Publication{}, err
	}
	if err := s.hook("publish:journaled"); err != nil {
		return Publication{}, err
	}
	if err := s.hook("publish:post"); err != nil {
		return Publication{}, err
	}
	postErr := s.postUpload(ctx, p, j, wires)
	return s.resolvePublication(ctx, p, j, wires, postErr)
}

// ResumePublish resolves a pending publication (§4.3 step 4), after a
// crash, a lost response or an unreachable server.
func (s *Store) ResumePublish(ctx context.Context, p Publisher) (Publication, error) {
	if err := s.lockSync(); err != nil {
		return Publication{}, err
	}
	defer s.syncMu.Unlock()
	j, wires, err := s.pendingPublication()
	if err != nil {
		return Publication{}, err
	}
	return s.resolvePublication(ctx, p, j, wires, nil)
}

// beginPublication runs the preflight and journals the publication.
func (s *Store) beginPublication(opts PublishOptions) (*publicationJSON, []*vaultlog.Wire, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, nil, s.lockedErr()
	}
	if s.server {
		return nil, nil, fmt.Errorf("%w: it is already published", ErrServerBacked)
	}
	email, err := NormalizeEmail(opts.Email)
	if err != nil {
		return nil, nil, err
	}
	if opts.Server == "" || crypto.CheckStr("server", opts.Server, 256) != nil {
		return nil, nil, errors.New("store: the server's origin must be 1 to 256 characters")
	}
	if opts.RegistrationCode == "" || crypto.CheckStr("registration_code", opts.RegistrationCode, 256) != nil {
		return nil, nil, errors.New("store: the registration code must be 1 to 256 characters")
	}
	unlock, err := s.lockFile()
	if err != nil {
		return nil, nil, err
	}
	defer unlock()
	if err := s.catchUp(); err != nil {
		return nil, nil, err
	}
	if pending, err := s.l.publicationPending(); err != nil {
		return nil, nil, err
	} else if pending {
		return nil, nil, ErrPublicationPending
	}
	if err := s.refuseLocalAppend(); err != nil {
		return nil, nil, err
	}
	if err := s.refuseCheckpoint(); err != nil {
		return nil, nil, err
	}
	// A local-only vault has no outbox (§11.1).
	if ns, err := s.l.outboxNumbers(); err != nil || len(ns) > 0 {
		return nil, nil, errors.Join(err, errors.New("store: a local-only vault holds outbox records"))
	}
	if _, err := s.outboxKey(); err != nil {
		return nil, nil, err
	}
	j := &publicationJSON{
		V: publicationVersion, Server: opts.Server, Email: email, AccountID: s.state.Account.AccountID,
		VaultID: s.state.VaultID, UploadSeq: s.state.Head.Seq, UploadH: s.state.Head.H,
		RegistrationCode: opts.RegistrationCode,
	}
	wires, err := s.assembleUpload(j.UploadSeq)
	if err != nil {
		return nil, nil, err
	}
	if err := checkUpload(j, wires); err != nil {
		return nil, nil, err
	}
	b, err := sealPublication(s.rec, j)
	if err != nil {
		return nil, nil, err
	}
	t := &txn{}
	t.put(publishRel, b)
	if err := s.commitTxn(t); err != nil {
		return nil, nil, err
	}
	s.pubAlarm = nil
	return j, wires, nil
}

// refuseCheckpoint refuses while a checkpoint journal or an
// unacknowledged kit exists (§10.1). The caller holds s.mu.
func (s *Store) refuseCheckpoint() error {
	if s.kit != nil || s.kitOrphaned {
		return ErrCheckpointPending
	}
	seqs, err := s.journalSeqs()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(seqs) > 0 {
		return ErrCheckpointPending
	}
	// A server-backed checkpoint's journal (checkpoint.go).
	if ok, err := s.l.checkpointExists(); err != nil {
		return err
	} else if ok {
		return ErrCheckpointPending
	}
	return nil
}

// pendingPublication reads the journal and assembles its upload again.
func (s *Store) pendingPublication() (*publicationJSON, []*vaultlog.Wire, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, nil, s.lockedErr()
	}
	unlock, err := s.lockFile()
	if err != nil {
		return nil, nil, err
	}
	defer unlock()
	j, err := s.readPublication(s.rec, s.state.VaultID)
	if err != nil {
		return nil, nil, err
	}
	if j == nil {
		return nil, nil, ErrNoPublication
	}
	if j.AccountID != s.state.Account.AccountID || j.UploadSeq > s.state.Head.Seq {
		return nil, nil, fmt.Errorf("%w: the publication journal does not match the vault", ErrCorrupt)
	}
	if h, err := s.entryHash(j.UploadSeq); err != nil {
		return nil, nil, err
	} else if !h.Equal(j.UploadH) {
		return nil, nil, fmt.Errorf("%w: the publication journal names an entry this vault does not hold", ErrCorrupt)
	}
	wires, err := s.assembleUpload(j.UploadSeq)
	if err != nil {
		return nil, nil, err
	}
	return j, wires, nil
}

// assembleUpload builds the wires of entries 0..last: each entry file with
// the objects its entry names (§4.3: entry files don't hold their objects),
// sorted by digest. The caller holds the file lock.
func (s *Store) assembleUpload(last uint64) ([]*vaultlog.Wire, error) {
	objs := objectDir(s.l.objects())
	out := make([]*vaultlog.Wire, 0, last+1)
	for seq := uint64(0); seq <= last; seq++ {
		w, err := s.l.readEntry(seq)
		if err != nil {
			return nil, err
		}
		w.Objects = []vaultlog.Object{}
		for _, h := range namedObjects(&w.Entry) {
			b, err := objs.FetchObject(h)
			if err != nil {
				return nil, fmt.Errorf("%w: entry %d names object %v: %w", ErrCorrupt, seq, h, err)
			}
			body, err := canonjson.Canonicalize(b)
			if err != nil {
				return nil, err
			}
			w.Objects = append(w.Objects, vaultlog.Object{SHA256: h, Body: body})
		}
		out = append(out, w)
	}
	return out, nil
}

// namedObjects is every object digest an entry's ops name (§5.2), each
// once, sorted.
func namedObjects(e *vaultlog.Entry) []crypto.Hash {
	var hs []crypto.Hash
	for _, o := range e.Ops {
		switch o := o.(type) {
		case *vaultlog.CredsOp:
			hs = append(hs, o.PwBlobSHA256, o.RkBlobSHA256)
		case *vaultlog.VKWrapOp:
			hs = append(hs, o.EnvelopeSHA256)
		case *vaultlog.DeviceAddOp:
			hs = append(hs, o.UnlockSHA256)
		case *vaultlog.ItemPutOp:
			hs = append(hs, o.WrapSHA256, o.BodySHA256)
		case *vaultlog.BundlePutOp:
			hs = append(hs, o.EnvelopeSHA256)
		}
	}
	slices.SortFunc(hs, func(a, b crypto.Hash) int { return bytes.Compare(a[:], b[:]) })
	return slices.CompactFunc(hs, func(a, b crypto.Hash) bool { return a.Equal(b) })
}

// signupBody is the encoded signup request, for its size (plan R9).
type signupBody struct {
	Email            string          `json:"email"`
	RegistrationCode string          `json:"registration_code"`
	Challenge        []byte          `json:"challenge"`
	PopSig           []byte          `json:"pop_sig"`
	Wires            []canonjson.Raw `json:"wires"`
}

// singletonResponse is one entry as the log endpoint returns it, with the
// head's seq at 20 digits (plan R9, "Wire admission").
type singletonResponse struct {
	Entries []singletonEntry `json:"entries"`
	Head    struct {
		Seq string      `json:"seq"`
		H   crypto.Hash `json:"h"`
	} `json:"head"`
}

type singletonEntry struct {
	Seq  uint64        `json:"seq,string"`
	H    crypto.Hash   `json:"h"`
	Wire canonjson.Raw `json:"wire"`
}

// checkUpload is the publication preflight a client can calculate (plan
// R9, R14): the whole encoded signup request against 64 MiB, each wire as a
// singleton log response against 4 MiB, each object against 1 MiB, and the
// collection limits.
func checkUpload(j *publicationJSON, wires []*vaultlog.Wire) error {
	if len(wires) > maxSignupWires {
		return fmt.Errorf("%w: %d entries, at most %d", ErrUploadTooLarge, len(wires), maxSignupWires)
	}
	body := signupBody{
		Email: j.Email, RegistrationCode: j.RegistrationCode,
		Challenge: make([]byte, challengeSize), PopSig: make([]byte, 64), Wires: []canonjson.Raw{},
	}
	empty, err := canonjson.Marshal(body)
	if err != nil {
		return err
	}
	total := len(empty)
	for i, w := range wires {
		if len(w.Entry.Ops) > maxOpsPerWire {
			return fmt.Errorf("%w: entry %d has %d ops, at most %d", ErrUploadTooLarge, i, len(w.Entry.Ops), maxOpsPerWire)
		}
		if len(w.Objects) > maxObjectsPerWire {
			return fmt.Errorf("%w: entry %d has %d objects, at most %d", ErrUploadTooLarge, i, len(w.Objects), maxObjectsPerWire)
		}
		for _, o := range w.Objects {
			if len(o.Body) > maxObjectBody {
				return fmt.Errorf("%w: object %v is %d bytes, at most %d", ErrUploadTooLarge, o.SHA256, len(o.Body), maxObjectBody)
			}
		}
		b, err := w.Marshal()
		if err != nil {
			return err
		}
		// The request nests each wire two levels down: {"wires":[wire]}.
		if d := jsonDepth(b) + 2; d > maxJSONDepth {
			return fmt.Errorf("%w: entry %d nests %d levels deep, at most %d", ErrUploadTooLarge, i, d, maxJSONDepth)
		}
		h, err := w.Entry.Hash()
		if err != nil {
			return err
		}
		resp := singletonResponse{Entries: []singletonEntry{{Seq: w.Entry.Seq, H: h, Wire: b}}}
		resp.Head.Seq, resp.Head.H = strings.Repeat("9", 20), h
		rb, err := canonjson.Marshal(resp)
		if err != nil {
			return err
		}
		if len(rb) > maxSingletonWire {
			return fmt.Errorf("%w: entry %d is %d bytes as a log response, at most %d", ErrUploadTooLarge, i, len(rb), maxSingletonWire)
		}
		total += len(b)
		if i > 0 {
			total++ // the comma
		}
	}
	if total > maxSignupBody {
		return fmt.Errorf("%w: the signup request is %d bytes, at most %d", ErrUploadTooLarge, total, maxSignupBody)
	}
	return nil
}

// jsonDepth is the deepest nesting of objects and arrays in b, which is
// valid JSON.
func jsonDepth(b []byte) int {
	depth, deepest, inStr, esc := 0, 0, false, false
	for _, c := range b {
		switch {
		case esc:
			esc = false
		case inStr && c == '\\':
			esc = true
		case c == '"':
			inStr = !inStr
		case inStr:
		case c == '{' || c == '[':
			depth++
			deepest = max(deepest, depth)
		case c == '}' || c == ']':
			depth--
		}
	}
	return deepest
}

// postUpload posts the journaled upload once. Its outcome is never trusted:
// the resolution reads the server's log.
func (s *Store) postUpload(ctx context.Context, p Publisher, j *publicationJSON, wires []*vaultlog.Wire) error {
	s.mu.Lock()
	if s.state == nil {
		s.mu.Unlock()
		return s.lockedErr()
	}
	ctx, gen, untrack := s.trackRequest(ctx)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		untrack()
		s.mu.Unlock()
	}()
	req := &SignupRequest{
		Server: j.Server, Email: j.Email, RegistrationCode: j.RegistrationCode, AccountID: j.AccountID,
		VaultID: j.VaultID, UploadSeq: j.UploadSeq, UploadH: j.UploadH, Wires: wires,
	}
	req.prove = func(origin string, challenge []byte) ([]byte, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.gen.Load() != gen || s.sec == nil || s.sec.Account == nil {
			return nil, ErrAuthClosed
		}
		if s.state.Head.Seq != j.UploadSeq || !s.state.Head.H.Equal(j.UploadH) {
			return nil, errors.New("store: the vault moved past the upload head")
		}
		return crypto.Sign(s.sec.Account.Sig, labelSignupPoP, &signupPoPObject{
			V: 1, Origin: origin, Email: j.Email, AccountID: j.AccountID, VaultID: j.VaultID,
			UploadSeq: j.UploadSeq, UploadH: j.UploadH, Challenge: append([]byte(nil), challenge...),
		})
	}
	defer func() { req.prove = nil }()
	_, err := p.Signup(ctx, req)
	return err
}

// maxPublishPosts bounds how often a resolution posts the upload again
// when the server says the vault is absent.
const maxPublishPosts = 2

// resolvePublication is §4.3 step 4. postErr is the error of the post just
// made, if any, for the report when the vault stays absent.
func (s *Store) resolvePublication(ctx context.Context, p Publisher, j *publicationJSON, wires []*vaultlog.Wire, postErr error) (Publication, error) {
	for posts := 0; ; posts++ {
		auth, err := s.DeviceAuth()
		if err != nil {
			return Publication{}, err
		}
		var c Committed
		err = s.remoteCall(ctx, func(ctx context.Context) (err error) {
			if err := s.hook("publish:resolve"); err != nil {
				return err
			}
			c, err = p.EntryAt(ctx, auth, j.UploadSeq)
			return err
		})
		if errors.Is(err, ErrPublicationAbsent) {
			if posts >= maxPublishPosts {
				return Publication{}, fmt.Errorf("store: the publication did not commit (%w); it stays pending", errors.Join(err, postErr))
			}
			postErr = s.postUpload(ctx, p, j, wires)
			continue
		}
		if err != nil {
			return Publication{}, fmt.Errorf("store: the publication's outcome is not known yet (%w); it stays pending", err)
		}
		if err := s.checkPublished(j, c); err != nil {
			return Publication{}, err
		}
		return s.finishPublication(ctx, p, j)
	}
}

// remoteCall runs f, a request to the server, without s.mu, with a context
// that Lock cancels; a lock in the meantime discards the result (§11.2).
func (s *Store) remoteCall(ctx context.Context, f func(ctx context.Context) error) error {
	s.mu.Lock()
	if s.state == nil {
		s.mu.Unlock()
		return s.lockedErr()
	}
	ctx, gen, untrack := s.trackRequest(ctx)
	s.mu.Unlock()
	err := f(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	untrack()
	if s.gen.Load() != gen || s.state == nil {
		return ErrSyncInterrupted
	}
	return err
}

// checkPublished compares the server's entry at upload_seq with the
// journal. Another H is an equivocation (§5.6): the alarm is raised and the
// publication stays pending.
func (s *Store) checkPublished(j *publicationJSON, c Committed) error {
	if c.Wire == nil || c.Seq != j.UploadSeq {
		return fmt.Errorf("store: the server returned entry %d for seq %d", c.Seq, j.UploadSeq)
	}
	h, err := c.Wire.Entry.Hash()
	if err != nil {
		return err
	}
	if !h.Equal(c.H) || c.Wire.Entry.Seq != c.Seq {
		return fmt.Errorf("store: the server's entry %d does not match its seq and H", c.Seq)
	}
	if !h.Equal(j.UploadH) {
		eq := &vaultlog.EquivocationError{Seq: j.UploadSeq, Have: j.UploadH, Got: h}
		s.mu.Lock()
		s.pubAlarm = eq
		s.mu.Unlock()
		return eq
	}
	return nil
}

// finishPublication verifies every entry past upload_seq from the server
// with the transition algorithm, committing each, and then switches to
// server-backed mode and deletes the journal in one durable commit.
func (s *Store) finishPublication(ctx context.Context, p Publisher, j *publicationJSON) (Publication, error) {
	for {
		auth, err := s.DeviceAuth()
		if err != nil {
			return Publication{}, err
		}
		var entries []Committed
		var head vaultlog.Head
		var after uint64
		s.mu.Lock()
		if s.state != nil {
			after = s.state.Head.Seq
		}
		s.mu.Unlock()
		err = s.remoteCall(ctx, func(ctx context.Context) (err error) {
			entries, head, err = p.Since(ctx, auth, after)
			return err
		})
		if err != nil {
			return Publication{}, fmt.Errorf("store: the publication committed, but verifying the server's later entries failed (%w); it stays pending", err)
		}
		done, err := s.applyPublished(j, entries, head)
		if err != nil || done {
			if err != nil {
				return Publication{}, err
			}
			pub := j.info()
			return pub, nil
		}
	}
}

// applyPublished verifies and commits one page of later entries, and once
// the verified head reaches the server's, makes the vault server-backed and
// deletes the journal in one commit. It reports whether it did.
func (s *Store) applyPublished(j *publicationJSON, entries []Committed, head vaultlog.Head) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return false, s.lockedErr()
	}
	unlock, err := s.lockFile()
	if err != nil {
		return false, err
	}
	defer unlock()
	before := s.state.Head.Seq
	st, sec, err := s.applyEntries(s.state, s.sec, s.dev, nil, entries, s.rec)
	if rev := (*vaultlog.RevokedError)(nil); errors.As(err, &rev) {
		if sec != s.sec {
			zeroSecrets(sec)
		}
		return false, s.revoke(rev)
	}
	if s.state != nil && st != s.state {
		s.state, s.sec = st, sec
	} else if s.state == nil && sec != nil {
		// An interrupted commit locked the store: these were never installed.
		zeroSecrets(sec)
	}
	if err != nil {
		var eq *vaultlog.EquivocationError
		if errors.As(err, &eq) {
			s.pubAlarm = eq
		}
		return false, err
	}
	ours := s.state.Head
	switch {
	case head.Seq < ours.Seq:
		return false, fmt.Errorf("%w: the server is at seq %d, this device at %d", ErrServerBehind, head.Seq, ours.Seq)
	case head.Seq == ours.Seq && !head.H.Equal(ours.H):
		eq := &vaultlog.EquivocationError{Seq: ours.Seq, Have: ours.H, Got: head.H}
		s.pubAlarm = eq
		return false, eq
	case head.Seq > ours.Seq:
		if ours.Seq == before {
			return false, fmt.Errorf("store: the server reports head %d but returned no entry past %d", head.Seq, before)
		}
		return false, nil
	}
	if err := s.hook("publish:switch"); err != nil {
		return false, err
	}
	t := &txn{}
	if err := serverModeOps(t, serverFile{Server: j.Server, Email: j.Email}); err != nil {
		return false, err
	}
	t.remove(publishRel)
	if err := s.commitTxn(t); err != nil {
		return false, err
	}
	s.server, s.pubAlarm = true, nil
	return true, nil
}

// TODO(slice E2 follow-up): another writer is adding a shared
// internal/email package; once it is on the phase branch, use its
// normalization here and delete this copy.
//
// NormalizeEmail normalizes and checks an email address as the server does
// (plan R4): leading and trailing ASCII spaces and tabs are removed, the
// domain is lowercased (ASCII only) and the local part kept byte for byte.
// Only an ASCII dot-atom local part of 1 to 64 bytes and an ASCII DNS
// domain name are accepted, at most 254 bytes in all.
func NormalizeEmail(email string) (string, error) {
	e := strings.Trim(email, " \t")
	bad := func(why string) (string, error) { return "", fmt.Errorf("store: not a usable email address: %s", why) }
	for i := 0; i < len(e); i++ {
		if c := e[i]; c <= ' ' || c >= 0x7f {
			return bad("it holds a space, a control character or a non-ASCII character")
		}
	}
	at := strings.LastIndexByte(e, '@')
	if at < 0 {
		return bad("there is no @")
	}
	local, domain := e[:at], strings.ToLower(e[at+1:])
	if len(local) < 1 || len(local) > 64 {
		return bad("the part before @ must be 1 to 64 characters")
	}
	for _, atom := range strings.Split(local, ".") {
		if atom == "" {
			return bad("the part before @ has an empty dot-separated part")
		}
		for i := 0; i < len(atom); i++ {
			c := atom[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) >= 0) {
				return bad("the part before @ holds a character a dot-atom can't")
			}
		}
	}
	if domain == "" || len(domain) > 253 {
		return bad("the domain must be 1 to 253 characters")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return bad("the domain is not a DNS name")
		}
		for i := 0; i < len(label); i++ {
			if c := label[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return bad("the domain is not a DNS name")
			}
		}
	}
	out := local + "@" + domain
	if len(out) > 254 {
		return bad("it is longer than 254 characters")
	}
	return out, nil
}
