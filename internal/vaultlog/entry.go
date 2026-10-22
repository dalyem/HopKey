// Package vaultlog implements HopKey's vault log (crypto spec §5, with the
// parts of §6, §8 and §10 it refers to; https://plan.23d.dev/p/xuu5z9q2,
// rev 10). It decides which state a client trusts.
//
// The package is pure logic: no network, no disk and no clock. Objects come
// through an ObjectFetcher, device private keys through a DeviceKey, and the
// caller persists the State and Secrets it gets back. Comments citing "rev
// 10 item N" refer to the numbered vault-log clarifications in the spec's
// "Changes from rev 9".
//
// The entry points are:
//
//   - CheckPublic: the public stage of a transition; also the whole check a
//     server runs (§5.3 "Who validates what").
//   - Transition: public stage, revoked-here exit, plaintext stage (§5.5).
//   - Anchor: the fresh-client anchor algorithm (§5.5).
//   - BuildGenesis, BuildBootstrap, BuildNormal, BuildCheckpoint: the
//     entries a client authors; every result has passed Transition or
//     Anchor before it is returned.
package vaultlog

import (
	"crypto/sha256"
	"fmt"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// Kind is an entry kind (§5.1).
type Kind string

const (
	KindGenesis    Kind = "genesis"
	KindCheckpoint Kind = "checkpoint"
	KindBootstrap  Kind = "bootstrap"
	KindNormal     Kind = "normal"
)

// Entry is E (§5.1):
//
//	{"v":1, "suite":1, "vault_id":id, "seq":u64s, "prev":h | "",
//	 "kind":..., "akv":u32, "kv":u32, "author":id, "time":ts, "ops":[op, ...]}
type Entry struct {
	V       int             `json:"v"`
	Suite   int             `json:"suite"`
	VaultID model.ID        `json:"vault_id"`
	Seq     uint64          `json:"seq,string"`
	Prev    crypto.OptHash  `json:"prev"`
	Kind    Kind            `json:"kind"`
	AKV     uint32          `json:"akv"`
	KV      uint32          `json:"kv"`
	Author  model.ID        `json:"author"`
	Time    model.Timestamp `json:"time"`
	Ops     []Op            `json:"ops"`
}

// entryJSON is Entry with undecoded ops, for the strict decoder.
type entryJSON struct {
	V       int             `json:"v"`
	Suite   int             `json:"suite"`
	VaultID model.ID        `json:"vault_id"`
	Seq     uint64          `json:"seq,string"`
	Prev    crypto.OptHash  `json:"prev"`
	Kind    Kind            `json:"kind"`
	AKV     uint32          `json:"akv"`
	KV      uint32          `json:"kv"`
	Author  model.ID        `json:"author"`
	Time    model.Timestamp `json:"time"`
	Ops     []canonjson.Raw `json:"ops"`
}

// Role is a signature role (§5.1).
type Role string

const (
	RoleDevice     Role = "device"
	RoleAccountOld Role = "account_old"
	RoleAccountNew Role = "account_new"
	RoleAccount    Role = "account"
)

// Sig is one {"role", "sig":b64} of wire.sigs. Every signature is
// Sig(key, "hopkey/v1/log-entry", E).
type Sig struct {
	Role Role   `json:"role"`
	Sig  []byte `json:"sig"`
}

// Object is one {"sha256":h, "body":envelope} of wire.objects. Its digest
// is SHA-256(JCS(body)) (§3). Bodies are AEAD or HPKE envelopes only;
// certificates travel inside device_add (rev 10 item 17).
type Object struct {
	SHA256 crypto.Hash   `json:"sha256"`
	Body   canonjson.Raw `json:"body"`
}

// Wire is {"entry":E, "sigs":[...], "objects":[...]} (§5.1).
type Wire struct {
	Entry   Entry    `json:"entry"`
	Sigs    []Sig    `json:"sigs"`
	Objects []Object `json:"objects"`
}

type wireJSON struct {
	Entry   canonjson.Raw `json:"entry"`
	Sigs    []Sig         `json:"sigs"`
	Objects []Object      `json:"objects"`
}

// Hash returns H(E) = D("hopkey/v1/log-entry", E).
func (e *Entry) Hash() (crypto.Hash, error) {
	if err := e.validate(); err != nil {
		return crypto.Hash{}, err
	}
	return crypto.D(crypto.LabelLogEntry, e)
}

// validate checks the closed schema of E and of every op.
func (e *Entry) validate() error {
	if e.V != crypto.Version || e.Suite != crypto.Suite {
		return fail(RuleSchema, "entry v/suite is %d/%d", e.V, e.Suite)
	}
	if e.VaultID.IsZero() {
		return fail(RuleSchema, "entry vault_id is empty")
	}
	if e.Author.IsZero() {
		return fail(RuleSchema, "entry author is empty")
	}
	switch e.Kind {
	case KindGenesis, KindCheckpoint, KindBootstrap, KindNormal:
	default:
		return fail(RuleSchema, "entry kind %q", e.Kind)
	}
	if err := checkTS("entry", "time", e.Time); err != nil {
		return err
	}
	for i, o := range e.Ops {
		if o == nil {
			return fail(RuleSchema, "op %d is null", i)
		}
		if err := o.validate(); err != nil {
			return err
		}
	}
	return nil
}

// Marshal returns JCS(E).
func (e *Entry) Marshal() ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	return canonjson.Marshal(e)
}

// ParseEntry decodes E with the strict decoder. Unknown ops are rejected.
// Input need not be canonical; hashing always uses the JCS re-encoding.
func ParseEntry(b []byte) (*Entry, error) {
	var j entryJSON
	if err := canonjson.Unmarshal(b, &j); err != nil {
		return nil, failErr(RuleSchema, err, "entry")
	}
	e := &Entry{
		V: j.V, Suite: j.Suite, VaultID: j.VaultID, Seq: j.Seq, Prev: j.Prev, Kind: j.Kind,
		AKV: j.AKV, KV: j.KV, Author: j.Author, Time: j.Time, Ops: make([]Op, 0, len(j.Ops)),
	}
	for _, raw := range j.Ops {
		o, err := parseOp(raw)
		if err != nil {
			return nil, err
		}
		e.Ops = append(e.Ops, o)
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	return e, nil
}

// ParseWire decodes a wire value with the strict decoder.
func ParseWire(b []byte) (*Wire, error) {
	var j wireJSON
	if err := canonjson.Unmarshal(b, &j); err != nil {
		return nil, failErr(RuleSchema, err, "wire")
	}
	e, err := ParseEntry(j.Entry)
	if err != nil {
		return nil, err
	}
	w := &Wire{Entry: *e, Sigs: j.Sigs, Objects: j.Objects}
	if err := w.validateSigs(); err != nil {
		return nil, err
	}
	return w, nil
}

// Marshal returns JCS(wire).
func (w *Wire) Marshal() ([]byte, error) {
	if err := w.Entry.validate(); err != nil {
		return nil, err
	}
	if err := w.validateSigs(); err != nil {
		return nil, err
	}
	return canonjson.Marshal(w)
}

func (w *Wire) validateSigs() error {
	for _, s := range w.Sigs {
		switch s.Role {
		case RoleDevice, RoleAccountOld, RoleAccountNew, RoleAccount:
		default:
			return fail(RuleSchema, "signature role %q", s.Role)
		}
	}
	return nil
}

// objectDigest returns SHA-256(JCS(body)).
func objectDigest(body []byte) (crypto.Hash, error) {
	c, err := canonjson.Canonicalize(body)
	if err != nil {
		return crypto.Hash{}, err
	}
	return sha256.Sum256(c), nil
}

// ObjectFetcher supplies objects by digest: from wire.objects, from a local
// cache, or from the server. The returned body may be in any JSON form; the
// caller checks its digest.
type ObjectFetcher interface {
	FetchObject(h crypto.Hash) ([]byte, error)
}

// ObjectMap is an in-memory ObjectFetcher.
type ObjectMap map[crypto.Hash][]byte

// ErrNoObject is returned by ObjectMap for an unknown digest.
var ErrNoObject = fmt.Errorf("vaultlog: object not found")

func (m ObjectMap) FetchObject(h crypto.Hash) ([]byte, error) {
	b, ok := m[h]
	if !ok {
		return nil, ErrNoObject
	}
	return b, nil
}

// Add stores body under its own digest and returns the digest.
func (m ObjectMap) Add(body []byte) (crypto.Hash, error) {
	h, err := objectDigest(body)
	if err != nil {
		return crypto.Hash{}, err
	}
	m[h] = body
	return h, nil
}

// WireObjects checks that every object's sha256 is the digest of its body,
// that every body is an envelope (rev 10 item 17) and that no digest
// repeats, and returns them as an ObjectMap.
func WireObjects(w *Wire) (ObjectMap, error) {
	m := make(ObjectMap, len(w.Objects))
	for _, o := range w.Objects {
		h, err := objectDigest(o.Body)
		if err != nil {
			return nil, failErr(RuleObjectDigest, err, "object %v", o.SHA256)
		}
		if !h.Equal(o.SHA256) {
			return nil, fail(RuleObjectDigest, "object %v has digest %v", o.SHA256, h)
		}
		if !isEnvelope(o.Body) {
			return nil, fail(RuleObjectEnvelope, "object %v is not an AEAD or HPKE envelope", h)
		}
		if _, dup := m[h]; dup {
			return nil, fail(RuleSchema, "object %v listed twice", h)
		}
		m[h] = o.Body
	}
	return m, nil
}

// isEnvelope reports whether body is an AEAD or an HPKE envelope under its
// closed schema (§3).
func isEnvelope(body []byte) bool {
	if _, err := crypto.ParseAEADEnvelope(body); err == nil {
		return true
	}
	_, err := crypto.ParseHPKEEnvelope(body)
	return err == nil
}
