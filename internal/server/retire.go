package server

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"strconv"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Retirement status (R5, crypto spec §9). A device whose logout is
// unresolved signs a retire-status challenge to learn its receipt, whether
// its retirement entry committed, and the head; while it is still active
// and the head is its entry's prev, it may post that entry again. Neither
// endpoint issues a session or returns anything else.

// retireAuth checks a retire-status device challenge and its signature
// inside tx: the challenge must be bound to this account, this device, the
// operation "retire-status" and the configured origin, and be unexpired;
// the device may be active or departed, and the signature must verify
// under the key it was added with (R5). It consumes nothing.
func (s *Server) retireAuth(tx Tx, accountID, deviceID model.ID, chal, sig []byte) (*Challenge, *Device, error) {
	if len(chal) != crypto.ChallengeSize {
		return nil, nil, errUnauthorized
	}
	ch, err := tx.Challenge(crypto.SHA256(chal))
	if errors.Is(err, ErrNotFound) {
		return nil, nil, errUnauthorized
	}
	if err != nil {
		return nil, nil, err
	}
	if ch.Kind != ChallengeDevice || ch.Operation != crypto.OperationRetireStatus ||
		ch.AccountID != accountID || ch.DeviceID != deviceID ||
		!s.now().Before(ch.ExpiresAt) || ch.Origin != s.origin {
		return nil, nil, errUnauthorized
	}
	d, err := tx.Device(ch.AccountID, ch.DeviceID)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, errUnauthorized
	}
	if err != nil {
		return nil, nil, err
	}
	obj := &crypto.DeviceAuth{
		V: crypto.Version, Origin: ch.Origin, AccountID: ch.AccountID, DeviceID: ch.DeviceID,
		Operation: ch.Operation, Challenge: chal,
	}
	if crypto.VerifyDeviceAuth(ed25519.PublicKey(d.SigPK), obj, sig) != nil {
		return nil, nil, errUnauthorized
	}
	return ch, d, nil
}

type retireStatusRequest struct {
	AccountID model.ID    `json:"account_id"`
	Challenge []byte      `json:"challenge"`
	DeviceID  model.ID    `json:"device_id"`
	H         crypto.Hash `json:"h"`
	Sig       []byte      `json:"sig"`
}

// receiptJSON is a permanent receipt (§9): {device_id, how, seq, h}.
type receiptJSON struct {
	DeviceID model.ID    `json:"device_id"`
	H        crypto.Hash `json:"h"`
	How      string      `json:"how"`
	Seq      uint64      `json:"seq,string"`
}

// u64s is a u64 written as a decimal string, for a member that may be
// null (canonjson takes ,string only on integer fields, not pointers).
type u64s uint64

func (n u64s) MarshalText() ([]byte, error) { return strconv.AppendUint(nil, uint64(n), 10), nil }

type retireStatusResponse struct {
	Committed bool          `json:"committed"`
	Head      vaultlog.Head `json:"head"`
	Receipt   *receiptJSON  `json:"receipt"`
	Seq       *u64s         `json:"seq"`
}

// retireStatus: POST /v1/retire-status {account_id, device_id, challenge,
// sig, h} → {receipt|null, committed, seq|null, head}. In one write
// transaction, serialized with every commit: retireAuth, the account's
// bucket, then the challenge is consumed and the answer read: this
// device's receipt only, whether h is committed in the account's vault and
// at what seq, and the head (R5).
func (s *Server) retireStatus(w http.ResponseWriter, r *http.Request, c *call) error {
	var req retireStatusRequest
	if err := s.decode(c.body, &req); err != nil {
		return err
	}
	var resp retireStatusResponse
	err := s.store.Update(r.Context(), func(tx Tx) error {
		ch, _, err := s.retireAuth(tx, req.AccountID, req.DeviceID, req.Challenge, req.Sig)
		if err != nil {
			return err
		}
		if !s.limiter.allow(c.route.pattern+"|account", ch.AccountID.String(), s.rates.Account) {
			return errRateLimited
		}
		if err := tx.DeleteChallenge(ch.Hash); err != nil {
			return err
		}
		a, err := tx.Account(ch.AccountID)
		if err != nil {
			return err
		}
		v, err := tx.Vault(a.VaultID)
		if err != nil {
			return err
		}
		resp.Head = v.Head
		rc, err := tx.Receipt(ch.AccountID, ch.DeviceID)
		switch {
		case err == nil:
			resp.Receipt = &receiptJSON{DeviceID: rc.DeviceID, H: rc.H, How: string(rc.How), Seq: rc.Seq}
		case !errors.Is(err, ErrNotFound):
			return err
		}
		e, err := tx.EntryByHash(v.ID, req.H)
		switch {
		case err == nil:
			seq := u64s(e.Seq)
			resp.Committed, resp.Seq = true, &seq
		case !errors.Is(err, ErrNotFound):
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

type retirePostRequest struct {
	AccountID model.ID      `json:"account_id"`
	Challenge []byte        `json:"challenge"`
	DeviceID  model.ID      `json:"device_id"`
	Sig       []byte        `json:"sig"`
	Wire      canonjson.Raw `json:"wire"`
}

// onlyRetireOf reports whether e is a normal entry, authored by dev, whose
// only op is dev's device_retire.
func onlyRetireOf(e *vaultlog.Entry, dev model.ID) bool {
	if e.Kind != vaultlog.KindNormal || e.Author != dev || len(e.Ops) != 1 {
		return false
	}
	op, ok := e.Ops[0].(*vaultlog.DeviceRetireOp)
	return ok && op.DeviceID == dev
}

// retirePost: POST /v1/retire-status/post {account_id, device_id,
// challenge, sig, wire} → {seq, h}, or head_conflict. The wire must be
// only this device's device_retire, and the device must still be active.
// Like postLog, it holds a validation slot while it decodes and prepares
// the wire, checks the signature and the device in a read transaction
// before it takes the account's admission lock (a retirement always
// invalidates the device's sessions, R2), and commits under that lock with
// the normal commit path: head check, ApplyPublic, R13 admission, receipt
// and session invalidation, in one transaction that also consumes the
// challenge. A challenge that authenticated is consumed even when the
// commit is refused (head_conflict, invalid entry, quota): a retry needs a
// fresh one (R5). Refusals of the challenge, the signature or an inactive
// device consume nothing.
func (s *Server) retirePost(w http.ResponseWriter, r *http.Request, c *call) error {
	release, ok := s.validate.acquire(r.Context())
	if !ok {
		return errBusy
	}
	defer func() { release() }()
	if !s.collectionsWithin(c.body, "wire") {
		return errTooLarge
	}
	var req retirePostRequest
	if err := s.decode(c.body, &req); err != nil {
		return err
	}
	wire, err := vaultlog.ParseWire(req.Wire)
	if err != nil {
		return errInvalidEntry(err)
	}
	if !onlyRetireOf(&wire.Entry, req.DeviceID) {
		return errBadRequest("the wire must hold only the signing device's device_retire")
	}
	pw, err := s.prepare(wire)
	if err != nil {
		return err
	}
	// authorize checks everything but the commit inside tx.
	authorize := func(tx Tx) (*Challenge, *Account, error) {
		ch, d, err := s.retireAuth(tx, req.AccountID, req.DeviceID, req.Challenge, req.Sig)
		if err != nil {
			return nil, nil, err
		}
		if !d.Active {
			return nil, nil, errUnauthorized
		}
		a, err := tx.Account(ch.AccountID)
		if err != nil {
			return nil, nil, err
		}
		if pw.w.Entry.VaultID != a.VaultID {
			return nil, nil, errBadRequest("the wire is not for the account's vault")
		}
		return ch, a, nil
	}
	err = s.store.View(r.Context(), func(tx Tx) error {
		_, _, err := authorize(tx)
		return err
	})
	if err != nil {
		return err
	}
	if !s.limiter.allow(c.route.pattern+"|account", req.AccountID.String(), s.rates.Account) {
		return errRateLimited
	}

	release()
	release = func() {}
	unlock, err := s.accounts.lock(r.Context(), req.AccountID)
	if err != nil {
		return err
	}
	defer unlock()
	if release, ok = s.validate.acquire(r.Context()); !ok {
		release = func() {}
		return errBusy
	}
	var result vaultlog.Head
	var vaultID model.ID
	var refused error
	committed := false
	err = s.store.Update(r.Context(), func(tx Tx) error {
		ch, a, err := authorize(tx)
		if err != nil {
			return err
		}
		vaultID = a.VaultID
		if err := tx.DeleteChallenge(ch.Hash); err != nil {
			return err
		}
		result, committed, err = s.commit(tx, a.ID, a.VaultID, pw, true)
		var ae *apiError
		if errors.As(err, &ae) {
			// commit refuses before it writes anything: keep only the
			// consumed challenge.
			refused = err
			return nil
		}
		return err
	})
	if err != nil {
		return err
	}
	if refused != nil {
		return refused
	}
	if committed {
		s.hub.notify(vaultID)
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}
