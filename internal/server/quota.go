package server

import (
	"context"
	"errors"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/email"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// R13 charges an account for the bytes a commit persists, per vault and
// regardless of physical deduplication:
//
//	len(stored wire) + entryRowOverhead
//	+ len(body) + rowOverhead      for each object new to the vault
//	+ rowOverhead                  for each new device row (device_add) and each receipt (departure)
//	+ len(public state after) − len(public state before)
//
// The public state is one column that each commit replaces, so its term
// is the change in its size and can be negative. A signup is charged its
// wires as above, its whole public state, and once the rows it keeps for
// the life of the account (signupCharge). Sessions, login tokens and
// challenges are not charged: they expire, the janitor deletes them, and
// R8 and R14 bound how many can exist.
const (
	// entryRowOverhead is a log row apart from its wire: vault ID, seq, H
	// and kind, the entries of its two indexes, and SQLite's record and
	// page overhead.
	entryRowOverhead = 512
	// rowOverhead is an object, device or receipt row apart from an object
	// body: two 16- or 32-byte key columns, a 32-byte public key or digest,
	// small integers, the primary-key index entry and SQLite's record
	// overhead. The largest, a receipt, is about 120 bytes.
	rowOverhead = 160
	// stateOpOverhead bounds what one op adds to the serialized public
	// state beyond its own bytes in the wire: a map key and a retired-list
	// ID (each a quoted 32-digit hex ID with punctuation) and the fixed
	// members of an item, grant, device or deploy record.
	stateOpOverhead = 256
)

// signupRowOverhead is the fixed part of the rows a signup keeps for the
// life of the account, apart from the email and the capability hash: the
// account row (two 16-byte IDs, a 16-byte salt, two 32-byte verifiers and
// six integers) with its primary-key, email and vault indexes; the vault
// row (two 16-byte IDs, a 32-byte head hash and three integers; the public
// state is charged on its own) with its two indexes; and the consumed
// registration row holding the publication acknowledgment (two 16-byte
// IDs, a 32-byte digest, a 32-byte head hash and four integers) with its
// primary-key index; plus SQLite's record and page overhead for the
// three rows and six index entries.
const signupRowOverhead = 1024

// signupCharge is what a signup is charged for the rows it keeps for the
// life of the account (R13):
//
//	signupRowOverhead
//	+ 3 × len(email)      the account row, its email index and the registration row
//	+ 2 × len(cap_hash)   the registration row and its primary-key index
func signupCharge(email string, capHash crypto.Hash) int64 {
	return signupRowOverhead + 3*int64(len(email)) + 2*int64(len(capHash))
}

// reserveHalf is each half of the R13 recovery reserve: the most one
// bootstrap or one checkpoint can be charged under the R9 and R14 limits.
// With W = MaxWireResponse, a wire that passes R9 is stored in fewer than
// W bytes, and the object bodies it carries are part of those bytes, so
//
//	half = W + entryRowOverhead                 the stored wire and its row
//	     + W + MaxObjects × rowOverhead         new object bodies and their rows
//	     + MaxOps × rowOverhead                 device rows and receipts, at most one per op
//	     + W + MaxOps × stateOpOverhead         public-state growth
//
// The public state holds only what ops say, so one entry grows it by at
// most its own wire plus the structure each op adds. The bootstrap and the
// checkpoint have the same bound. With the default limits (4 MiB, 16,384
// objects, 8,192 ops) a half is 18,612,736 bytes, about 17.75 MiB, and the
// whole reserve about 35.5 MiB of the 256 MiB default quota.
func reserveHalf(l Limits) int64 {
	w := int64(l.MaxWireResponse)
	return w + entryRowOverhead +
		w + int64(l.MaxObjects)*rowOverhead +
		int64(l.MaxOps)*rowOverhead +
		w + int64(l.MaxOps)*stateOpOverhead
}

// stored reports what a vault and its account already hold, for R13.
type stored interface {
	hasObject(crypto.Hash) (bool, error)
	// hasDevice: a checkpoint repeats the device_add of every surviving
	// device, which updates the existing row.
	hasDevice(model.ID) (bool, error)
}

// entryCost is R13's charge for storing pw with deps departures, without
// the public-state term.
func entryCost(pw *prepared, deps int, have stored) (int64, error) {
	cost := int64(len(pw.canon)) + entryRowOverhead
	for _, o := range pw.w.Objects {
		ok, err := have.hasObject(o.SHA256)
		if err != nil {
			return 0, err
		}
		if !ok {
			cost += int64(len(o.Body)) + rowOverhead
		}
	}
	for _, op := range pw.w.Entry.Ops {
		if d, isAdd := op.(*vaultlog.DeviceAddOp); isAdd {
			ok, err := have.hasDevice(d.Cert.DeviceID)
			if err != nil {
				return 0, err
			}
			if !ok {
				cost += rowOverhead
			}
		}
	}
	return cost + int64(deps)*rowOverhead, nil
}

// txStored is what the store holds for one vault and its account.
type txStored struct {
	tx      Tx
	vault   model.ID
	account model.ID
}

func (t txStored) hasObject(h crypto.Hash) (bool, error) {
	_, err := t.tx.Object(t.vault, h)
	return found(err)
}

func (t txStored) hasDevice(id model.ID) (bool, error) {
	_, err := t.tx.Device(t.account, id)
	return found(err)
}

func found(err error) (bool, error) {
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// pubStored is what earlier wires of a signup publication store.
type pubStored struct {
	objects vaultlog.ObjectMap
	devices map[model.ID]bool
}

func (p pubStored) hasObject(h crypto.Hash) (bool, error) {
	_, ok := p.objects[h]
	return ok, nil
}

func (p pubStored) hasDevice(id model.ID) (bool, error) { return p.devices[id], nil }

func (s *Server) quota(a *Account) int64 {
	if a.QuotaBytes > 0 {
		return a.QuotaBytes
	}
	return s.lim.QuotaBytes
}

// admit applies R13 to a write charged cost and returns the account's
// reserve state after it. A write that leaves the whole reserve free is
// ordinary and admitted in any state. Otherwise only the recovery sequence
// may spend the reserve, once:
//
//   - ReserveIntact: a bootstrap may spend the bootstrap half
//     (→ ReserveBootstrapSpent). A checkpoint that follows an ordinary
//     bootstrap may spend the whole reserve (→ ReserveExhausted).
//   - ReserveBootstrapSpent: a checkpoint may spend the rest
//     (→ ReserveExhausted). A second bootstrap may not.
//   - ReserveExhausted: nothing may spend the reserve until an operator
//     raises the quota (SetQuota).
//
// v is nil for a signup, which is always ordinary.
func (s *Server) admit(a *Account, v *Vault, kind vaultlog.Kind, cost int64) (ReserveState, bool) {
	quota, half := s.quota(a), reserveHalf(s.lim)
	used := a.UsedBytes + cost
	if used+2*half <= quota {
		return a.Reserve, true
	}
	switch {
	case kind == vaultlog.KindBootstrap && a.Reserve == ReserveIntact && used+half <= quota:
		return ReserveBootstrapSpent, true
	case kind == vaultlog.KindCheckpoint && used <= quota &&
		(a.Reserve == ReserveBootstrapSpent || a.Reserve == ReserveIntact && v.LastBootstrap > v.LastCheckpoint):
		return ReserveExhausted, true
	}
	return a.Reserve, false
}

// QuotaStatus is an account's R13 position.
type QuotaStatus struct {
	AccountID    model.ID
	Email        string
	UsedBytes    int64
	QuotaBytes   int64
	ReserveBytes int64 // the whole recovery reserve
	Reserve      ReserveState
}

// SetQuota sets an account's storage quota: the operator raising capacity
// (R13). who is an account ID or an email. When the new quota leaves the
// whole recovery reserve free, the reserve is replenished and the account
// returns to ReserveIntact; otherwise its reserve state is kept. lim must
// be the limits the server runs with.
func SetQuota(ctx context.Context, st Store, who string, quota int64, lim Limits) (*QuotaStatus, error) {
	if quota <= 0 {
		return nil, errors.New("server: the quota must be positive")
	}
	var out *QuotaStatus
	err := st.Update(ctx, func(tx Tx) error {
		a, err := findAccount(tx, who)
		if err != nil {
			return err
		}
		reserve := 2 * reserveHalf(lim)
		a.QuotaBytes = quota
		if a.UsedBytes+reserve <= quota {
			a.Reserve = ReserveIntact
		}
		if err := tx.UpdateAccount(a); err != nil {
			return err
		}
		out = &QuotaStatus{
			AccountID: a.ID, Email: a.Email, UsedBytes: a.UsedBytes, QuotaBytes: a.QuotaBytes,
			ReserveBytes: reserve, Reserve: a.Reserve,
		}
		return nil
	})
	return out, err
}

// findAccount looks an account up by ID or by email.
func findAccount(tx Tx, who string) (*Account, error) {
	var a *Account
	var err error
	if id, ok := parseID(who); ok {
		a, err = tx.Account(id)
	} else {
		email, nerr := email.Normalize(who)
		if nerr != nil {
			return nil, errors.New("server: not an account ID or email")
		}
		a, err = tx.AccountByEmail(email)
	}
	if errors.Is(err, ErrNotFound) {
		return nil, errors.New("server: no such account")
	}
	return a, err
}
