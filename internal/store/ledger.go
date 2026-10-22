package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// The sign-in ledger keeps what this data directory has learnt about the
// devices its sign-ins enrolled in other accounts, outside device.json and
// the device key store, so neither a failed keychain write nor a cancelled
// merge loses it:
//
//	signins.json = JCS({"v":1, "accounts":[{"account_id":id, "revoked":[id, ...], "orphaned":[id, ...]}, ...]})
//
// with accounts sorted by account_id and each list sorted, with no
// duplicates.
//
//   - revoked: devices a verified checkpoint revoked (§5.5) while a sign-in
//     (SignIn's pending device, or a login merge's destination device) was
//     enrolling them. The entry is written durably before the device's
//     tombstone is attempted, and it is terminal: a sign-in or merge whose
//     device.json names one of them stops (ErrSignInRevoked) before it
//     reads the device key store or asks the server, and retries the
//     tombstone. Nothing installs one (installSignIn, dropSource), a
//     promotion revokes it (promoteNextLocked), and Open and every unlock
//     refuse one that device.json names as this device or its pending
//     replacement (checkRevoked). It is never removed.
//   - orphaned: destination devices a MergeCancel with ForceOrphan dropped
//     from device.json while a bootstrap may have committed for them. The
//     next merge into account_id carries them into its next.stale, and the
//     next SignIn into it into its stale devices, so hop passwd revokes
//     the active ones once that destination is installed. The ledger
//     forgets them once device.json lists them.
//
// It lives next to device.json, not in vault/, so a logout's cleanup of
// the vault leaves it. Anything that does not parse is ErrCorrupt, and
// every sign-in, merge, promotion, Open and unlock then refuses: it never
// reads as empty.

const (
	ledgerRel     = "signins.json"
	ledgerVersion = 1
)

func (l layout) ledgerFile() string { return filepath.Join(l.data, ledgerRel) }

type signInLedger struct {
	V        int             `json:"v"`
	Accounts []ledgerAccount `json:"accounts"`
}

type ledgerAccount struct {
	AccountID model.ID   `json:"account_id"`
	Revoked   []model.ID `json:"revoked"`
	Orphaned  []model.ID `json:"orphaned"`
}

func compareIDs(a, b model.ID) int { return bytes.Compare(a[:], b[:]) }

// readLedger reads signins.json, or returns an empty ledger when there is
// none. The caller holds the file lock.
func (l layout) readLedger() (*signInLedger, error) {
	g := &signInLedger{V: ledgerVersion}
	b, err := os.ReadFile(l.ledgerFile())
	if errors.Is(err, os.ErrNotExist) {
		return g, nil
	}
	if err != nil {
		return nil, err
	}
	bad := fmt.Errorf("%w: %s does not parse", ErrCorrupt, l.ledgerFile())
	if canonjson.Unmarshal(b, g) != nil || g.V != ledgerVersion {
		return nil, bad
	}
	for i, a := range g.Accounts {
		if a.AccountID.IsZero() || (i > 0 && compareIDs(g.Accounts[i-1].AccountID, a.AccountID) >= 0) {
			return nil, bad
		}
		for _, ids := range [][]model.ID{a.Revoked, a.Orphaned} {
			for j, id := range ids {
				if id.IsZero() || (j > 0 && compareIDs(ids[j-1], id) >= 0) {
					return nil, bad
				}
			}
		}
	}
	return g, nil
}

// writeLedger replaces signins.json durably. The caller holds the file
// lock.
func (l layout) writeLedger(g *signInLedger) error {
	g.V = ledgerVersion
	for i := range g.Accounts {
		a := &g.Accounts[i]
		if a.Revoked == nil {
			a.Revoked = []model.ID{}
		}
		if a.Orphaned == nil {
			a.Orphaned = []model.ID{}
		}
	}
	if g.Accounts == nil {
		g.Accounts = []ledgerAccount{}
	}
	b, err := canonjson.Marshal(g)
	if err != nil {
		return err
	}
	return writeFileAtomic(l.ledgerFile(), b)
}

// account returns the entry of id, or nil.
func (g *signInLedger) account(id model.ID) *ledgerAccount {
	for i := range g.Accounts {
		if g.Accounts[i].AccountID == id {
			return &g.Accounts[i]
		}
	}
	return nil
}

// isRevoked reports whether device dev of account acct is revoked.
func (g *signInLedger) isRevoked(acct, dev model.ID) bool {
	a := g.account(acct)
	return a != nil && slices.Contains(a.Revoked, dev)
}

// orphaned returns the orphaned devices of account acct.
func (g *signInLedger) orphaned(acct model.ID) []model.ID {
	if a := g.account(acct); a != nil {
		return slices.Clone(a.Orphaned)
	}
	return nil
}

// add records revoked and orphaned devices of account acct, and reports
// whether anything changed.
func (g *signInLedger) add(acct model.ID, revoked, orphaned []model.ID) bool {
	a := g.account(acct)
	if a == nil {
		g.Accounts = append(g.Accounts, ledgerAccount{AccountID: acct})
		slices.SortFunc(g.Accounts, func(x, y ledgerAccount) int { return compareIDs(x.AccountID, y.AccountID) })
		a = g.account(acct)
	}
	changed := false
	merge := func(list *[]model.ID, ids []model.ID) {
		for _, id := range ids {
			if !id.IsZero() && !slices.Contains(*list, id) {
				*list = append(*list, id)
				changed = true
			}
		}
		slices.SortFunc(*list, compareIDs)
	}
	merge(&a.Revoked, revoked)
	merge(&a.Orphaned, orphaned)
	return changed
}

// clearOrphaned forgets the orphaned devices of account acct, and reports
// whether anything changed.
func (g *signInLedger) clearOrphaned(acct model.ID) bool {
	a := g.account(acct)
	if a == nil || len(a.Orphaned) == 0 {
		return false
	}
	a.Orphaned = nil
	return true
}

// markRevoked records durably that device dev of account acct was
// revoked. The caller holds the file lock.
func (l layout) markRevoked(acct, dev model.ID) error {
	g, err := l.readLedger()
	if err != nil {
		return err
	}
	if !g.add(acct, []model.ID{dev}, nil) {
		return nil
	}
	return l.writeLedger(g)
}
