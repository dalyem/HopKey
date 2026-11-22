package vaultlog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"slices"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// Candidate is an entry that passed the public stage, with the candidate
// post-state it declares. The candidate may be used for validation only,
// never by the application (§5.5).
type Candidate struct {
	Wire *Wire
	H    crypto.Hash
	Pre  *State // nil at an anchor and for a server's genesis
	Post *State

	pin *crypto.AccountPin // set at an anchor

	accountKeys *AccountKeysOp
	creds       *CredsOp
	vkWrap      *VKWrapOp
	retired     *RetiredOp
	history     *HistoryOp

	deviceAdds     map[model.ID]*DeviceAddOp // by device_id
	revokedDevices idSet
	retiredDevices idSet // device_retire (rev 16)
	puts           map[model.ID]*ItemPutOp
	deletes        map[model.ID]*ItemDeleteOp
	grantAdds      map[model.ID]*GrantAddOp // by grant_id
	grantByRecord  map[model.ID]*GrantAddOp // by record_item_id
	bundlePuts     map[model.ID]*BundlePutOp
	revokedGrants  idSet
	deploys        map[model.ID]*DeployOp

	aead map[crypto.Hash]crypto.AEADEnvelope
	hpke map[crypto.Hash]crypto.HPKEEnvelope
}

// Kind returns the entry kind.
func (c *Candidate) Kind() Kind { return c.Wire.Entry.Kind }

// Revokes reports whether the entry revokes device id.
func (c *Candidate) Revokes(id model.ID) bool { return c.revokedDevices[id] }

// Retires reports whether the entry is device id's device_retire (rev 16).
func (c *Candidate) Retires(id model.ID) bool { return c.retiredDevices[id] }

// CheckPublic is the public stage of the transition algorithm (§5.5): seq,
// prev, the header rules, the closed schemas, the public §5.3 rules for the
// entry's kind against pre, every required signature, and the digests of
// the named objects. It is also everything a server checks (§5.3 "Who
// validates what"). With pre == nil it accepts only a genesis entry, as a
// server's first entry.
//
// objs supplies objects the wire does not carry; it may be nil.
func CheckPublic(pre *State, w *Wire, objs ObjectFetcher) (*Candidate, error) {
	if pre == nil && w.Entry.Kind != KindGenesis {
		return nil, fail(RuleAnchorKind, "with no verified state only a genesis entry can be checked")
	}
	return checkPublic(pre, nil, w, objs)
}

// CheckHeader is the public stage without the objects: seq, prev, the
// header rules, the closed schemas, the public §5.3 rules for the entry's
// kind against pre, and every required signature, over an entry whose
// wire may carry no objects. The digests the entry names are covered by
// its signatures, but the objects behind them are neither fetched nor
// checked, so the candidate it returns says only who signed what, in
// which order: it serves a device that left the account to verify the
// entry that removed it (its revocation proof), and is never a step of
// the transition algorithm. pre must be a verified state.
func CheckHeader(pre *State, w *Wire) (*Candidate, error) {
	if pre == nil {
		return nil, fail(RuleAnchorKind, "a header is checked only against a verified state")
	}
	return checkEntry(pre, nil, w, nil, false)
}

func checkPublic(pre *State, pin *crypto.AccountPin, w *Wire, objs ObjectFetcher) (*Candidate, error) {
	return checkEntry(pre, pin, w, objs, true)
}

// checkEntry is the public stage; withObjects fetches and checks the
// objects the entry names.
func checkEntry(pre *State, pin *crypto.AccountPin, w *Wire, objs ObjectFetcher, withObjects bool) (*Candidate, error) {
	e := &w.Entry
	if err := e.validate(); err != nil {
		return nil, err
	}
	if err := w.validateSigs(); err != nil {
		return nil, err
	}
	h, err := e.Hash()
	if err != nil {
		return nil, err
	}
	c := &Candidate{
		Wire: w, H: h, Pre: pre, pin: pin,
		deviceAdds: map[model.ID]*DeviceAddOp{}, revokedDevices: idSet{}, retiredDevices: idSet{},
		puts: map[model.ID]*ItemPutOp{}, deletes: map[model.ID]*ItemDeleteOp{},
		grantAdds: map[model.ID]*GrantAddOp{}, grantByRecord: map[model.ID]*GrantAddOp{},
		bundlePuts: map[model.ID]*BundlePutOp{}, revokedGrants: idSet{},
		deploys: map[model.ID]*DeployOp{},
		aead:    map[crypto.Hash]crypto.AEADEnvelope{}, hpke: map[crypto.Hash]crypto.HPKEEnvelope{},
	}
	if pre != nil {
		// Equivocation and staleness come first: they are about the log,
		// not about this entry's contents.
		if err := checkSeqAgainst(pre.Head, e.Seq, h); err != nil {
			return nil, err
		}
	}
	if err := c.collect(); err != nil {
		return nil, err
	}
	if err := c.checkHeader(); err != nil {
		return nil, err
	}
	accountID, err := c.accountID()
	if err != nil {
		return nil, err
	}
	if err := c.checkSigs(accountID); err != nil {
		return nil, err
	}
	if err := c.apply(accountID); err != nil {
		return nil, err
	}
	if err := c.checkPublicInvariants(); err != nil {
		return nil, err
	}
	if !withObjects {
		return c, nil
	}
	if err := c.fetchObjects(objs); err != nil {
		return nil, err
	}
	return c, nil
}

// checkSeqAgainst applies §5.6 against the verified head.
func checkSeqAgainst(head Head, seq uint64, h crypto.Hash) error {
	switch {
	case seq == head.Seq && h.Equal(head.H):
		return ErrAlreadyApplied
	case seq == head.Seq:
		return &EquivocationError{Seq: seq, Have: head.H, Got: h}
	case seq < head.Seq:
		return ErrStale
	}
	return nil
}

// CheckHeld compares an entry with the H the client holds for the same
// seq (§5.6). It returns an *EquivocationError if they differ.
func CheckHeld(seq uint64, have crypto.Hash, e *Entry) error {
	if e.Seq != seq {
		return nil
	}
	h, err := e.Hash()
	if err != nil {
		return err
	}
	if !h.Equal(have) {
		return &EquivocationError{Seq: seq, Have: have, Got: h}
	}
	return nil
}

// opNames lists the (category, id) pairs an op names for the
// within-entry uniqueness rule of §5.2. Only each op's subject ID counts
// (rev 10 item 1): item_put/item_delete item_id, device_add cert.device_id,
// device_revoke and device_retire device_id, grant_add/bundle_put/grant_revoke grant_id,
// deploy_op op_id, and the IDs in the retired lists. References such as
// record_item_id, key_item_id or host_item_id don't.
type namedID struct {
	cat string
	id  model.ID
}

func opNames(o Op) []namedID {
	switch o := o.(type) {
	case *DeviceAddOp:
		return []namedID{{"device", o.Cert.DeviceID}}
	case *DeviceRevokeOp:
		return []namedID{{"device", o.DeviceID}}
	case *DeviceRetireOp:
		return []namedID{{"device", o.DeviceID}}
	case *ItemPutOp:
		return []namedID{{"item", o.ItemID}}
	case *ItemDeleteOp:
		return []namedID{{"item", o.ItemID}}
	case *GrantAddOp:
		return []namedID{{"grant", o.GrantID}}
	case *BundlePutOp:
		return []namedID{{"grant", o.GrantID}}
	case *GrantRevokeOp:
		return []namedID{{"grant", o.GrantID}}
	case *DeployOp:
		return []namedID{{"op", o.OpID}}
	case *RetiredOp:
		var out []namedID
		for _, id := range o.ItemIDs {
			out = append(out, namedID{"item", id})
		}
		for _, id := range o.DeviceIDs {
			out = append(out, namedID{"device", id})
		}
		for _, id := range o.GrantIDs {
			out = append(out, namedID{"grant", id})
		}
		return out
	}
	return nil
}

// collect checks the §5.2 "Allowed in" column, the within-entry ID
// uniqueness rule and the per-kind op counts, and indexes the ops.
func (c *Candidate) collect() error {
	e := &c.Wire.Entry
	seen := map[namedID][]Op{}
	count := map[string]int{}
	for _, o := range e.Ops {
		if !opAllowed(o.Name(), e.Kind) {
			return fail(RuleOpKind, "%s is not allowed in a %s entry", o.Name(), e.Kind)
		}
		count[o.Name()]++
		for _, n := range opNames(o) {
			seen[n] = append(seen[n], o)
		}
	}
	for n, ops := range seen {
		if len(ops) == 1 {
			continue
		}
		if len(ops) == 2 && dupAllowed(ops[0], ops[1], e.Kind) {
			continue
		}
		return fail(RuleOpDupID, "%d ops name %s %v", len(ops), n.cat, n.id)
	}
	// Genesis and every checkpoint carry exactly one history op (rev 12).
	if (e.Kind == KindGenesis || e.Kind == KindCheckpoint) && count[OpHistory] != 1 {
		return fail(RuleHistoryCount, "%s holds %d history ops, want exactly 1", e.Kind, count[OpHistory])
	}
	switch e.Kind {
	case KindGenesis:
		if count[OpAccountKeys] != 1 || count[OpCreds] != 1 || count[OpDeviceAdd] != 1 || count[OpVKWrap] != 1 || len(e.Ops) != 5 {
			return fail(RuleGenesis, "genesis must hold exactly account_keys, creds, one device_add, vk_wrap and history")
		}
	case KindBootstrap:
		if count[OpDeviceAdd] != 1 || len(e.Ops) != 1 {
			return fail(RuleBootstrap, "bootstrap must hold exactly one device_add")
		}
	case KindNormal:
		// A device can retire only itself, with an entry that does
		// nothing else (rev 16). checkSigs then requires the author, and
		// so the retired device, to be active in the pre-state.
		if count[OpDeviceRetire] > 0 {
			if len(e.Ops) != 1 {
				return fail(RuleRetireContents, "device_retire must be the entry's only op, the entry holds %d", len(e.Ops))
			}
			if r := e.Ops[0].(*DeviceRetireOp); r.DeviceID != e.Author {
				return fail(RuleRetireSelf, "device_retire names %v, the author is %v", r.DeviceID, e.Author)
			}
		}
	case KindCheckpoint:
		for _, n := range []string{OpAccountKeys, OpCreds, OpVKWrap, OpRetired} {
			if count[n] != 1 {
				return fail(RuleCheckpointOps, "checkpoint holds %d %s ops, want exactly 1", count[n], n)
			}
		}
	}
	for _, o := range e.Ops {
		switch o := o.(type) {
		case *AccountKeysOp:
			c.accountKeys = o
		case *CredsOp:
			c.creds = o
		case *VKWrapOp:
			c.vkWrap = o
		case *RetiredOp:
			c.retired = o
		case *HistoryOp:
			c.history = o
		case *DeviceAddOp:
			c.deviceAdds[o.Cert.DeviceID] = o
		case *DeviceRevokeOp:
			c.revokedDevices[o.DeviceID] = true
		case *DeviceRetireOp:
			c.retiredDevices[o.DeviceID] = true
		case *ItemPutOp:
			c.puts[o.ItemID] = o
		case *ItemDeleteOp:
			c.deletes[o.ItemID] = o
		case *GrantAddOp:
			c.grantAdds[o.GrantID] = o
			c.grantByRecord[o.RecordItemID] = o
		case *BundlePutOp:
			c.bundlePuts[o.GrantID] = o
		case *GrantRevokeOp:
			c.revokedGrants[o.GrantID] = true
		case *DeployOp:
			c.deploys[o.OpID] = o
		}
	}
	return nil
}

// dupAllowed is the §5.2 exception list: a grant_add and its bundle_put
// share a grant_id, and a checkpoint's retired lists may repeat IDs revoked
// in the same entry.
func dupAllowed(a, b Op, k Kind) bool {
	is := func(x, y string) bool {
		return a.Name() == x && b.Name() == y || a.Name() == y && b.Name() == x
	}
	switch {
	case is(OpGrantAdd, OpBundlePut):
		return true
	case k == KindCheckpoint && is(OpRetired, OpDeviceRevoke):
		return true
	case k == KindCheckpoint && is(OpRetired, OpGrantRevoke):
		return true
	}
	return false
}

// checkHeader applies the §5.3 header rules.
func (c *Candidate) checkHeader() error {
	e := &c.Wire.Entry
	pre := c.Pre
	if e.Kind == KindGenesis {
		if pre != nil || e.Seq != 0 || !e.Prev.IsZero() || e.AKV != 1 || e.KV != 1 {
			return fail(RuleGenesisHdr, "genesis needs seq 0, prev \"\", akv = kv = 1 and no prior state")
		}
		return nil
	}
	if e.Seq == 0 {
		return fail(RuleSeq, "only genesis has seq 0")
	}
	if e.Prev.IsZero() {
		return fail(RulePrev, "prev is empty")
	}
	if pre != nil {
		if e.VaultID != pre.VaultID {
			return fail(RuleVault, "entry is for vault %v, state is %v", e.VaultID, pre.VaultID)
		}
		if e.Seq != pre.Head.Seq+1 {
			return fail(RuleSeq, "seq %d, want %d", e.Seq, pre.Head.Seq+1)
		}
		if !e.Prev.Equal(pre.Head.H) {
			return fail(RulePrev, "prev does not name the verified head")
		}
	}
	switch e.Kind {
	case KindNormal, KindBootstrap:
		if pre != nil && (e.AKV != pre.Account.AKV || e.KV != pre.KV) {
			return fail(RuleVersions, "%s entry has akv/kv %d/%d, state has %d/%d", e.Kind, e.AKV, e.KV, pre.Account.AKV, pre.KV)
		}
	case KindCheckpoint:
		if e.AKV != c.accountKeys.AKV || e.KV != c.vkWrap.KV {
			return fail(RuleVersions, "checkpoint header akv/kv %d/%d differ from account_keys.akv/vk_wrap.kv %d/%d",
				e.AKV, e.KV, c.accountKeys.AKV, c.vkWrap.KV)
		}
	}
	return nil
}

// accountID returns the account the entry belongs to: the verified
// state's, the pinned one at an anchor, or for a server's genesis the
// account its certificate names (the common invariants then check that
// every certificate and vk_wrap agree).
func (c *Candidate) accountID() (model.ID, error) {
	switch {
	case c.Pre != nil:
		return c.Pre.Account.AccountID, nil
	case c.pin != nil:
		return c.pin.AccountID, nil
	}
	for _, d := range c.deviceAdds {
		return d.Cert.AccountID, nil
	}
	return model.ID{}, fail(RuleGenesis, "genesis has no device_add")
}

// requiredRoles is the signature set for each kind (§5.3). wire.sigs
// carries exactly these roles, with no extras and no duplicates (rev 10
// item 2).
func requiredRoles(k Kind) []Role {
	switch k {
	case KindGenesis, KindBootstrap:
		return []Role{RoleAccount}
	case KindNormal:
		return []Role{RoleDevice}
	case KindCheckpoint:
		return []Role{RoleDevice, RoleAccountOld, RoleAccountNew}
	}
	return nil
}

func (c *Candidate) checkSigs(accountID model.ID) error {
	e := &c.Wire.Entry
	sigs := map[Role][]byte{}
	for _, s := range c.Wire.Sigs {
		if _, dup := sigs[s.Role]; dup {
			return fail(RuleSigRoles, "two %s signatures", s.Role)
		}
		sigs[s.Role] = s.Sig
	}
	want := requiredRoles(e.Kind)
	if len(sigs) != len(want) {
		return fail(RuleSigRoles, "%s entry carries %d signatures, want %v", e.Kind, len(sigs), want)
	}
	for _, r := range want {
		if _, ok := sigs[r]; !ok {
			return fail(RuleSigRoles, "%s entry lacks the %s signature", e.Kind, r)
		}
	}
	verify := func(r Rule, pk []byte, sig []byte) error {
		if err := crypto.Verify(ed25519.PublicKey(pk), crypto.LabelLogEntry, e, sig); err != nil {
			return failErr(r, err, "signature does not verify")
		}
		return nil
	}
	pre := c.Pre
	switch e.Kind {
	case KindGenesis:
		if e.Author != accountID {
			return fail(RuleAuthor, "genesis author must be the account ID")
		}
		if c.pin != nil {
			if err := c.checkPin(); err != nil {
				return err
			}
		}
		return verify(RuleSigAccount, c.accountKeys.SigPK, sigs[RoleAccount])
	case KindBootstrap:
		if e.Author != accountID {
			return fail(RuleAuthor, "bootstrap author must be the account ID")
		}
		return verify(RuleSigAccount, pre.Account.SigPK, sigs[RoleAccount])
	case KindNormal:
		d, ok := pre.Devices[e.Author]
		if !ok {
			return fail(RuleAuthorState, "author %v is not an active device", e.Author)
		}
		if d.Cert.AKV != pre.Account.AKV {
			return fail(RuleAuthorState, "author certificate akv %d, state akv %d", d.Cert.AKV, pre.Account.AKV)
		}
		return verify(RuleSigDevice, d.SigPK, sigs[RoleDevice])
	case KindCheckpoint:
		if pre != nil {
			d, ok := pre.Devices[e.Author]
			if !ok {
				return fail(RuleAuthorState, "author %v is not an active device", e.Author)
			}
			if d.Cert.AKV != pre.Account.AKV {
				return fail(RuleAuthorState, "author certificate akv %d, state akv %d", d.Cert.AKV, pre.Account.AKV)
			}
			if err := verify(RuleSigDevice, d.SigPK, sigs[RoleDevice]); err != nil {
				return err
			}
			if err := verify(RuleSigAcctOld, pre.Account.SigPK, sigs[RoleAccountOld]); err != nil {
				return err
			}
		} else {
			if err := c.checkPin(); err != nil {
				return err
			}
			// account_old can't be checked at an anchor. The device
			// signature is verified against the author's own device_add
			// in the entry (rev 10 item 7).
			d, ok := c.deviceAdds[e.Author]
			if !ok {
				return fail(RuleDeviceCover, "the authoring device does not survive the checkpoint")
			}
			if err := verify(RuleSigDevice, d.SigPK, sigs[RoleDevice]); err != nil {
				return err
			}
		}
		return verify(RuleSigAcctNew, c.accountKeys.SigPK, sigs[RoleAccountNew])
	}
	return fail(RuleSchema, "kind %q", e.Kind)
}

// checkPin requires account_keys to match the pinned account (§5.5 anchor
// step 2).
func (c *Candidate) checkPin() error {
	ak := c.accountKeys
	p := c.pin
	if ak.AKV != p.AKV || !crypto.FpKEM(ak.KEMPK).Equal(p.FpKEM) || !crypto.FpSig(ak.SigPK).Equal(p.FpSig) {
		return fail(RuleAnchorPin, "account_keys do not match the pinned account")
	}
	return nil
}

// apply builds the candidate post-state, checking the per-op rules of §5.3
// against the pre-state.
func (c *Candidate) apply(accountID model.ID) error {
	e := &c.Wire.Entry
	pre := c.Pre
	anchor := pre == nil
	var post *State
	if anchor {
		post = emptyState()
	} else {
		post = pre.clone()
	}
	post.VaultID = e.VaultID
	post.Head = Head{Seq: e.Seq, H: c.H}
	if c.accountKeys != nil {
		// checkHistory, below, ties the history to the pre-state and to
		// account_keys.
		post.History = c.history.History()
		post.Account = accountFromOp(accountID, c.accountKeys)
		post.KV = c.vkWrap.KV
		post.Creds = *c.creds
		post.Creds.Salt = append([]byte(nil), c.creds.Salt...)
		post.VKWrap = *c.vkWrap
	}
	used := idSet{}
	if !anchor {
		for id := range pre.allIDs() {
			used[id] = true
		}
	}
	// addNew enforces "IDs are never reused" (§5.3) for transitions. At an
	// anchor, uniqueness is checked over the whole snapshot afterwards.
	addNew := func(id model.ID, what string) error {
		if anchor {
			return nil
		}
		if used[id] {
			return fail(RuleUniqueID, "%s %v is live or retired already", what, id)
		}
		used[id] = true
		return nil
	}
	checkpoint := e.Kind == KindCheckpoint

	// Devices.
	for id := range c.revokedDevices {
		if !anchor {
			if _, ok := pre.Devices[id]; !ok {
				return fail(RuleDeviceCover, "device_revoke names %v, which is not active", id)
			}
		}
		delete(post.Devices, id)
	}
	// device_retire removes its author from the active set (rev 16).
	// checkSigs has already required the author to be active; this repeats
	// it for the op itself.
	for id := range c.retiredDevices {
		if !anchor {
			if _, ok := pre.Devices[id]; !ok {
				return fail(RuleAuthorState, "device_retire names %v, which is not active", id)
			}
		}
		delete(post.Devices, id)
	}
	for id, d := range c.deviceAdds {
		if d.Cert.AKV != e.AKV {
			return fail(RuleCertAKV, "certificate of %v has akv %d, entry akv is %d", id, d.Cert.AKV, e.AKV)
		}
		// At a checkpoint anchor the pre-state certificates are unknown,
		// so only issued_at = the entry's time can be checked (rev 10
		// item 13).
		if checkpoint && anchor && d.Cert.IssuedAt != e.Time {
			return fail(RuleSurvivorCert, "surviving device %v: certificate issued_at is not the entry time", id)
		}
		if checkpoint && !anchor {
			old, ok := pre.Devices[id]
			if !ok {
				return fail(RuleDeviceCover, "checkpoint adds %v, which is not an active device", id)
			}
			if !bytes.Equal(old.KEMPK, d.KEMPK) || !bytes.Equal(old.SigPK, d.SigPK) {
				return fail(RuleSurvivorKeys, "surviving device %v changes its public keys", id)
			}
			// The new certificate keeps name and enroll_transcript, and
			// issued_at is the entry's time (rev 10 item 13).
			if d.Cert.Name != old.Cert.Name || d.Cert.EnrollTranscript != old.Cert.EnrollTranscript || d.Cert.IssuedAt != e.Time {
				return fail(RuleSurvivorCert, "surviving device %v: certificate changes name or enroll_transcript, or issued_at is not the entry time", id)
			}
		} else if err := addNew(id, "device"); err != nil {
			return err
		}
		// Bootstrap requires enroll_transcript = "". A device_add in a
		// normal entry comes only from enrollment and needs a non-empty
		// one (rev 10 item 14).
		if e.Kind == KindBootstrap && !d.Cert.EnrollTranscript.IsZero() {
			return fail(RuleBootstrap, "bootstrap certificate must have enroll_transcript \"\"")
		}
		if e.Kind == KindNormal && d.Cert.EnrollTranscript.IsZero() {
			return fail(RuleEnrollTranscript, "certificate of %v has no enroll_transcript", id)
		}
		post.Devices[id] = *d
	}

	// Grants revoked before items, so a record deletion sees them.
	for g := range c.revokedGrants {
		if !anchor {
			if _, ok := pre.Grants[g]; !ok {
				return fail(RuleGrantActive, "grant_revoke names %v, which is not active", g)
			}
		}
		delete(post.Grants, g)
	}

	// Items.
	newRetiredItems := idSet{}
	for id, d := range c.deletes {
		old, ok := pre.Items[id]
		if !ok {
			return fail(RuleItemLive, "item_delete names %v, which is not live", id)
		}
		if d.ItemVersion != old.ItemVersion+1 {
			return fail(RuleItemVersion, "item_delete of %v has version %d, want %d", id, d.ItemVersion, old.ItemVersion+1)
		}
		delete(post.Items, id)
		newRetiredItems[id] = true
	}
	for id, p := range c.puts {
		if anchor {
			if p.ItemVersion == 0 || p.IV == 0 {
				return fail(RuleItemVersion, "item %v has version %d, iv %d", id, p.ItemVersion, p.IV)
			}
		} else if old, ok := pre.Items[id]; ok {
			if p.Type != old.Type {
				return fail(RuleItemType, "item_put of %v changes type %q to %q", id, old.Type, p.Type)
			}
			if p.ItemVersion != old.ItemVersion+1 {
				return fail(RuleItemVersion, "item_put of %v has version %d, want %d", id, p.ItemVersion, old.ItemVersion+1)
			}
			wantIV := old.IV
			if checkpoint {
				wantIV = old.IV + 1
			}
			if p.IV != wantIV {
				return fail(RuleItemIV, "item_put of %v has iv %d, want %d", id, p.IV, wantIV)
			}
		} else {
			if err := addNew(id, "item"); err != nil {
				return err
			}
			// A checkpoint can't create items: every item_put names a
			// pre-state live item (rev 10 item 5).
			if checkpoint {
				return fail(RuleCheckpointItems, "checkpoint creates item %v", id)
			}
			if p.ItemVersion != 1 {
				return fail(RuleItemVersion, "new item %v has version %d, want 1", id, p.ItemVersion)
			}
			if p.IV != 1 {
				return fail(RuleItemIV, "new item %v has iv %d, want 1", id, p.IV)
			}
			// "a new record matches its accompanying grant_add" (§5.5).
			if p.Type == model.TypeGrant {
				if _, ok := c.grantByRecord[id]; !ok {
					return fail(RuleGrantNewRecord, "new grant record %v has no grant_add", id)
				}
			}
		}
		post.Items[id] = ItemState{
			Type: p.Type, ItemVersion: p.ItemVersion, IV: p.IV, KV: p.KV,
			BodySHA256: p.BodySHA256, WrapSHA256: p.WrapSHA256,
		}
	}

	// Grant adds and bundles.
	for g, a := range c.grantAdds {
		if err := addNew(g, "grant"); err != nil {
			return err
		}
		rp, ok := c.puts[a.RecordItemID]
		if !ok || rp.Type != model.TypeGrant || rp.ItemVersion != 1 {
			return fail(RuleGrantAdd, "grant_add %v has no item_put (type grant, version 1) for its record", g)
		}
		if _, ok := c.bundlePuts[g]; !ok {
			return fail(RuleGrantAdd, "grant_add %v has no bundle_put", g)
		}
		post.Grants[g] = GrantState{
			RecordItemID: a.RecordItemID, TokenKEMPK: append([]byte(nil), a.TokenKEMPK...), ExpiresAt: a.ExpiresAt,
		}
	}
	for g, b := range c.bundlePuts {
		gs, ok := post.Grants[g]
		if !ok {
			return fail(RuleGrantActive, "bundle_put for %v, which is not active in the post-state", g)
		}
		if b.BundleVersion != gs.BundleVersion+1 {
			return fail(RuleBundleVersion, "bundle_put for %v has version %d, want %d", g, b.BundleVersion, gs.BundleVersion+1)
		}
		gs.BundleVersion = b.BundleVersion
		gs.EnvelopeSHA256 = b.EnvelopeSHA256
		post.Grants[g] = gs
	}

	// Deploy ops.
	for id, d := range c.deploys {
		n := d.normalized()
		if old, ok := pre.deployOp(id); ok {
			if checkpoint {
				if !sameJCS(&old, &n) {
					return fail(RuleCheckpointDeploy, "checkpoint changes deploy_op %v", id)
				}
			} else if err := checkDeployUpdate(&old, &n); err != nil {
				return err
			}
		} else {
			if err := addNew(id, "deploy_op"); err != nil {
				return err
			}
			// A checkpoint can't create deploy_ops: it only repeats
			// pre-state ops (rev 10 item 6).
			if checkpoint && !anchor {
				return fail(RuleCheckpointDeploy, "checkpoint creates deploy_op %v", id)
			}
			// A new op's key_item_version is the key item's current
			// version (rev 10 item 10). At an anchor every op is a
			// repeat, not a creation.
			if !anchor {
				k, ok := post.Items[d.KeyItemID]
				if !ok || k.Type != model.TypeKey {
					return fail(RuleDeployRefs, "new deploy_op %v names %v, which is not a live key", id, d.KeyItemID)
				}
				if d.KeyItemVersion != k.ItemVersion {
					return fail(RuleDeployKeyVersion, "new deploy_op %v has key_item_version %d, key %v is at %d",
						id, d.KeyItemVersion, d.KeyItemID, k.ItemVersion)
				}
			}
		}
		post.DeployOps[id] = n
	}

	// Retired sets.
	if checkpoint {
		if err := c.checkRetired(); err != nil {
			return err
		}
		post.Retired = Retired{
			ItemIDs:   append([]model.ID{}, c.retired.ItemIDs...),
			DeviceIDs: append([]model.ID{}, c.retired.DeviceIDs...),
			GrantIDs:  append([]model.ID{}, c.retired.GrantIDs...),
		}
	} else if !anchor {
		post.Retired = Retired{
			ItemIDs:   unionSorted(pre.Retired.ItemIDs, newRetiredItems),
			DeviceIDs: unionSorted(pre.Retired.DeviceIDs, c.retiredDevices),
			GrantIDs:  unionSorted(pre.Retired.GrantIDs, c.revokedGrants),
		}
	}

	if checkpoint && !anchor {
		if err := c.checkCheckpointCoverage(); err != nil {
			return err
		}
	}
	if e.Kind == KindGenesis {
		if c.accountKeys.AKV != 1 || c.creds.Gen != 1 || c.vkWrap.KV != 1 {
			return fail(RuleGenesis, "genesis needs account_keys.akv = 1, creds.gen = 1 and vk_wrap.kv = 1")
		}
	}
	if c.history != nil {
		if err := c.checkHistory(); err != nil {
			return err
		}
	}
	c.Post = post
	return nil
}

// checkHistory applies the public history rules of rev 12 to a genesis or
// checkpoint. Both lists run through the entry's akv and kv, and the last
// account row matches account_keys (and, at an anchor, the pinned
// fingerprints). A transition's history is the pre-state history plus
// exactly one account row and one VK row. The new account fingerprints
// differ from every earlier row; at a transition the earlier rows are the
// pre-state's, so the check reaches back past any anchor. The VK rows need
// the plaintext stage.
func (c *Candidate) checkHistory() error {
	e := &c.Wire.Entry
	h := c.history
	if len(h.Accounts) != int(e.AKV) || len(h.VKCommits) != int(e.KV) {
		return fail(RuleHistoryRows, "history runs to akv %d and kv %d, the entry has akv %d and kv %d",
			len(h.Accounts), len(h.VKCommits), e.AKV, e.KV)
	}
	last := h.Accounts[len(h.Accounts)-1]
	if p := c.pin; p != nil && (last.AKV != p.AKV || !last.FpKEM.Equal(p.FpKEM) || !last.FpSig.Equal(p.FpSig)) {
		return fail(RuleAnchorPin, "the last history account row does not match the pinned account")
	}
	ak := c.accountKeys
	if last.AKV != ak.AKV || !last.FpKEM.Equal(crypto.FpKEM(ak.KEMPK)) || !last.FpSig.Equal(crypto.FpSig(ak.SigPK)) {
		return fail(RuleHistoryAccount, "the last history account row does not match account_keys")
	}
	if pre := c.Pre; pre != nil {
		ph := &pre.History
		if len(h.Accounts) != len(ph.Accounts)+1 || len(h.VKCommits) != len(ph.VKCommits)+1 ||
			!slices.Equal(h.Accounts[:len(ph.Accounts)], ph.Accounts) || !slices.Equal(h.VKCommits[:len(ph.VKCommits)], ph.VKCommits) {
			return fail(RuleHistoryExtend, "history is not the pre-state history plus one account row and one VK row")
		}
	}
	// Every row against every earlier row, not only the last: an anchor
	// imports rows no transition on this client checked (rev 13).
	for i := 1; i < len(h.Accounts); i++ {
		r := h.Accounts[i]
		if err := checkFreshAccount(h.Accounts[:i], r.FpKEM, r.FpSig); err != nil {
			return err
		}
	}
	return nil
}

func (s *State) deployOp(id model.ID) (DeployOp, bool) {
	if s == nil {
		return DeployOp{}, false
	}
	o, ok := s.DeployOps[id]
	return o, ok
}

func unionSorted(base []model.ID, add idSet) []model.ID {
	s := setOf(base)
	for id := range add {
		s[id] = true
	}
	return s.sorted()
}

func sameJCS(a, b any) bool {
	x, err1 := canonjson.Marshal(a)
	y, err2 := canonjson.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// checkDeployUpdate applies §10.3 to an update of an existing op: action,
// ssh_pk_fp, key_item_id, key_item_version and the set of target hosts are
// immutable, and done and abandoned never change.
func checkDeployUpdate(old, n *DeployOp) error {
	if old.Action != n.Action || old.SSHPKFp != n.SSHPKFp || old.KeyItemID != n.KeyItemID || old.KeyItemVersion != n.KeyItemVersion {
		return fail(RuleDeployImmutable, "deploy_op %v changes an immutable field", n.OpID)
	}
	om, nm := old.targetMap(), n.targetMap()
	if len(om) != len(nm) {
		return fail(RuleDeployImmutable, "deploy_op %v changes its target hosts", n.OpID)
	}
	for h, st := range om {
		ns, ok := nm[h]
		if !ok {
			return fail(RuleDeployImmutable, "deploy_op %v changes its target hosts", n.OpID)
		}
		if (st == TargetDone || st == TargetAbandoned) && ns != st {
			return fail(RuleDeployState, "deploy_op %v target %v leaves the terminal state %q", n.OpID, h, st)
		}
	}
	return nil
}

// checkRetired: retired = the pre-state retired sets ∪ every item deleted,
// device revoked, device retired (rev 16) and grant revoked since then,
// including this entry (§5.3). The verified state's Retired is already
// cumulative: every normal entry adds its deletions, grant revocations and
// retirement to it, so the pre-state sets hold everything since the last
// checkpoint. At an anchor the pre-state is unknown; the entry's own
// revocations must still be listed.
func (c *Candidate) checkRetired() error {
	r := c.retired
	if c.Pre == nil {
		got := setOf(r.DeviceIDs)
		for id := range c.revokedDevices {
			if !got[id] {
				return fail(RuleCheckpointRetired, "revoked device %v is not in retired", id)
			}
		}
		got = setOf(r.GrantIDs)
		for id := range c.revokedGrants {
			if !got[id] {
				return fail(RuleCheckpointRetired, "revoked grant %v is not in retired", id)
			}
		}
		return nil
	}
	pre := c.Pre.Retired
	wantDevices := setOf(pre.DeviceIDs)
	for id := range c.revokedDevices {
		wantDevices[id] = true
	}
	wantGrants := setOf(pre.GrantIDs)
	for id := range c.revokedGrants {
		wantGrants[id] = true
	}
	if !setOf(r.ItemIDs).equal(setOf(pre.ItemIDs)) {
		return fail(RuleCheckpointRetired, "retired.item_ids differ from the retired items")
	}
	if !setOf(r.DeviceIDs).equal(wantDevices) {
		return fail(RuleCheckpointRetired, "retired.device_ids differ from the retired devices")
	}
	if !setOf(r.GrantIDs).equal(wantGrants) {
		return fail(RuleCheckpointRetired, "retired.grant_ids differ from the retired grants")
	}
	return nil
}

// checkCheckpointCoverage applies the pre-state checkpoint rules of §5.3.
func (c *Candidate) checkCheckpointCoverage() error {
	pre := c.Pre
	e := &c.Wire.Entry
	if c.accountKeys.AKV != pre.Account.AKV+1 {
		return fail(RuleCheckpointAKV, "account_keys.akv %d, want %d", c.accountKeys.AKV, pre.Account.AKV+1)
	}
	// The new account keys differ from every earlier account key (rev 11).
	// Otherwise a revoked device holding an old acct_priv could read later
	// writes. checkHistory compares them with every earlier history row.
	if c.creds.Gen != pre.Creds.Gen+1 {
		return fail(RuleCheckpointGen, "creds.gen %d, want %d", c.creds.Gen, pre.Creds.Gen+1)
	}
	if c.vkWrap.KV != pre.KV+1 {
		return fail(RuleCheckpointKV, "vk_wrap.kv %d, want %d", c.vkWrap.KV, pre.KV+1)
	}
	for id := range pre.Devices {
		_, survives := c.deviceAdds[id]
		if survives == c.revokedDevices[id] {
			return fail(RuleDeviceCover, "device %v must be either recertified or revoked", id)
		}
	}
	if _, ok := c.deviceAdds[e.Author]; !ok {
		return fail(RuleDeviceCover, "the authoring device does not survive the checkpoint")
	}
	for id := range pre.Items {
		if _, ok := c.puts[id]; !ok {
			return fail(RuleCheckpointItems, "checkpoint does not re-put live item %v", id)
		}
	}
	for g := range pre.Grants {
		if !c.revokedGrants[g] {
			return fail(RuleCheckpointGrants, "checkpoint does not revoke active grant %v", g)
		}
	}
	for id := range pre.DeployOps {
		if _, ok := c.deploys[id]; !ok {
			return fail(RuleCheckpointDeploy, "checkpoint drops deploy_op %v", id)
		}
	}
	return nil
}

// checkPublicInvariants applies the common snapshot invariants of §5.5
// that need no plaintext, on the candidate post-state.
func (c *Candidate) checkPublicInvariants() error {
	e := &c.Wire.Entry
	s := c.Post
	if e.AKV != s.Account.AKV || e.KV != s.KV {
		return fail(RuleVersions, "header akv/kv %d/%d, state %d/%d", e.AKV, e.KV, s.Account.AKV, s.KV)
	}
	return checkStateInvariants(s, c.Pre == nil)
}

// checkStateInvariants is the public half of the common snapshot
// invariants (§5.5), on a whole state.
func checkStateInvariants(s *State, anchor bool) error {
	acct := s.Account
	for id, d := range s.Devices {
		if d.Cert.DeviceID != id || d.Cert.AccountID != acct.AccountID || d.Cert.AKV != acct.AKV {
			return fail(RuleSnapCert, "certificate of %v names a different account, device or akv", id)
		}
		if err := crypto.VerifyCert(ed25519.PublicKey(acct.SigPK), &d.Cert, d.CertSig); err != nil {
			return failErr(RuleSnapCert, err, "certificate of %v", id)
		}
		if err := crypto.CheckCertKeys(&d.Cert, d.KEMPK, d.SigPK); err != nil {
			return failErr(RuleSnapCert, err, "device_add of %v", id)
		}
	}
	for id, it := range s.Items {
		if it.KV != s.KV {
			return fail(RuleSnapKV, "item %v has kv %d, current kv is %d", id, it.KV, s.KV)
		}
	}
	if s.VKWrap.Recipient != acct.AccountID {
		return fail(RuleSnapRecipient, "vk_wrap addresses %v, not the account", s.VKWrap.Recipient)
	}
	for id, n := range s.allIDs() {
		if n > 1 {
			return fail(RuleSnapDisjoint, "ID %v occurs %d times across the live sets and retired", id, n)
		}
	}
	for g, gs := range s.Grants {
		if it, ok := s.Items[gs.RecordItemID]; !ok || it.Type != model.TypeGrant {
			return fail(RuleGrantRecordDelete, "active grant %v has no live grant record %v", g, gs.RecordItemID)
		}
	}
	if anchor && len(s.Grants) != 0 {
		return fail(RuleAnchorGrants, "an anchor has active grants")
	}
	for id, o := range s.DeployOps {
		if o.Closed() {
			continue
		}
		if it, ok := s.Items[o.KeyItemID]; !ok || it.Type != model.TypeKey {
			return fail(RuleDeployRefs, "incomplete deploy_op %v names %v, which is not a live key", id, o.KeyItemID)
		}
		for _, t := range o.Targets {
			if it, ok := s.Items[t.HostItemID]; !ok || it.Type != model.TypeHost {
				return fail(RuleDeployRefs, "incomplete deploy_op %v names %v, which is not a live host", id, t.HostItemID)
			}
		}
	}
	return nil
}

// fetchObjects fetches every object the entry names and checks its digest.
// Objects in wire.objects come first; objs supplies the rest.
func (c *Candidate) fetchObjects(objs ObjectFetcher) error {
	wireObjs, err := WireObjects(c.Wire)
	if err != nil {
		return err
	}
	f := chainFetcher{wireObjs, objs}
	wantAEAD := func(h crypto.Hash) error {
		env, err := fetchAEAD(f, h)
		c.aead[h] = env
		return err
	}
	wantHPKE := func(h crypto.Hash) error {
		env, err := fetchHPKE(f, h)
		c.hpke[h] = env
		return err
	}
	for _, o := range c.Wire.Entry.Ops {
		var err error
		switch o := o.(type) {
		case *CredsOp:
			if err = wantAEAD(o.PwBlobSHA256); err == nil {
				err = wantAEAD(o.RkBlobSHA256)
			}
		case *VKWrapOp:
			err = wantHPKE(o.EnvelopeSHA256)
		case *DeviceAddOp:
			err = wantHPKE(o.UnlockSHA256)
		case *ItemPutOp:
			if err = wantAEAD(o.WrapSHA256); err == nil {
				err = wantAEAD(o.BodySHA256)
			}
		case *BundlePutOp:
			err = wantHPKE(o.EnvelopeSHA256)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// chainFetcher looks in the wire's objects, then in a caller's fetcher.
type chainFetcher struct {
	wire ObjectMap
	next ObjectFetcher
}

func (f chainFetcher) FetchObject(h crypto.Hash) ([]byte, error) {
	if b, ok := f.wire[h]; ok {
		return b, nil
	}
	if f.next == nil {
		return nil, ErrNoObject
	}
	return f.next.FetchObject(h)
}

var errWrongSecrets = errors.New("vaultlog: secrets do not belong to the verified state")
