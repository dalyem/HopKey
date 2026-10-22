package vaultlog

import (
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// NewID returns a random id (16 bytes from the OS CSPRNG).
func NewID() (model.ID, error) {
	var id model.ID
	for id.IsZero() {
		if _, err := rand.Read(id[:]); err != nil {
			return model.ID{}, err
		}
	}
	return id, nil
}

// DeviceInfo describes a device to certify: its ID, name and public keys.
// EnrollTranscript is SHA-256(T) for a device enrolled by approval (§7) and
// "" otherwise. A device added by a normal entry needs one (rev 10 item
// 14).
type DeviceInfo struct {
	ID               model.ID
	Name             string
	KEMPK            []byte
	SigPK            []byte
	EnrollTranscript crypto.OptHash
}

// CredsInput is the creds op's content (§5.2) and the two blobs it names.
// The caller derives them (§4.2); gen is set by the builder.
type CredsInput struct {
	KDFVersion  uint32
	Salt        []byte
	AuthSHA256  crypto.Hash
	RAuthSHA256 crypto.Hash
	PwBlob      crypto.AEADEnvelope
	RkBlob      crypto.AEADEnvelope
}

// builder accumulates an entry's ops and objects.
type builder struct {
	w    Wire
	seen map[crypto.Hash]bool
}

func newBuilder(e Entry) *builder {
	e.V, e.Suite = crypto.Version, crypto.Suite
	return &builder{w: Wire{Entry: e, Sigs: []Sig{}, Objects: []Object{}}, seen: map[crypto.Hash]bool{}}
}

func (b *builder) op(o Op) { b.w.Entry.Ops = append(b.w.Entry.Ops, o) }

// object adds an envelope to wire.objects and returns its digest.
func (b *builder) object(env any) (crypto.Hash, error) {
	body, err := canonjson.Marshal(env)
	if err != nil {
		return crypto.Hash{}, err
	}
	h, err := objectDigest(body)
	if err != nil {
		return crypto.Hash{}, err
	}
	if !b.seen[h] {
		b.seen[h] = true
		b.w.Objects = append(b.w.Objects, Object{SHA256: h, Body: body})
	}
	return h, nil
}

func (b *builder) sign(r Role, sig []byte, err error) error {
	if err != nil {
		return err
	}
	b.w.Sigs = append(b.w.Sigs, Sig{Role: r, Sig: sig})
	return nil
}

func (b *builder) signAccount(r Role, k *crypto.AccountKeys) error {
	sig, err := crypto.Sign(k.Sig, crypto.LabelLogEntry, &b.w.Entry)
	return b.sign(r, sig, err)
}

func (b *builder) signDevice(dev DeviceKey) error {
	sig, err := dev.SignEntry(&b.w.Entry)
	return b.sign(RoleDevice, sig, err)
}

// deviceAdd certifies a device under acct and seals its unlock blob.
func (b *builder) deviceAdd(acct *crypto.AccountKeys, d DeviceInfo, issuedAt model.Timestamp) error {
	cert := crypto.Cert{
		V: crypto.Version, AccountID: acct.AccountID, AKV: acct.AKV, DeviceID: d.ID, Name: d.Name,
		KEMFp: crypto.FpKEM(d.KEMPK), SigFp: crypto.FpSig(d.SigPK),
		EnrollTranscript: d.EnrollTranscript, IssuedAt: issuedAt,
	}
	sig, err := crypto.SignCert(acct, &cert)
	if err != nil {
		return err
	}
	unlock, err := crypto.SealUnlock(d.KEMPK, &cert, acct)
	if err != nil {
		return err
	}
	h, err := b.object(unlock)
	if err != nil {
		return err
	}
	b.op(&DeviceAddOp{
		Op: OpDeviceAdd, Cert: cert, CertSig: sig,
		KEMPK: slices.Clone(d.KEMPK), SigPK: slices.Clone(d.SigPK), UnlockSHA256: h,
	})
	return nil
}

func (b *builder) creds(gen uint32, c CredsInput) error {
	pw, err := b.object(c.PwBlob)
	if err != nil {
		return err
	}
	rk, err := b.object(c.RkBlob)
	if err != nil {
		return err
	}
	b.op(&CredsOp{
		Op: OpCreds, Gen: gen, KDFVersion: c.KDFVersion, Salt: slices.Clone(c.Salt),
		AuthSHA256: c.AuthSHA256, RAuthSHA256: c.RAuthSHA256, PwBlobSHA256: pw, RkBlobSHA256: rk,
	})
	return nil
}

func (b *builder) vkWrap(vaultID model.ID, acct *crypto.AccountKeys, kv uint32, vk *crypto.SymKey) error {
	pub := acct.Public()
	env, err := crypto.SealVK(pub.KEMPK, crypto.VKContext{VaultID: vaultID, AccountID: acct.AccountID, KV: kv, AKV: acct.AKV}, vk)
	if err != nil {
		return err
	}
	h, err := b.object(env)
	if err != nil {
		return err
	}
	b.op(&VKWrapOp{Op: OpVKWrap, KV: kv, Recipient: acct.AccountID, EnvelopeSHA256: h})
	return nil
}

// history adds the history op: prev plus one account row for acct and one
// VK row for vk (rev 12). Genesis passes an empty prev.
func (b *builder) history(prev History, acct *crypto.AccountKeys, vk *crypto.SymKey) {
	pin := acct.Pin()
	h := prev.clone()
	h.Accounts = append(h.Accounts, AccountRow{AKV: uint32(len(prev.Accounts) + 1), FpKEM: pin.FpKEM, FpSig: pin.FpSig})
	h.VKCommits = append(h.VKCommits, VKRow{KV: uint32(len(prev.VKCommits) + 1), Commit: crypto.VKCommit(vk)})
	b.op(&HistoryOp{Op: OpHistory, Accounts: h.Accounts, VKCommits: h.VKCommits})
}

func accountKeysOp(acct *crypto.AccountKeys) *AccountKeysOp {
	pub := acct.Public()
	return &AccountKeysOp{Op: OpAccountKeys, AKV: acct.AKV, KEMPK: pub.KEMPK, SigPK: slices.Clone([]byte(pub.SigPK))}
}

// itemPut seals a plaintext and adds the item_put. it must already carry
// the header for (version); ctx gives everything else.
func (b *builder) itemPut(vk, ik *crypto.SymKey, ctx crypto.ItemContext, it crypto.Item) error {
	wrap, err := crypto.WrapItemKey(vk, ctx, ik)
	if err != nil {
		return err
	}
	body, err := crypto.SealItem(ik, ctx, it)
	if err != nil {
		return itemErr(RuleSchema, err, "item %v", ctx.ItemID)
	}
	wh, err := b.object(wrap)
	if err != nil {
		return err
	}
	bh, err := b.object(body)
	if err != nil {
		return err
	}
	b.op(&ItemPutOp{
		Op: OpItemPut, ItemID: ctx.ItemID, Type: ctx.Type, ItemVersion: ctx.ItemVersion,
		IV: ctx.IV, KV: ctx.KV, BodySHA256: bh, WrapSHA256: wh,
	})
	return nil
}

// withHeader returns a shallow copy of it with header {v:1, item_id, type,
// item_version}.
func withHeader(it crypto.Item, version uint64) (crypto.Item, model.Header, error) {
	h, err := crypto.ItemHeader(it)
	if err != nil {
		return nil, model.Header{}, err
	}
	h.V, h.ItemVersion = crypto.Version, version
	switch v := it.(type) {
	case *model.Host:
		c := *v
		c.Header = h
		return &c, h, nil
	case *model.Key:
		c := *v
		c.Header = h
		return &c, h, nil
	case *model.Credential:
		c := *v
		c.Header = h
		return &c, h, nil
	case *model.Snippet:
		c := *v
		c.Header = h
		return &c, h, nil
	case *model.Grant:
		c := *v
		c.Header = h
		return &c, h, nil
	}
	return nil, model.Header{}, fmt.Errorf("vaultlog: %T is not an item plaintext", it)
}

// GenesisParams is everything signup supplies (§4.3).
type GenesisParams struct {
	VaultID model.ID
	Account *crypto.AccountKeys // akv 1
	VK      crypto.SymKey       // VK[1]
	Creds   CredsInput
	Device  DeviceInfo // the signing-up device
	Time    model.Timestamp
}

// BuildGenesis builds the genesis entry (§5.3), with the history op for
// akv 1 and kv 1 (rev 12), and verifies it with the anchor algorithm. It
// returns the wire to post and the verified state.
func BuildGenesis(p GenesisParams) (*Wire, *State, *Secrets, error) {
	acct := p.Account
	if acct == nil || acct.AKV != 1 {
		return nil, nil, nil, errors.New("vaultlog: genesis needs account keys with akv 1")
	}
	b := newBuilder(Entry{VaultID: p.VaultID, Seq: 0, Kind: KindGenesis, AKV: 1, KV: 1, Author: acct.AccountID, Time: p.Time})
	b.op(accountKeysOp(acct))
	if err := b.creds(1, p.Creds); err != nil {
		return nil, nil, nil, err
	}
	if err := b.deviceAdd(acct, p.Device, p.Time); err != nil {
		return nil, nil, nil, err
	}
	if err := b.vkWrap(p.VaultID, acct, 1, &p.VK); err != nil {
		return nil, nil, nil, err
	}
	b.history(History{}, acct, &p.VK)
	if err := b.signAccount(RoleAccount, acct); err != nil {
		return nil, nil, nil, err
	}
	s, sec, _, err := Anchor(acct.Pin(), acct, &b.w, nil, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vaultlog: built genesis fails verification: %w", err)
	}
	return &b.w, s, sec, nil
}

func nextEntry(pre *State, k Kind, author model.ID, t model.Timestamp) Entry {
	return Entry{
		VaultID: pre.VaultID, Seq: pre.Head.Seq + 1, Prev: crypto.SomeHash(pre.Head.H), Kind: k,
		AKV: pre.Account.AKV, KV: pre.KV, Author: author, Time: t,
	}
}

// BuildBootstrap builds a bootstrap entry that adds d (§4.4, §5.3), signed
// by the current account key, and verifies it as a transition of pre.
func BuildBootstrap(pre *State, sec *Secrets, d DeviceInfo, t model.Timestamp) (*Wire, *State, *Secrets, error) {
	if err := checkSecrets(pre, sec); err != nil {
		return nil, nil, nil, err
	}
	d.EnrollTranscript = crypto.OptHash{}
	b := newBuilder(nextEntry(pre, KindBootstrap, pre.Account.AccountID, t))
	if err := b.deviceAdd(sec.Account, d, t); err != nil {
		return nil, nil, nil, err
	}
	if err := b.signAccount(RoleAccount, sec.Account); err != nil {
		return nil, nil, nil, err
	}
	s, next, err := Transition(pre, sec, nil, &b.w, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vaultlog: built bootstrap fails verification: %w", err)
	}
	return &b.w, s, next, nil
}

// BuildRetire builds the device_retire entry by which dev removes itself
// (rev 16, §5.3): a normal entry, signed by dev, whose only op names dev.
// Nothing is rotated. It verifies the result as a transition of pre by dev;
// the returned State no longer lists dev as active.
func BuildRetire(pre *State, sec *Secrets, dev DeviceKey, t model.Timestamp) (*Wire, *State, *Secrets, error) {
	w, err := buildRetireWire(pre, sec, dev, t)
	if err != nil {
		return nil, nil, nil, err
	}
	s, next, err := Transition(pre, sec, dev, w, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vaultlog: built retirement fails verification: %w", err)
	}
	return w, s, next, nil
}

// buildRetireWire builds and signs a device_retire entry without verifying
// it.
func buildRetireWire(pre *State, sec *Secrets, dev DeviceKey, t model.Timestamp) (*Wire, error) {
	if err := checkSecrets(pre, sec); err != nil {
		return nil, err
	}
	b := newBuilder(nextEntry(pre, KindNormal, dev.DeviceID(), t))
	b.op(&DeviceRetireOp{Op: OpDeviceRetire, DeviceID: dev.DeviceID()})
	if err := b.signDevice(dev); err != nil {
		return nil, err
	}
	return &b.w, nil
}

// NewGrant is a grant to create (§8.1): the plaintext grant record (with
// its item_id, grant_id, token_kem_pk and expires_at set) and SHA-256(tAuth).
type NewGrant struct {
	Record      *model.Grant
	TAuthSHA256 crypto.Hash
}

// Changes is the content of a normal entry.
type Changes struct {
	// Put holds new or edited plaintexts. Each needs its item_id and type;
	// v and item_version are filled in. A zero ID is refused.
	Put []crypto.Item
	// Delete lists items to delete. Grant records that list a deleted item
	// are updated to drop it (§8.6) unless Put already holds them; other
	// references (host key_id and so on) are the caller's to clean up.
	Delete []model.ID
	// Grants to create; their records are put as new items.
	Grants []NewGrant
	// Revoke lists grants to revoke.
	Revoke []model.ID
	// Deploy holds new deploy_ops and updates of existing ones.
	Deploy []DeployOp
	// Devices to add by approval (§7).
	Devices []DeviceInfo
}

// BuildNormal builds a normal entry authored by dev, adds every bundle_put
// that §5.3 requires (rebuilding each bundle from the candidate post-state,
// §8.6), and verifies the result as a transition of pre. objs supplies
// objects the wire does not carry; it may be nil.
func BuildNormal(pre *State, sec *Secrets, dev DeviceKey, ch Changes, t model.Timestamp, objs ObjectFetcher) (*Wire, *State, *Secrets, error) {
	w, err := buildNormalWire(pre, sec, dev, ch, t)
	if err != nil {
		return nil, nil, nil, err
	}
	s, next, err := Transition(pre, sec, dev, w, objs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vaultlog: built entry fails verification: %w", err)
	}
	return w, s, next, nil
}

// buildNormalWire builds and signs a normal entry without verifying it.
func buildNormalWire(pre *State, sec *Secrets, dev DeviceKey, ch Changes, t model.Timestamp) (*Wire, error) {
	if err := checkSecrets(pre, sec); err != nil {
		return nil, err
	}
	b := newBuilder(nextEntry(pre, KindNormal, dev.DeviceID(), t))
	for _, d := range ch.Devices {
		if err := b.deviceAdd(sec.Account, d, t); err != nil {
			return nil, err
		}
	}

	puts := map[model.ID]crypto.Item{}
	for _, it := range ch.Put {
		h, err := crypto.ItemHeader(it)
		if err != nil {
			return nil, err
		}
		if h.ItemID.IsZero() {
			return nil, errors.New("vaultlog: item to put has no item_id")
		}
		puts[h.ItemID] = it
	}
	for _, g := range ch.Grants {
		puts[g.Record.ItemID] = g.Record
	}
	deleted := setOf(ch.Delete)
	// §8.6: deleting an item listed in a grant also updates the record.
	for _, id := range sortedKeys(sec.Items) {
		rec, ok := sec.Items[id].Item.(*model.Grant)
		if !ok || deleted[id] {
			continue
		}
		if _, explicit := puts[id]; explicit {
			continue
		}
		if cleaned, changed := dropFromRecord(rec, deleted); changed {
			puts[id] = cleaned
		}
	}

	// Candidate post-state plaintexts, for bundles.
	post := sec.Plaintexts()
	for id := range deleted {
		delete(post, id)
	}
	versions := map[model.ID]uint64{}
	for _, id := range sortedKeys(puts) {
		v := uint64(1)
		if old, ok := pre.Items[id]; ok {
			v = old.ItemVersion + 1
		}
		it, _, err := withHeader(puts[id], v)
		if err != nil {
			return nil, err
		}
		puts[id], post[id], versions[id] = it, it, v
	}

	for _, id := range sortedKeys(puts) {
		it := puts[id]
		h, _ := crypto.ItemHeader(it)
		iv := uint32(1)
		var ik crypto.SymKey
		if old, ok := pre.Items[id]; ok {
			iv, ik = old.IV, sec.Items[id].IK
		} else {
			var err error
			if ik, err = crypto.NewSymKey(); err != nil {
				return nil, err
			}
		}
		ctx := crypto.ItemContext{
			AccountID: pre.Account.AccountID, VaultID: pre.VaultID, ItemID: id, Type: h.Type,
			ItemVersion: versions[id], IV: iv, KV: pre.KV,
		}
		if err := b.itemPut(&sec.VK, &ik, ctx, it); err != nil {
			return nil, err
		}
	}
	for _, id := range ch.Delete {
		old, ok := pre.Items[id]
		if !ok {
			return nil, fmt.Errorf("vaultlog: item %v is not live", id)
		}
		b.op(&ItemDeleteOp{Op: OpItemDelete, ItemID: id, ItemVersion: old.ItemVersion + 1})
	}

	// Grants active in the post-state, and which of them need a bundle.
	revoked := setOf(ch.Revoke)
	active := map[model.ID]GrantState{}
	for g, gs := range pre.Grants {
		if !revoked[g] {
			active[g] = gs
		}
	}
	for _, g := range ch.Grants {
		r := g.Record
		b.op(&GrantAddOp{
			Op: OpGrantAdd, GrantID: r.GrantID, RecordItemID: r.ItemID,
			TokenKEMPK: slices.Clone(r.TokenKEMPK), TAuthSHA256: g.TAuthSHA256, ExpiresAt: r.ExpiresAt,
		})
		active[r.GrantID] = GrantState{RecordItemID: r.ItemID}
	}
	touched := func(id model.ID) bool {
		_, p := puts[id]
		return p || deleted[id]
	}
	for _, g := range sortedKeys(active) {
		gs := active[g]
		// Listed in the record before or after this entry (§5.3).
		need := touched(gs.RecordItemID)
		for _, it := range []crypto.Item{sec.Items[gs.RecordItemID].Item, post[gs.RecordItemID]} {
			if rec, ok := it.(*model.Grant); ok {
				for _, id := range rec.Items {
					need = need || touched(id)
				}
			}
		}
		if !need {
			continue
		}
		rec, ok := post[gs.RecordItemID].(*model.Grant)
		if !ok {
			return nil, fmt.Errorf("vaultlog: grant %v has no record", g)
		}
		version := gs.BundleVersion + 1
		bundle, err := crypto.BuildBundle(rec, post, pre.Account.AccountID, pre.Account.AKV, version)
		if err != nil {
			return nil, err
		}
		env, err := crypto.SealBundle(sec.Account, rec, bundle)
		if err != nil {
			return nil, err
		}
		h, err := b.object(env)
		if err != nil {
			return nil, err
		}
		b.op(&BundlePutOp{Op: OpBundlePut, GrantID: g, BundleVersion: version, EnvelopeSHA256: h})
	}
	for _, g := range ch.Revoke {
		b.op(&GrantRevokeOp{Op: OpGrantRevoke, GrantID: g})
	}
	for _, d := range ch.Deploy {
		d.Op = OpDeploy
		d.Targets = slices.Clone(d.Targets)
		b.op(&d)
	}
	if err := b.signDevice(dev); err != nil {
		return nil, err
	}
	return &b.w, nil
}

// dropFromRecord removes deleted items from a grant record's items,
// host_key_map and dedicated_key_id (§8.6). It reports whether anything
// changed.
func dropFromRecord(rec *model.Grant, deleted idSet) (*model.Grant, bool) {
	c := *rec
	changed := false
	c.Items = nil
	for _, id := range rec.Items {
		if deleted[id] {
			changed = true
			continue
		}
		c.Items = append(c.Items, id)
	}
	if c.Items == nil {
		c.Items = []model.ID{}
	}
	c.HostKeyMap = maps.Clone(rec.HostKeyMap)
	for h, k := range rec.HostKeyMap {
		if deleted[h] || deleted[k] {
			delete(c.HostKeyMap, h)
			changed = true
		}
	}
	if deleted[c.DedicatedKeyID] {
		c.DedicatedKeyID = model.ID{}
		changed = true
	}
	return &c, changed
}

// CheckpointParams are the fresh keys and choices of a checkpoint (§10.1).
// The caller generates and journals them before building.
type CheckpointParams struct {
	NewAccount *crypto.AccountKeys // akv = current akv + 1
	NewVK      crypto.SymKey       // VK[kv + 1]
	Creds      CredsInput          // under the new credentials; gen is set by the builder
	Revoke     []model.ID          // devices to revoke
	Time       model.Timestamp

	reuseIK bool // tests only: re-put items under their old IK
}

// BuildCheckpoint builds a checkpoint from the verified pre-state (§5.3,
// §10.1): new account keys, creds and VK; recertified survivors with new
// unlock blobs; every live item re-put under a fresh IK, iv + 1 and the new
// kv; every active grant revoked; every deploy_op repeated; the cumulative
// retired sets; and the history extended by one account row and one VK row
// (rev 12). dev is the authoring device and must survive.
// The result is verified as a transition of pre by dev. A survivor's new
// certificate keeps its name and enroll_transcript, and issued_at is the
// checkpoint time (rev 10 item 13).
func BuildCheckpoint(pre *State, sec *Secrets, dev DeviceKey, p CheckpointParams) (*Wire, *State, *Secrets, error) {
	na := p.NewAccount
	if na == nil || na.AccountID != pre.Account.AccountID || na.AKV != pre.Account.AKV+1 {
		return nil, nil, nil, errors.New("vaultlog: checkpoint needs new account keys for akv + 1")
	}
	// Keys and a VK that differ from every earlier one in the history
	// (rev 11, rev 12), checked before anything is built. The transition
	// below checks them again.
	pin := na.Pin()
	if err := checkFreshAccount(pre.History.Accounts, pin.FpKEM, pin.FpSig); err != nil {
		return nil, nil, nil, err
	}
	commit := crypto.VKCommit(&p.NewVK)
	for _, r := range pre.History.VKCommits {
		if commit.Equal(r.Commit) {
			return nil, nil, nil, fail(RuleCheckpointFreshVK, "the new VK equals VK[%d]", r.KV)
		}
	}
	w, err := buildCheckpointWire(pre, sec, dev, p)
	if err != nil {
		return nil, nil, nil, err
	}
	s, next, err := Transition(pre, sec, dev, w, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vaultlog: built checkpoint fails verification: %w", err)
	}
	return w, s, next, nil
}

// buildCheckpointWire builds and signs a checkpoint without verifying it.
func buildCheckpointWire(pre *State, sec *Secrets, dev DeviceKey, p CheckpointParams) (*Wire, error) {
	if err := checkSecrets(pre, sec); err != nil {
		return nil, err
	}
	na := p.NewAccount
	kv := pre.KV + 1
	e := nextEntry(pre, KindCheckpoint, dev.DeviceID(), p.Time)
	e.AKV, e.KV = na.AKV, kv
	b := newBuilder(e)
	b.op(accountKeysOp(na))
	if err := b.creds(pre.Creds.Gen+1, p.Creds); err != nil {
		return nil, err
	}
	if err := b.vkWrap(pre.VaultID, na, kv, &p.NewVK); err != nil {
		return nil, err
	}
	b.history(pre.History, na, &p.NewVK)
	revoke := setOf(p.Revoke)
	for _, id := range sortedKeys(pre.Devices) {
		d := pre.Devices[id]
		if revoke[id] {
			b.op(&DeviceRevokeOp{Op: OpDeviceRevoke, DeviceID: id})
			continue
		}
		info := DeviceInfo{ID: id, Name: d.Cert.Name, KEMPK: d.KEMPK, SigPK: d.SigPK, EnrollTranscript: d.Cert.EnrollTranscript}
		if err := b.deviceAdd(na, info, p.Time); err != nil {
			return nil, err
		}
	}
	for id := range revoke {
		if _, ok := pre.Devices[id]; !ok {
			return nil, fmt.Errorf("vaultlog: device %v is not active", id)
		}
	}
	for _, id := range sortedKeys(pre.Items) {
		st := pre.Items[id]
		it, _, err := withHeader(sec.Items[id].Item, st.ItemVersion+1)
		if err != nil {
			return nil, err
		}
		ik, err := crypto.NewSymKey()
		if err != nil {
			return nil, err
		}
		if p.reuseIK {
			ik = sec.Items[id].IK
		}
		ctx := crypto.ItemContext{
			AccountID: pre.Account.AccountID, VaultID: pre.VaultID, ItemID: id, Type: st.Type,
			ItemVersion: st.ItemVersion + 1, IV: st.IV + 1, KV: kv,
		}
		if err := b.itemPut(&p.NewVK, &ik, ctx, it); err != nil {
			return nil, err
		}
	}
	grants := setOf(pre.Retired.GrantIDs)
	for _, g := range sortedKeys(pre.Grants) {
		b.op(&GrantRevokeOp{Op: OpGrantRevoke, GrantID: g})
		grants[g] = true
	}
	for _, id := range sortedKeys(pre.DeployOps) {
		d := pre.DeployOps[id]
		d.Targets = slices.Clone(d.Targets)
		b.op(&d)
	}
	devices := setOf(pre.Retired.DeviceIDs)
	for id := range revoke {
		devices[id] = true
	}
	b.op(&RetiredOp{
		Op: OpRetired, ItemIDs: setOf(pre.Retired.ItemIDs).sorted(),
		DeviceIDs: devices.sorted(), GrantIDs: grants.sorted(),
	})
	if err := b.signDevice(dev); err != nil {
		return nil, err
	}
	if err := b.signAccount(RoleAccountOld, sec.Account); err != nil {
		return nil, err
	}
	if err := b.signAccount(RoleAccountNew, na); err != nil {
		return nil, err
	}
	return &b.w, nil
}
