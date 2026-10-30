package vaultlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// PlainItem is one decrypted live item: its item key and its verified
// plaintext.
type PlainItem struct {
	IK   crypto.SymKey
	Item crypto.Item
}

// Secrets is a full device's secret view of one verified State: the
// account keys for State.Account.AKV, VK[State.KV], and every live item's
// key and plaintext. The caller persists it encrypted under the device key,
// in the same durable commit as the State (§5.5, §11).
type Secrets struct {
	Account *crypto.AccountKeys
	VK      crypto.SymKey
	Items   map[model.ID]PlainItem
}

// Plaintexts returns the item plaintexts by ID.
func (s *Secrets) Plaintexts() map[model.ID]crypto.Item {
	out := make(map[model.ID]crypto.Item, len(s.Items))
	for id, p := range s.Items {
		out[id] = p.Item
	}
	return out
}

// DeviceKey is this client's device identity. Its private keys may live in
// an OS keychain, so it is an interface.
type DeviceKey interface {
	DeviceID() model.ID
	// OpenUnlock opens a device unlock blob addressed to this device
	// (crypto.OpenUnlock with the device KEM key).
	OpenUnlock(c *crypto.Cert, e crypto.HPKEEnvelope) (*crypto.AccountKeys, error)
	// SignEntry returns Sig(dev_sig, "hopkey/v1/log-entry", E).
	SignEntry(e *Entry) ([]byte, error)
}

// LocalDevice is a DeviceKey with its private keys in memory.
type LocalDevice struct {
	ID  model.ID
	KEM hpke.PrivateKey
	Sig ed25519.PrivateKey
}

func (d *LocalDevice) DeviceID() model.ID { return d.ID }

func (d *LocalDevice) OpenUnlock(c *crypto.Cert, e crypto.HPKEEnvelope) (*crypto.AccountKeys, error) {
	return crypto.OpenUnlock(d.KEM, c, e)
}

func (d *LocalDevice) SignEntry(e *Entry) ([]byte, error) {
	return crypto.Sign(d.Sig, crypto.LabelLogEntry, e)
}

// Transition is the transition algorithm of an existing client (§5.5):
//
//  1. Public stage (CheckPublic).
//  2. Revoked here: if an authenticated checkpoint revokes dev, it returns
//     a *RevokedError and decrypts nothing.
//  3. Plaintext stage, on temporary state (Candidate.CheckPlaintext).
//  4. The caller commits the returned State and Secrets in one durable
//     commit; only then are they usable.
//
// pre and sec are the verified state and its secrets. dev is this client's
// device; it must be active in pre. objs supplies objects the wire does not
// carry (for example a local cache); it may be nil.
func Transition(pre *State, sec *Secrets, dev DeviceKey, w *Wire, objs ObjectFetcher) (*State, *Secrets, error) {
	if pre == nil {
		return nil, nil, errors.New("vaultlog: a transition needs a verified state; use Anchor")
	}
	c, err := CheckPublic(pre, w, objs)
	if err != nil {
		return nil, nil, err
	}
	if dev != nil && c.Revokes(dev.DeviceID()) {
		return nil, nil, &RevokedError{DeviceID: dev.DeviceID(), Head: c.Post.Head}
	}
	return c.CheckPlaintext(sec, dev)
}

// CheckPlaintext is the plaintext stage of a transition (§5.5 step 3). For
// a checkpoint it opens dev's new unlock blob, requires the account keys it
// yields to equal the authenticated account_keys, and opens the VK
// envelope. For every kind it decrypts the affected items with the
// candidate keys and checks every plaintext-dependent rule and the common
// snapshot invariants. dev may be nil except for a checkpoint.
func (c *Candidate) CheckPlaintext(sec *Secrets, dev DeviceKey) (*State, *Secrets, error) {
	pre := c.Pre
	if pre == nil {
		return nil, nil, errors.New("vaultlog: CheckPlaintext is for transitions; use Anchor")
	}
	if err := checkSecrets(pre, sec); err != nil {
		return nil, nil, err
	}
	post := c.Post
	acct, vk := sec.Account, sec.VK
	if c.Kind() == KindCheckpoint {
		if dev == nil {
			return nil, nil, errors.New("vaultlog: crossing a checkpoint needs this device's keys")
		}
		if c.Revokes(dev.DeviceID()) {
			return nil, nil, &RevokedError{DeviceID: dev.DeviceID(), Head: post.Head}
		}
		d, ok := c.deviceAdds[dev.DeviceID()]
		if !ok {
			return nil, nil, fmt.Errorf("vaultlog: device %v is not in the checkpoint", dev.DeviceID())
		}
		k, err := dev.OpenUnlock(&d.Cert, c.hpke[d.UnlockSHA256])
		if err != nil {
			return nil, nil, failErr(RuleDecrypt, err, "this device's unlock blob")
		}
		if err := crypto.CheckUnlockKeys(k, c.accountKeys.Public(post.Account.AccountID)); err != nil {
			return nil, nil, failErr(RuleCheckpointUnlock, err, "unlock blob")
		}
		acct = k
		vk, err = openVK(post, k, c.hpke[post.VKWrap.EnvelopeSHA256])
		if err != nil {
			return nil, nil, err
		}
		// The pre-state VK matches its own history row, and the new VK
		// matches the new row and differs from every earlier VK (rev 11,
		// rev 12). Only the plaintext stage can see them.
		if !crypto.VKCommit(&sec.VK).Equal(pre.History.lastVK().Commit) {
			return nil, nil, fail(RuleHistoryVKCommit, "the pre-state VK does not match its history row")
		}
		if err := checkVKCommits(post.History.VKCommits, &vk); err != nil {
			return nil, nil, err
		}
	}
	items := maps.Clone(sec.Items)
	for id := range c.deletes {
		delete(items, id)
	}
	for _, id := range sortedKeys(c.puts) {
		p := c.puts[id]
		pi, err := c.openItem(post, vk, p)
		if err != nil {
			return nil, nil, err
		}
		if old, ok := sec.Items[id]; ok {
			// iv stays the same for ordinary edits (a new nonce under the
			// same IK) and increases with a fresh IK in a checkpoint (§5.3).
			same := old.IK == pi.IK
			if c.Kind() == KindCheckpoint && same {
				return nil, nil, fail(RuleItemIK, "checkpoint re-puts item %v under its old IK", id)
			}
			if c.Kind() != KindCheckpoint && !same {
				return nil, nil, fail(RuleItemIK, "edit of item %v changes its IK without a new iv", id)
			}
		}
		items[id] = pi
	}
	next := &Secrets{Account: acct, VK: vk, Items: items}
	if err := c.checkTransitionPlain(sec, next); err != nil {
		return nil, nil, err
	}
	if err := checkPlainSnapshot(post, next); err != nil {
		return nil, nil, err
	}
	return post, next, nil
}

// checkVKCommits requires vk to match the last row of rows and every row's
// commitment to differ from every other row's (rev 12, rev 13).
func checkVKCommits(rows []VKRow, vk *crypto.SymKey) error {
	commit := crypto.VKCommit(vk)
	last := rows[len(rows)-1]
	if !commit.Equal(last.Commit) {
		return fail(RuleHistoryVKCommit, "VK[%d] does not match its history row", last.KV)
	}
	// Pairwise over every row: an anchor imports rows no transition on
	// this client checked (rev 13).
	for i, a := range rows {
		for _, b := range rows[:i] {
			if a.Commit.Equal(b.Commit) {
				return fail(RuleCheckpointFreshVK, "VK[%d] reuses VK[%d]", a.KV, b.KV)
			}
		}
	}
	return nil
}

// checkSecrets requires sec to belong to the verified state.
func checkSecrets(s *State, sec *Secrets) error {
	if sec == nil || sec.Account == nil {
		return errWrongSecrets
	}
	if !sec.Account.Pin().Equal(s.Pin()) {
		return fmt.Errorf("%w: account keys", errWrongSecrets)
	}
	if len(sec.Items) != len(s.Items) {
		return fmt.Errorf("%w: item count", errWrongSecrets)
	}
	for id := range s.Items {
		if _, ok := sec.Items[id]; !ok {
			return fmt.Errorf("%w: item %v", errWrongSecrets, id)
		}
	}
	return nil
}

func openVK(s *State, acct *crypto.AccountKeys, env crypto.HPKEEnvelope) (crypto.SymKey, error) {
	ctx := crypto.VKContext{VaultID: s.VaultID, AccountID: s.Account.AccountID, KV: s.KV, AKV: s.Account.AKV}
	vk, err := crypto.OpenVK(acct, ctx, env)
	if err != nil {
		return crypto.SymKey{}, failErr(RuleDecrypt, err, "vault key envelope")
	}
	return vk, nil
}

func itemContext(s *State, p *ItemPutOp) crypto.ItemContext {
	return crypto.ItemContext{
		AccountID: s.Account.AccountID, VaultID: s.VaultID, ItemID: p.ItemID, Type: p.Type,
		ItemVersion: p.ItemVersion, IV: p.IV, KV: p.KV,
	}
}

// openItem unwraps an item's IK with VK and opens its body. Only objects
// the candidate state names are used (§5.5).
func (c *Candidate) openItem(s *State, vk crypto.SymKey, p *ItemPutOp) (PlainItem, error) {
	ctx := itemContext(s, p)
	ik, err := crypto.UnwrapItemKey(&vk, ctx, c.aead[p.WrapSHA256])
	if err != nil {
		return PlainItem{}, failErr(RuleDecrypt, err, "item key of %v", p.ItemID)
	}
	it, err := crypto.OpenItem(&ik, ctx, c.aead[p.BodySHA256])
	if err != nil {
		return PlainItem{}, itemErr(RuleDecrypt, err, "body of %v", p.ItemID)
	}
	return PlainItem{IK: ik, Item: it}, nil
}

func sortedKeys[V any](m map[model.ID]V) []model.ID {
	out := slices.Collect(maps.Keys(m))
	sortIDs(out)
	return out
}

// checkTransitionPlain applies the plaintext rules that compare against
// the pre-state: grant-record metadata, record deletion, frozen deploy key
// material and required bundle_puts (§5.3, §5.5, §8.7, §10.3).
func (c *Candidate) checkTransitionPlain(pre, next *Secrets) error {
	post := c.Post
	// Grant record metadata: a new record matches its grant_add; an
	// existing record's immutable fields equal the verified pre-state.
	for id, p := range c.puts {
		if p.Type != model.TypeGrant {
			continue
		}
		rec := next.Items[id].Item.(*model.Grant)
		if old, ok := pre.Items[id]; ok {
			o := old.Item.(*model.Grant)
			if rec.GrantID != o.GrantID || !bytes.Equal(rec.TokenKEMPK, o.TokenKEMPK) || rec.ExpiresAt != o.ExpiresAt {
				return fail(RuleGrantRecordMeta, "grant record %v changes grant_id, token_kem_pk or expires_at", id)
			}
		} else {
			a := c.grantByRecord[id]
			if a == nil || rec.GrantID != a.GrantID || !bytes.Equal(rec.TokenKEMPK, a.TokenKEMPK) || rec.ExpiresAt != a.ExpiresAt {
				return fail(RuleGrantRecordMeta, "grant record %v does not match its grant_add", id)
			}
		}
	}
	// An item of type grant can be deleted only once its grant has an
	// explicit grant_revoke in the log (§5.3). A grant_revoke in the same
	// entry counts (rev 10 item 16), so this checks the post-state.
	retiredGrants := setOf(post.Retired.GrantIDs)
	for id := range c.deletes {
		if rec, ok := pre.Items[id].Item.(*model.Grant); ok && !retiredGrants[rec.GrantID] {
			return fail(RuleGrantRecordDelete, "grant record %v deleted before grant %v is revoked", id, rec.GrantID)
		}
	}
	// While an op is incomplete, the key item's SSH material (key_type,
	// private_key and public_key, rev 10 item 8) MUST stay unchanged
	// (§10.3).
	for id, o := range c.allDeployOps() {
		if o.Closed() {
			continue
		}
		if _, put := c.puts[o.KeyItemID]; !put {
			continue
		}
		oldKey, ok := pre.Items[o.KeyItemID].Item.(*model.Key)
		if !ok {
			continue
		}
		newKey, ok := next.Items[o.KeyItemID].Item.(*model.Key)
		if !ok || !sameSSHMaterial(oldKey, newKey) {
			return fail(RuleDeployMaterial, "key %v changes its SSH material while deploy_op %v is incomplete", o.KeyItemID, id)
		}
	}
	// An item_put on an existing key item keeps key_type, private_key and
	// public_key, whether or not a deploy_op is pending: replacing an SSH
	// key always creates a new item ID (rev 11, §10.3). Metadata edits and
	// rewraps stay allowed. The check above names the pending op when
	// there is one.
	for _, id := range sortedKeys(c.puts) {
		oldKey, ok := pre.Items[id].Item.(*model.Key)
		if !ok {
			continue
		}
		newKey, ok := next.Items[id].Item.(*model.Key)
		if !ok || !sameSSHMaterial(oldKey, newKey) {
			return fail(RuleKeyMaterial, "item_put of key %v changes its SSH material; a new key needs a new item ID", id)
		}
	}
	// Access items: identity, targets, author, checkpoint and terminal
	// non-regression (crypto spec rev 17, Part 2, §5.1).
	for _, id := range sortedKeys(c.puts) {
		if c.puts[id].Type != model.TypeAccess {
			continue
		}
		a, ok := next.Items[id].Item.(*model.Access)
		if !ok {
			return fail(RuleItemType, "access item %v does not decode as one", id)
		}
		var old *model.Access
		if o, ok := pre.Items[id]; ok {
			if old, ok = o.Item.(*model.Access); !ok {
				return fail(RuleItemType, "item %v changes its type to access", id)
			}
		}
		if err := CheckAccessPut(old, a, c.Kind(), c.Wire.Entry.Author); err != nil {
			return err
		}
	}
	// Normal entries only: an entry that changes or deletes an item listed
	// in the record of a grant active in the post-state, or changes the
	// record itself, MUST contain a bundle_put for that grant (§5.3).
	if c.Kind() == KindNormal {
		changed := func(id model.ID) bool {
			_, p := c.puts[id]
			_, d := c.deletes[id]
			return p || d
		}
		for _, g := range sortedKeys(post.Grants) {
			gs := post.Grants[g]
			if _, ok := c.bundlePuts[g]; ok {
				continue
			}
			need := changed(gs.RecordItemID)
			// "Listed in the record": the pre-state record as well, so
			// that removing an item from the record and deleting it in
			// the same entry still needs a bundle.
			for _, s := range []*Secrets{pre, next} {
				if rec, ok := s.Items[gs.RecordItemID].Item.(*model.Grant); ok {
					for _, id := range rec.Items {
						need = need || changed(id)
					}
				}
			}
			if need {
				return fail(RuleBundleRequired, "entry changes grant %v without a bundle_put", g)
			}
		}
	}
	return nil
}

// sameSSHMaterial reports whether two key plaintexts have the same SSH
// material: key_type, private_key and public_key (rev 10 item 8).
func sameSSHMaterial(a, b *model.Key) bool {
	return a.KeyType == b.KeyType && a.PrivateKey == b.PrivateKey && a.PublicKey == b.PublicKey
}

// allDeployOps returns every op incomplete in the pre-state or the
// post-state, by op_id (post-state version when both exist).
func (c *Candidate) allDeployOps() map[model.ID]DeployOp {
	out := map[model.ID]DeployOp{}
	for id, o := range c.Pre.DeployOps {
		out[id] = o
	}
	for id, o := range c.Post.DeployOps {
		if pre, ok := out[id]; ok && !pre.Closed() {
			continue // keep the incomplete pre-state view
		}
		out[id] = o
	}
	return out
}

// checkPlainSnapshot is the plaintext half of the common snapshot
// invariants (§5.5): reference integrity, grant-record metadata of active
// grants, the §8.7 binding rules of active grants' records, and the key
// fingerprint of every incomplete deploy_op.
func checkPlainSnapshot(s *State, sec *Secrets) error {
	items := sec.Plaintexts()
	if len(items) != len(s.Items) {
		return errWrongSecrets
	}
	typeOf := func(id model.ID) model.Type {
		if st, ok := s.Items[id]; ok {
			return st.Type
		}
		return ""
	}
	ref := func(owner model.ID, field string, id model.ID, want ...model.Type) error {
		if id.IsZero() {
			return nil
		}
		if !slices.Contains(want, typeOf(id)) {
			return fail(RuleRefIntegrity, "%v.%s names %v, which is not a live %v", owner, field, id, want)
		}
		return nil
	}
	for _, id := range sortedKeys(items) {
		switch it := items[id].(type) {
		case *model.Host:
			if err := ref(id, "key_id", it.KeyID, model.TypeKey); err != nil {
				return err
			}
			if err := ref(id, "credential_id", it.CredentialID, model.TypeCredential); err != nil {
				return err
			}
			if err := ref(id, "jump_host_id", it.JumpHostID, model.TypeHost); err != nil {
				return err
			}
		case *model.Grant:
			for _, x := range it.Items {
				if x.IsZero() {
					return fail(RuleRefIntegrity, "%v.items holds an empty ID", id)
				}
				if err := ref(id, "items", x, model.TypeHost, model.TypeKey, model.TypeCredential, model.TypeSnippet); err != nil {
					return err
				}
			}
			for h, k := range it.HostKeyMap {
				if h.IsZero() || k.IsZero() {
					return fail(RuleRefIntegrity, "%v.host_key_map holds an empty ID", id)
				}
				if err := ref(id, "host_key_map", h, model.TypeHost); err != nil {
					return err
				}
				if err := ref(id, "host_key_map", k, model.TypeKey); err != nil {
					return err
				}
			}
			if err := ref(id, "dedicated_key_id", it.DedicatedKeyID, model.TypeKey); err != nil {
				return err
			}
		}
	}
	// Active grants: the record matches the grant's immutable metadata and
	// passes the §8.7 binding rules against the current plaintexts. §8.7
	// applies to active grants' records only; revoked grants' records need
	// reference integrity above (rev 10 item 12).
	for _, g := range sortedKeys(s.Grants) {
		gs := s.Grants[g]
		rec, ok := items[gs.RecordItemID].(*model.Grant)
		if !ok {
			return fail(RuleGrantRecordDelete, "active grant %v has no grant record", g)
		}
		if rec.GrantID != g || !bytes.Equal(rec.TokenKEMPK, gs.TokenKEMPK) || rec.ExpiresAt != gs.ExpiresAt {
			return fail(RuleGrantRecordMeta, "record of grant %v differs from its grant_add", g)
		}
		if err := crypto.CheckGrantRecord(rec, items); err != nil {
			return failErr(RuleGrantRecordBinding, err, "record of grant %v", g)
		}
	}
	for _, id := range sortedKeys(s.DeployOps) {
		o := s.DeployOps[id]
		if o.Closed() {
			continue
		}
		k, ok := items[o.KeyItemID].(*model.Key)
		if !ok {
			return fail(RuleDeployRefs, "incomplete deploy_op %v names %v, which is not a live key", id, o.KeyItemID)
		}
		fp, err := SSHFingerprint(k.PublicKey)
		if err != nil || fp != o.SSHPKFp {
			return fail(RuleDeployFingerprint, "key %v does not have fingerprint %s", o.KeyItemID, o.SSHPKFp)
		}
	}
	return nil
}

// SSHFingerprint returns ssh_pk_fp for an OpenSSH public-key line: "SHA256:"
// and the unpadded standard base64 of the SHA-256 of the public-key wire
// blob (§10.3). It is crypto.SSHFingerprint.
func SSHFingerprint(publicKey string) (string, error) { return crypto.SSHFingerprint(publicKey) }

// itemErr classifies an error from sealing or opening an item: a
// key.public_key or host.host_keys entry that is not an OpenSSH line
// (crypto.ValidateKey and crypto.ValidateHost, rev 10 item 11) is
// RuleSSHKeyLine, a key.private_key that fails rev 12 is
// RuleSSHPrivateKey, and anything else is r.
func itemErr(r Rule, err error, format string, args ...any) error {
	switch {
	case errors.Is(err, crypto.ErrSSHKeyLine):
		r = RuleSSHKeyLine
	case errors.Is(err, crypto.ErrSSHPrivateKey):
		r = RuleSSHPrivateKey
	}
	return failErr(r, err, format, args...)
}

// AnchorID is the anchor identity (account_id, vault_id, akv, fp_kem,
// fp_sig, H(E)) (§5.5).
type AnchorID struct {
	AccountID model.ID
	VaultID   model.ID
	AKV       uint32
	FpKEM     crypto.Hash
	FpSig     crypto.Hash
	H         crypto.Hash
}

// Anchor is the anchor algorithm of a fresh client (§5.5). pin is the
// pinned account (from acct_priv or the SAS) and acct the account keys the
// client holds for pin.AKV. w is the genesis or checkpoint entry whose
// account_keys.akv equals pin.AKV. trusted, when non-nil, is the
// (anchor_seq, anchor_h) enrollment supplies (§7); password and recovery
// logins pass nil.
//
// An initialized client MUST NOT call Anchor again: it may only advance
// through Transition.
func Anchor(pin crypto.AccountPin, acct *crypto.AccountKeys, w *Wire, objs ObjectFetcher, trusted *Head) (*State, *Secrets, AnchorID, error) {
	c, err := CheckAnchorPublic(pin, w, objs)
	if err != nil {
		return nil, nil, AnchorID{}, err
	}
	if trusted != nil && (trusted.Seq != c.Post.Head.Seq || !trusted.H.Equal(c.H)) {
		return nil, nil, AnchorID{}, fail(RuleAnchorTrusted, "anchor entry is not the trusted (anchor_seq, anchor_h)")
	}
	s, sec, err := c.anchorPlaintext(acct)
	if err != nil {
		return nil, nil, AnchorID{}, err
	}
	id := AnchorID{
		AccountID: s.Account.AccountID, VaultID: s.VaultID, AKV: s.Account.AKV,
		FpKEM: s.Account.FpKEM, FpSig: s.Account.FpSig, H: c.H,
	}
	return s, sec, id, nil
}

// CheckAnchorPublic is the public part of the anchor algorithm: closed
// schemas, kind, the account or account_new signature under the pinned
// key, the pinned fingerprints, snapshot consistency and object digests.
func CheckAnchorPublic(pin crypto.AccountPin, w *Wire, objs ObjectFetcher) (*Candidate, error) {
	k := w.Entry.Kind
	if k != KindGenesis && k != KindCheckpoint {
		return nil, fail(RuleAnchorKind, "an anchor is a genesis or checkpoint entry, not %s", k)
	}
	return checkPublic(nil, &pin, w, objs)
}

func (c *Candidate) anchorPlaintext(acct *crypto.AccountKeys) (*State, *Secrets, error) {
	s := c.Post
	if acct == nil || !acct.Pin().Equal(*c.pin) || !s.Pin().Equal(*c.pin) {
		return nil, nil, fail(RuleAnchorPin, "account keys do not match the pinned account")
	}
	vk, err := openVK(s, acct, c.hpke[s.VKWrap.EnvelopeSHA256])
	if err != nil {
		return nil, nil, err
	}
	// The VK matches the last commitment of the imported history (rev 12),
	// and, as a transition into this entry would have required, differs
	// from every earlier one.
	if err := checkVKCommits(s.History.VKCommits, &vk); err != nil {
		return nil, nil, err
	}
	sec := &Secrets{Account: acct, VK: vk, Items: map[model.ID]PlainItem{}}
	for _, id := range sortedKeys(c.puts) {
		pi, err := c.openItem(s, vk, c.puts[id])
		if err != nil {
			return nil, nil, err
		}
		sec.Items[id] = pi
	}
	// At a checkpoint anchor, every surviving grant record MUST name a
	// grant in retired.grant_ids (§5.5).
	retired := setOf(s.Retired.GrantIDs)
	for _, id := range sortedKeys(sec.Items) {
		if rec, ok := sec.Items[id].Item.(*model.Grant); ok && !retired[rec.GrantID] {
			return nil, nil, fail(RuleAnchorGrants, "grant record %v names grant %v, which is not retired", id, rec.GrantID)
		}
	}
	if err := checkPlainSnapshot(s, sec); err != nil {
		return nil, nil, err
	}
	return s, sec, nil
}

// OpenSecrets rebuilds the Secrets of a verified state from the objects it
// names: it opens dev's unlock blob, requires the account keys to match the
// pinned account (§6.2), then opens the VK envelope and every live item.
// Only digests named by s are used (§5.5). A store can therefore persist
// State and objects only, and reopen the vault with the device key.
func OpenSecrets(s *State, dev DeviceKey, objs ObjectFetcher) (*Secrets, error) {
	d, ok := s.Devices[dev.DeviceID()]
	if !ok {
		return nil, fmt.Errorf("vaultlog: device %v is not active", dev.DeviceID())
	}
	env, err := fetchHPKE(objs, d.UnlockSHA256)
	if err != nil {
		return nil, err
	}
	acct, err := dev.OpenUnlock(&d.Cert, env)
	if err != nil {
		return nil, failErr(RuleDecrypt, err, "unlock blob")
	}
	if err := crypto.CheckUnlockPin(acct, s.Pin()); err != nil {
		return nil, err
	}
	return OpenSecretsWithAccount(s, acct, objs)
}

// OpenSecretsWithAccount is OpenSecrets for a client that holds acct_priv
// directly (password or recovery login, before its bootstrap).
func OpenSecretsWithAccount(s *State, acct *crypto.AccountKeys, objs ObjectFetcher) (*Secrets, error) {
	if acct == nil || !acct.Pin().Equal(s.Pin()) {
		return nil, fmt.Errorf("%w: account keys", errWrongSecrets)
	}
	env, err := fetchHPKE(objs, s.VKWrap.EnvelopeSHA256)
	if err != nil {
		return nil, err
	}
	vk, err := openVK(s, acct, env)
	if err != nil {
		return nil, err
	}
	if !crypto.VKCommit(&vk).Equal(s.History.lastVK().Commit) {
		return nil, fail(RuleHistoryVKCommit, "VK[%d] does not match its history row", s.KV)
	}
	sec := &Secrets{Account: acct, VK: vk, Items: map[model.ID]PlainItem{}}
	for _, id := range sortedKeys(s.Items) {
		st := s.Items[id]
		p := &ItemPutOp{ItemID: id, Type: st.Type, ItemVersion: st.ItemVersion, IV: st.IV, KV: st.KV}
		ctx := itemContext(s, p)
		wrap, err := fetchAEAD(objs, st.WrapSHA256)
		if err != nil {
			return nil, err
		}
		body, err := fetchAEAD(objs, st.BodySHA256)
		if err != nil {
			return nil, err
		}
		ik, err := crypto.UnwrapItemKey(&vk, ctx, wrap)
		if err != nil {
			return nil, failErr(RuleDecrypt, err, "item key of %v", id)
		}
		it, err := crypto.OpenItem(&ik, ctx, body)
		if err != nil {
			return nil, itemErr(RuleDecrypt, err, "body of %v", id)
		}
		sec.Items[id] = PlainItem{IK: ik, Item: it}
	}
	if err := checkPlainSnapshot(s, sec); err != nil {
		return nil, err
	}
	return sec, nil
}

func fetchObject(objs ObjectFetcher, h crypto.Hash) ([]byte, error) {
	if objs == nil {
		return nil, fail(RuleObjectMissing, "object %v: no fetcher", h)
	}
	b, err := objs.FetchObject(h)
	if err != nil {
		return nil, failErr(RuleObjectMissing, err, "object %v", h)
	}
	return b, nil
}

func fetchAEAD(objs ObjectFetcher, h crypto.Hash) (crypto.AEADEnvelope, error) {
	b, err := fetchObject(objs, h)
	if err != nil {
		return crypto.AEADEnvelope{}, err
	}
	env, err := crypto.ParseAEADEnvelope(b)
	if err != nil {
		return crypto.AEADEnvelope{}, failErr(RuleObjectDigest, err, "object %v is not an AEAD envelope", h)
	}
	if d, err := env.Digest(); err != nil || !d.Equal(h) {
		return crypto.AEADEnvelope{}, fail(RuleObjectDigest, "object %v does not match its digest", h)
	}
	return env, nil
}

func fetchHPKE(objs ObjectFetcher, h crypto.Hash) (crypto.HPKEEnvelope, error) {
	b, err := fetchObject(objs, h)
	if err != nil {
		return crypto.HPKEEnvelope{}, err
	}
	env, err := crypto.ParseHPKEEnvelope(b)
	if err != nil {
		return crypto.HPKEEnvelope{}, failErr(RuleObjectDigest, err, "object %v is not an HPKE envelope", h)
	}
	if d, err := env.Digest(); err != nil || !d.Equal(h) {
		return crypto.HPKEEnvelope{}, fail(RuleObjectDigest, "object %v does not match its digest", h)
	}
	return env, nil
}
