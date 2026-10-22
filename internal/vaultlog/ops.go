package vaultlog

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"slices"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// Op names (§5.2).
const (
	OpAccountKeys  = "account_keys"
	OpCreds        = "creds"
	OpVKWrap       = "vk_wrap"
	OpDeviceAdd    = "device_add"
	OpDeviceRevoke = "device_revoke"
	OpItemPut      = "item_put"
	OpItemDelete   = "item_delete"
	OpRetired      = "retired"
	OpGrantAdd     = "grant_add"
	OpBundlePut    = "bundle_put"
	OpGrantRevoke  = "grant_revoke"
	OpDeploy       = "deploy_op"
)

// Op is one operation of an entry. The set is closed: only the types in
// this file implement it.
type Op interface {
	// Name returns the "op" member.
	Name() string
	validate() error
}

// AccountKeysOp is {op, akv:u32, kem_pk:b64, sig_pk:b64}.
type AccountKeysOp struct {
	Op    string `json:"op"`
	AKV   uint32 `json:"akv"`
	KEMPK []byte `json:"kem_pk"`
	SigPK []byte `json:"sig_pk"`
}

// CredsOp is {op, gen:u32, kdf_version:u32, salt:b64(16), auth_sha256:h,
// rauth_sha256:h, pw_blob_sha256:h, rk_blob_sha256:h}.
type CredsOp struct {
	Op           string      `json:"op"`
	Gen          uint32      `json:"gen"`
	KDFVersion   uint32      `json:"kdf_version"`
	Salt         []byte      `json:"salt"`
	AuthSHA256   crypto.Hash `json:"auth_sha256"`
	RAuthSHA256  crypto.Hash `json:"rauth_sha256"`
	PwBlobSHA256 crypto.Hash `json:"pw_blob_sha256"`
	RkBlobSHA256 crypto.Hash `json:"rk_blob_sha256"`
}

// VKWrapOp is {op, kv:u32, recipient:id, envelope_sha256:h}.
type VKWrapOp struct {
	Op             string      `json:"op"`
	KV             uint32      `json:"kv"`
	Recipient      model.ID    `json:"recipient"`
	EnvelopeSHA256 crypto.Hash `json:"envelope_sha256"`
}

// DeviceAddOp is {op, cert:Cert, cert_sig:b64, kem_pk:b64, sig_pk:b64,
// unlock_sha256:h}.
type DeviceAddOp struct {
	Op           string      `json:"op"`
	Cert         crypto.Cert `json:"cert"`
	CertSig      []byte      `json:"cert_sig"`
	KEMPK        []byte      `json:"kem_pk"`
	SigPK        []byte      `json:"sig_pk"`
	UnlockSHA256 crypto.Hash `json:"unlock_sha256"`
}

// DeviceRevokeOp is {op, device_id:id}.
type DeviceRevokeOp struct {
	Op       string   `json:"op"`
	DeviceID model.ID `json:"device_id"`
}

// ItemPutOp is {op, item_id:id, type, item_version:u64s, iv:u32, kv:u32,
// body_sha256:h, wrap_sha256:h}.
type ItemPutOp struct {
	Op          string      `json:"op"`
	ItemID      model.ID    `json:"item_id"`
	Type        model.Type  `json:"type"`
	ItemVersion uint64      `json:"item_version,string"`
	IV          uint32      `json:"iv"`
	KV          uint32      `json:"kv"`
	BodySHA256  crypto.Hash `json:"body_sha256"`
	WrapSHA256  crypto.Hash `json:"wrap_sha256"`
}

// ItemDeleteOp is {op, item_id:id, item_version:u64s}.
type ItemDeleteOp struct {
	Op          string   `json:"op"`
	ItemID      model.ID `json:"item_id"`
	ItemVersion uint64   `json:"item_version,string"`
}

// RetiredOp is {op, item_ids:[id], device_ids:[id], grant_ids:[id]}, each
// list sorted ascending with no duplicates.
type RetiredOp struct {
	Op        string     `json:"op"`
	ItemIDs   []model.ID `json:"item_ids"`
	DeviceIDs []model.ID `json:"device_ids"`
	GrantIDs  []model.ID `json:"grant_ids"`
}

// GrantAddOp is {op, grant_id:id, record_item_id:id, token_kem_pk:b64,
// tauth_sha256:h, expires_at:ts}.
type GrantAddOp struct {
	Op           string          `json:"op"`
	GrantID      model.ID        `json:"grant_id"`
	RecordItemID model.ID        `json:"record_item_id"`
	TokenKEMPK   []byte          `json:"token_kem_pk"`
	TAuthSHA256  crypto.Hash     `json:"tauth_sha256"`
	ExpiresAt    model.Timestamp `json:"expires_at"`
}

// BundlePutOp is {op, grant_id:id, bundle_version:u64s, envelope_sha256:h}.
type BundlePutOp struct {
	Op             string      `json:"op"`
	GrantID        model.ID    `json:"grant_id"`
	BundleVersion  uint64      `json:"bundle_version,string"`
	EnvelopeSHA256 crypto.Hash `json:"envelope_sha256"`
}

// GrantRevokeOp is {op, grant_id:id}.
type GrantRevokeOp struct {
	Op      string   `json:"op"`
	GrantID model.ID `json:"grant_id"`
}

// Deploy actions and target states (§5.2, §10.3).
const (
	ActionDeploy = "deploy"
	ActionRemove = "remove"

	TargetPending   = "pending"
	TargetDone      = "done"
	TargetFailed    = "failed"
	TargetAbandoned = "abandoned"
)

// Target is one {host_item_id:id, state} of a deploy_op.
type Target struct {
	HostItemID model.ID `json:"host_item_id"`
	State      string   `json:"state"`
}

// DeployOp is {op, op_id:id, action, ssh_pk_fp:str≤64, key_item_id:id,
// key_item_version:u64s, targets:[{host_item_id:id, state}]}.
type DeployOp struct {
	Op             string   `json:"op"`
	OpID           model.ID `json:"op_id"`
	Action         string   `json:"action"`
	SSHPKFp        string   `json:"ssh_pk_fp"`
	KeyItemID      model.ID `json:"key_item_id"`
	KeyItemVersion uint64   `json:"key_item_version,string"`
	Targets        []Target `json:"targets"`
}

func (*AccountKeysOp) Name() string  { return OpAccountKeys }
func (*CredsOp) Name() string        { return OpCreds }
func (*VKWrapOp) Name() string       { return OpVKWrap }
func (*DeviceAddOp) Name() string    { return OpDeviceAdd }
func (*DeviceRevokeOp) Name() string { return OpDeviceRevoke }
func (*ItemPutOp) Name() string      { return OpItemPut }
func (*ItemDeleteOp) Name() string   { return OpItemDelete }
func (*RetiredOp) Name() string      { return OpRetired }
func (*GrantAddOp) Name() string     { return OpGrantAdd }
func (*BundlePutOp) Name() string    { return OpBundlePut }
func (*GrantRevokeOp) Name() string  { return OpGrantRevoke }
func (*DeployOp) Name() string       { return OpDeploy }

func schemaFail(op, format string, args ...any) error {
	return fail(RuleSchema, "%s: %s", op, fmt.Sprintf(format, args...))
}

func checkOpName(o Op, got string) error {
	if got != o.Name() {
		return schemaFail(o.Name(), "op member is %q", got)
	}
	return nil
}

func checkID(op, field string, id model.ID) error {
	if id.IsZero() {
		return schemaFail(op, "%s is empty", field)
	}
	return nil
}

func checkTS(op, field string, t model.Timestamp) error {
	if _, err := t.MarshalText(); err != nil {
		return schemaFail(op, "%s: %v", field, err)
	}
	return nil
}

// checkKEMPK requires an X-Wing public key in the crypto/hpke encoding (§3).
func checkKEMPK(op, field string, pk []byte) error {
	if _, err := crypto.ParseKEMPublicKey(pk); err != nil {
		return schemaFail(op, "%s is not an X-Wing public key", field)
	}
	return nil
}

// checkSigPK requires 32 raw Ed25519 public key bytes (§3).
func checkSigPK(op, field string, pk []byte) error {
	if len(pk) != ed25519.PublicKeySize {
		return schemaFail(op, "%s is not a 32-byte Ed25519 public key", field)
	}
	return nil
}

func (o *AccountKeysOp) validate() error {
	if err := checkOpName(o, o.Op); err != nil {
		return err
	}
	if err := checkKEMPK(o.Op, "kem_pk", o.KEMPK); err != nil {
		return err
	}
	return checkSigPK(o.Op, "sig_pk", o.SigPK)
}

// Public returns the account public keys for accountID.
func (o *AccountKeysOp) Public(accountID model.ID) crypto.AccountPublic {
	return crypto.AccountPublic{AccountID: accountID, AKV: o.AKV, KEMPK: o.KEMPK, SigPK: ed25519.PublicKey(o.SigPK)}
}

// kdf_version MUST be 1 in suite 1 (rev 10 item 15).
func (o *CredsOp) validate() error {
	if err := checkOpName(o, o.Op); err != nil {
		return err
	}
	if o.KDFVersion != crypto.KDFv1.Version {
		return fail(RuleKDFVersion, "creds: kdf_version %d, want %d", o.KDFVersion, crypto.KDFv1.Version)
	}
	if len(o.Salt) != 16 {
		return schemaFail(o.Op, "salt is %d bytes, want 16", len(o.Salt))
	}
	return nil
}

func (o *VKWrapOp) validate() error {
	if err := checkOpName(o, o.Op); err != nil {
		return err
	}
	return checkID(o.Op, "recipient", o.Recipient)
}

func (o *DeviceAddOp) validate() error {
	if err := checkOpName(o, o.Op); err != nil {
		return err
	}
	if err := o.Cert.Validate(); err != nil {
		return failErr(RuleSchema, err, "device_add: cert")
	}
	if len(o.CertSig) != ed25519.SignatureSize {
		return schemaFail(o.Op, "cert_sig is not an Ed25519 signature")
	}
	if err := checkKEMPK(o.Op, "kem_pk", o.KEMPK); err != nil {
		return err
	}
	return checkSigPK(o.Op, "sig_pk", o.SigPK)
}

func (o *DeviceRevokeOp) validate() error {
	if err := checkOpName(o, o.Op); err != nil {
		return err
	}
	return checkID(o.Op, "device_id", o.DeviceID)
}

// isItemType reports whether t is one of the §5.2 item types.
func isItemType(t model.Type) bool {
	switch t {
	case model.TypeHost, model.TypeKey, model.TypeCredential, model.TypeSnippet, model.TypeGrant:
		return true
	}
	return false
}

func (o *ItemPutOp) validate() error {
	if err := checkOpName(o, o.Op); err != nil {
		return err
	}
	if err := checkID(o.Op, "item_id", o.ItemID); err != nil {
		return err
	}
	if !isItemType(o.Type) {
		return schemaFail(o.Op, "type %q", o.Type)
	}
	return nil
}

func (o *ItemDeleteOp) validate() error {
	if err := checkOpName(o, o.Op); err != nil {
		return err
	}
	return checkID(o.Op, "item_id", o.ItemID)
}

// checkSortedIDs requires a list sorted ascending with no duplicates and
// no empty IDs.
func checkSortedIDs(op, field string, ids []model.ID) error {
	for i, id := range ids {
		if err := checkID(op, field, id); err != nil {
			return err
		}
		if i > 0 && bytes.Compare(ids[i-1][:], id[:]) >= 0 {
			return schemaFail(op, "%s is not sorted ascending without duplicates", field)
		}
	}
	return nil
}

func (o *RetiredOp) validate() error {
	if err := checkOpName(o, o.Op); err != nil {
		return err
	}
	if err := checkSortedIDs(o.Op, "item_ids", o.ItemIDs); err != nil {
		return err
	}
	if err := checkSortedIDs(o.Op, "device_ids", o.DeviceIDs); err != nil {
		return err
	}
	return checkSortedIDs(o.Op, "grant_ids", o.GrantIDs)
}

func (o *GrantAddOp) validate() error {
	if err := checkOpName(o, o.Op); err != nil {
		return err
	}
	if err := checkID(o.Op, "grant_id", o.GrantID); err != nil {
		return err
	}
	if err := checkID(o.Op, "record_item_id", o.RecordItemID); err != nil {
		return err
	}
	if err := checkKEMPK(o.Op, "token_kem_pk", o.TokenKEMPK); err != nil {
		return err
	}
	return checkTS(o.Op, "expires_at", o.ExpiresAt)
}

func (o *BundlePutOp) validate() error {
	if err := checkOpName(o, o.Op); err != nil {
		return err
	}
	return checkID(o.Op, "grant_id", o.GrantID)
}

func (o *GrantRevokeOp) validate() error {
	if err := checkOpName(o, o.Op); err != nil {
		return err
	}
	return checkID(o.Op, "grant_id", o.GrantID)
}

func (o *DeployOp) validate() error {
	if err := checkOpName(o, o.Op); err != nil {
		return err
	}
	if err := checkID(o.Op, "op_id", o.OpID); err != nil {
		return err
	}
	if o.Action != ActionDeploy && o.Action != ActionRemove {
		return schemaFail(o.Op, "action %q", o.Action)
	}
	if err := crypto.CheckStr("ssh_pk_fp", o.SSHPKFp, 64); err != nil {
		return failErr(RuleSchema, err, "deploy_op")
	}
	if err := checkID(o.Op, "key_item_id", o.KeyItemID); err != nil {
		return err
	}
	// A deploy_op MUST have at least one target (rev 10 item 9).
	if len(o.Targets) == 0 {
		return fail(RuleDeployTargets, "deploy_op %v has no targets", o.OpID)
	}
	seen := make(map[model.ID]bool, len(o.Targets))
	for _, t := range o.Targets {
		if err := checkID(o.Op, "targets.host_item_id", t.HostItemID); err != nil {
			return err
		}
		switch t.State {
		case TargetPending, TargetDone, TargetFailed, TargetAbandoned:
		default:
			return schemaFail(o.Op, "target state %q", t.State)
		}
		// §10.3 calls the targets a set of hosts.
		if seen[t.HostItemID] {
			return schemaFail(o.Op, "target host %v listed twice", t.HostItemID)
		}
		seen[t.HostItemID] = true
	}
	return nil
}

// Closed reports whether every target is done or abandoned (§10.3). An op
// that is not closed is incomplete. A valid op has at least one target
// (rev 10 item 9).
func (o *DeployOp) Closed() bool {
	for _, t := range o.Targets {
		if t.State != TargetDone && t.State != TargetAbandoned {
			return false
		}
	}
	return true
}

// normalized returns a copy with targets sorted by host_item_id. Targets
// are a set (§10.3); state keeps them in one order so its serialization is
// deterministic.
func (o *DeployOp) normalized() DeployOp {
	c := *o
	c.Targets = slices.Clone(o.Targets)
	slices.SortFunc(c.Targets, func(a, b Target) int { return bytes.Compare(a.HostItemID[:], b.HostItemID[:]) })
	return c
}

func (o *DeployOp) targetMap() map[model.ID]string {
	m := make(map[model.ID]string, len(o.Targets))
	for _, t := range o.Targets {
		m[t.HostItemID] = t.State
	}
	return m
}

// parseOp decodes one op under its closed schema. Unknown ops are rejected.
func parseOp(raw []byte) (Op, error) {
	var peek map[string]canonjson.Raw
	if err := canonjson.Unmarshal(raw, &peek); err != nil {
		return nil, failErr(RuleSchema, err, "op is not an object")
	}
	nameRaw, ok := peek["op"]
	if !ok {
		return nil, fail(RuleSchema, "op has no op member")
	}
	var name string
	if err := canonjson.Unmarshal(nameRaw, &name); err != nil {
		return nil, failErr(RuleSchema, err, "op member is not a string")
	}
	var o Op
	switch name {
	case OpAccountKeys:
		o = new(AccountKeysOp)
	case OpCreds:
		o = new(CredsOp)
	case OpVKWrap:
		o = new(VKWrapOp)
	case OpDeviceAdd:
		o = new(DeviceAddOp)
	case OpDeviceRevoke:
		o = new(DeviceRevokeOp)
	case OpItemPut:
		o = new(ItemPutOp)
	case OpItemDelete:
		o = new(ItemDeleteOp)
	case OpRetired:
		o = new(RetiredOp)
	case OpGrantAdd:
		o = new(GrantAddOp)
	case OpBundlePut:
		o = new(BundlePutOp)
	case OpGrantRevoke:
		o = new(GrantRevokeOp)
	case OpDeploy:
		o = new(DeployOp)
	default:
		return nil, fail(RuleUnknownOp, "unknown op %q", name)
	}
	if err := canonjson.Unmarshal(raw, o); err != nil {
		return nil, failErr(RuleSchema, err, "%s", name)
	}
	if err := o.validate(); err != nil {
		return nil, err
	}
	return o, nil
}

// opAllowed is the "Allowed in" column of §5.2.
func opAllowed(name string, k Kind) bool {
	switch name {
	case OpAccountKeys, OpCreds, OpVKWrap:
		return k == KindGenesis || k == KindCheckpoint
	case OpDeviceAdd:
		return true
	case OpDeviceRevoke, OpRetired:
		return k == KindCheckpoint
	case OpItemPut, OpGrantRevoke, OpDeploy:
		return k == KindCheckpoint || k == KindNormal
	case OpItemDelete, OpGrantAdd, OpBundlePut:
		return k == KindNormal
	}
	return false
}
