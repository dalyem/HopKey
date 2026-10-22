package vaultlog

import (
	"errors"
	"fmt"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// Rule names one validation rule of §5 (or of §6, §8.7 and §10.3 where §5
// refers to them). Every rejection carries the rule that caused it, so a
// caller (and a test) can tell which check failed.
type Rule string

// Header and schema rules (§5.1, §5.2, §5.3 "Header rules").
const (
	RuleSchema      Rule = "schema"         // closed schemas of E, ops, sigs and objects
	RuleUnknownOp   Rule = "op.unknown"     // an op name outside §5.2
	RuleOpKind      Rule = "op.kind"        // an op not allowed in the entry's kind (§5.2 table)
	RuleOpDupID     Rule = "op.dup-id"      // two ops of one entry name the same ID (§5.2)
	RuleVault       Rule = "header.vault"   // vault_id differs from the verified state
	RuleSeq         Rule = "header.seq"     // seq is not pre-state seq + 1
	RulePrev        Rule = "header.prev"    // prev is not the pre-state H
	RuleGenesisHdr  Rule = "header.genesis" // genesis needs seq "0", prev "", akv = kv = 1
	RuleVersions    Rule = "header.versions"
	RuleAuthor      Rule = "header.author"
	RuleCertAKV     Rule = "cert.akv" // every certificate uses the entry's resulting akv
	RuleSigRoles    Rule = "sig.roles"
	RuleSigDevice   Rule = "sig.device"
	RuleSigAccount  Rule = "sig.account"
	RuleSigAcctOld  Rule = "sig.account_old"
	RuleSigAcctNew  Rule = "sig.account_new"
	RuleAuthorState Rule = "normal.author" // normal/checkpoint author must be an active device with the pre-state akv
)

// Per-kind content rules (§5.3).
const (
	RuleGenesis            Rule = "genesis.contents"
	RuleBootstrap          Rule = "bootstrap.contents"
	RuleCheckpointOps      Rule = "checkpoint.contents" // exactly one account_keys, creds, vk_wrap, retired
	RuleCheckpointAKV      Rule = "checkpoint.akv"
	RuleCheckpointGen      Rule = "checkpoint.gen"
	RuleCheckpointKV       Rule = "checkpoint.kv"
	RuleSurvivorKeys       Rule = "checkpoint.survivor-keys"
	RuleDeviceCover        Rule = "checkpoint.devices" // survivors ∪ revoked = pre-state active set, author survives
	RuleCheckpointItems    Rule = "checkpoint.items"
	RuleCheckpointGrants   Rule = "checkpoint.grants"
	RuleCheckpointDeploy   Rule = "checkpoint.deploy-ops"
	RuleCheckpointRetired  Rule = "checkpoint.retired"
	RuleCheckpointUnlock   Rule = "checkpoint.unlock" // the new unlock blob does not yield the authenticated account keys
	RuleUniqueID           Rule = "id.unique"         // an added ID is live or retired already
	RuleItemVersion        Rule = "item.version"
	RuleItemType           Rule = "item.type"
	RuleItemIV             Rule = "item.iv"
	RuleItemIK             Rule = "item.ik" // same IK for ordinary edits, a fresh one in a checkpoint
	RuleItemLive           Rule = "item.live"
	RuleGrantRecordDelete  Rule = "item.grant-delete" // a grant record is deleted before its grant_revoke
	RuleGrantAdd           Rule = "grant.add"
	RuleGrantNewRecord     Rule = "grant.new-record" // a new grant record without its grant_add
	RuleGrantActive        Rule = "grant.active"
	RuleBundleVersion      Rule = "grant.bundle-version"
	RuleBundleRequired     Rule = "grant.bundle-required"
	RuleGrantRecordMeta    Rule = "grant.record-meta"
	RuleGrantRecordBinding Rule = "grant.record-binding" // §8.7 rules on an active grant's record
	RuleDeployImmutable    Rule = "deploy.immutable"
	RuleDeployState        Rule = "deploy.state" // done and abandoned never change
	RuleDeployRefs         Rule = "deploy.refs"  // an incomplete op names a live key and live hosts
	RuleDeployFingerprint  Rule = "deploy.fingerprint"
	RuleDeployMaterial     Rule = "deploy.material" // a key's SSH material changes while an op is incomplete
	RuleRefIntegrity       Rule = "ref.integrity"
	RuleObjectMissing      Rule = "object.missing"
	RuleObjectDigest       Rule = "object.digest"
	RuleDecrypt            Rule = "object.decrypt"
)

// Common snapshot invariants (§5.5).
const (
	RuleSnapCert      Rule = "snapshot.cert"
	RuleSnapKV        Rule = "snapshot.kv"
	RuleSnapRecipient Rule = "snapshot.recipient"
	RuleSnapDisjoint  Rule = "snapshot.disjoint" // also "every ID is unique" at an anchor
)

// Anchor rules (§5.5 "Anchor algorithm").
const (
	RuleAnchorKind    Rule = "anchor.kind"
	RuleAnchorPin     Rule = "anchor.pin"
	RuleAnchorTrusted Rule = "anchor.trusted" // seq or H differs from the trusted anchor_seq/anchor_h
	RuleAnchorGrants  Rule = "anchor.grants"  // active grants, or a grant record naming no retired grant
)

// RuleError is a rejected entry. Any violation rejects the whole entry
// (§5.3), and the client stops syncing.
type RuleError struct {
	Rule Rule
	Msg  string
	Err  error // an underlying error, when there is one
}

func (e *RuleError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("vaultlog: %s: %s: %v", e.Rule, e.Msg, e.Err)
	}
	return fmt.Sprintf("vaultlog: %s: %s", e.Rule, e.Msg)
}

func (e *RuleError) Unwrap() error { return e.Err }

func fail(r Rule, format string, args ...any) error {
	return &RuleError{Rule: r, Msg: fmt.Sprintf(format, args...)}
}

func failErr(r Rule, err error, format string, args ...any) error {
	return &RuleError{Rule: r, Msg: fmt.Sprintf(format, args...), Err: err}
}

// RuleOf returns the rule of a *RuleError in err's chain, or "".
func RuleOf(err error) Rule {
	var re *RuleError
	if errors.As(err, &re) {
		return re.Rule
	}
	return ""
}

// EquivocationError means the client was shown an entry at a seq it
// already holds, with a different H (§5.6). The client stops and raises an
// alarm; hop status prints seq and the first 8 bytes of each H.
type EquivocationError struct {
	Seq  uint64
	Have crypto.Hash
	Got  crypto.Hash
}

func (e *EquivocationError) Error() string {
	return fmt.Sprintf("vaultlog: equivocation at seq %d: have %x, shown %x", e.Seq, e.Have[:8], e.Got[:8])
}

// RevokedError is the "revoked here" exit of the transition algorithm
// (§5.5): an authenticated checkpoint revokes this device. The caller
// records a terminal revocation, wipes its decrypted material, disables
// vault use and never accepts a standalone anchor afterwards. The new
// snapshot is not decrypted.
type RevokedError struct {
	DeviceID model.ID
	Head     Head // the revoking checkpoint
}

func (e *RevokedError) Error() string {
	return fmt.Sprintf("vaultlog: device %v is revoked by the checkpoint at seq %d", e.DeviceID, e.Head.Seq)
}

// ErrAlreadyApplied means the entry is the verified head itself (same seq,
// same H). It is not an error of the log; callers usually ignore it.
var ErrAlreadyApplied = errors.New("vaultlog: entry is already the verified head")

// ErrStale means the entry's seq is below the verified head. The caller
// compares it against the H it holds for that seq with CheckHeld.
var ErrStale = errors.New("vaultlog: entry is older than the verified head")
