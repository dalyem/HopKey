package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/tailscale"
)

// The control protocol is newline-delimited JSON over a Unix socket: the
// client writes one Request per line and reads one Response per line, in
// order. No response carries private key bytes.

// Ops.
const (
	OpStatus     = "status"
	OpList       = "list"
	OpResolve    = "resolve"
	OpTailscale  = "tailscale"
	OpPutHost    = "put_host"
	OpSetHostKey = "set_host_key"
	OpPutKey     = "put_key"
	OpPutSnippet = "put_snippet"
	OpDelete     = "delete"
	OpReload     = "reload"
	OpShutdown   = "shutdown"

	// Sync ops (sync.go). They need the encrypted store; sync.now,
	// sync.held, sync.resolve and devices.list need it unlocked too.
	OpSyncStatus  = "sync.status"
	OpSyncNow     = "sync.now"
	OpSyncHeld    = "sync.held"
	OpSyncResolve = "sync.resolve"
	OpDevicesList = "devices.list"
)

// Error codes.
const (
	CodeInvalid  = "invalid"   // the request was malformed or its content refused
	CodeNotFound = "not_found" // no such item
	CodeLocked   = "locked"    // the vault is locked
	CodeInternal = "internal"
	// CodeChanged refuses a conditional write: an item it depends on is
	// no longer at the version the caller named.
	CodeChanged = "changed"

	CodeLocalOnly    = "local_only"    // the vault has no server to sync with
	CodeRevoked      = "revoked"       // this device was revoked from the account
	CodeSyncHalted   = "sync_halted"   // sync stopped on an equivocation or a rule violation
	CodeUnreachable  = "unreachable"   // the server could not be reached, or is busy; it is retried
	CodeNotHeld      = "not_held"      // no held change, or not the one named
	CodeStillHeld    = "still_held"    // a retry found the change still held
	CodeStaleConfirm = "stale_confirm" // the confirmation token no longer matches the proposal
	CodeConfirm      = "confirm"       // keep-mine and edit need the proposal's confirmation token
	CodeOffline      = "offline"       // the account's max-offline policy locked the vault

	// CodeConfigStale refuses a resolve while the ssh config could not be
	// written from the vault: ssh would use the settings it had before.
	CodeConfigStale = "config_stale"
	// CodeConfigNotWritten is a partial success: the change (an unlock, a
	// put, a delete, a resolution, a reload) took effect and the agent
	// serves the vault's keys, but the ssh config could not be written. The
	// daemon retries. It is never an error response: the response is a
	// success, with the op's result (the saved host or key, say), and this
	// code in its Warning.
	CodeConfigNotWritten = "config_not_written"
)

// Request is one control call.
type Request struct {
	Op     string          `json:"op"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response answers one Request. A success can carry a Warning beside its
// Result: the change took effect, and something after it did not
// (CodeConfigNotWritten).
type Response struct {
	OK      bool            `json:"ok"`
	Error   *Error          `json:"error,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Warning *Error          `json:"warning,omitempty"`
}

// Error is a failed call.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

// IsCode reports whether err is a daemon Error with the given code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// ResolveParams is the request for OpResolve.
type ResolveParams struct {
	Target      string `json:"target"`
	Interactive bool   `json:"interactive"`
	// AgentOnly resolves among the hosts local agents may use (hop mcp):
	// a host with agent_access deny is left out, as if it were not in the
	// vault, so it is neither matched nor offered as a candidate.
	AgentOnly bool `json:"agent_only,omitempty"`
	// AgentTags narrows AgentOnly to the hosts that carry at least one of
	// these tags (hop mcp --tag): any other host is left out exactly as a
	// denied one is. Empty means no narrowing.
	AgentTags []string `json:"agent_tags,omitempty"`
}

// ResolveResult answers OpResolve.
type ResolveResult struct {
	Result *resolve.Result `json:"result"`
	// Host, Route and the ssh fields are set when Result matched a host.
	Host       *model.Host    `json:"host,omitempty"`
	Route      *resolve.Route `json:"route,omitempty"`
	RouteError string         `json:"route_error,omitempty"`
	// RouteHint says how to route a host over Tailscale when its address
	// names a tailnet node the host is not linked to (resolve.SuggestLink).
	// It is never set for agent_only resolution.
	RouteHint string `json:"route_hint,omitempty"`
	// SSHAlias is the name of the host's Host block in the generated ssh
	// config. Empty means the host has none; SSHProblem then says why.
	SSHAlias   string `json:"ssh_alias,omitempty"`
	SSHProblem string `json:"ssh_problem,omitempty"`
	// Mark is "pending" or "held" when a queued change to the host has
	// not reached the server.
	Mark model.Mark `json:"mark,omitempty"`
	// CaughtUp means the target first matched nothing and a catch-up pull
	// ran before this answer.
	CaughtUp bool `json:"caught_up,omitempty"`
}

// PutHostParams is the request for OpPutHost. A zero ItemID creates the host.
type PutHostParams struct {
	Host model.Host `json:"host"`
}

// SetHostKeyParams is the request for OpSetHostKey: point host HostID at
// key KeyID, but only if the host and every jump host on its way are still
// as in Chain. Chain is the whole way, in order: the host itself first,
// then its jump host, then that one's, and so on. The check and the write
// happen under the daemon's lock, and the store checks again in the
// write's own transaction, so nothing changes between them. A host, or a
// jump host, at another version, with another connection, missing, or
// with a longer or shorter way than Chain is CodeChanged, and nothing is
// written. hop key rotate uses it to point a host at a key only while the
// record still reaches the server it checked.
type SetHostKeyParams struct {
	HostID string        `json:"host_id"`
	KeyID  string        `json:"key_id"`
	Chain  []ItemVersion `json:"chain"`
}

// ItemVersion names an item at a version. In SetHostKeyParams.Chain, Conn
// is the model.ConnDigest of the host as the caller checked it: of the
// host itself with its key, of a jump host without. A version alone does
// not pin what an item holds: a held edit resolved in place changes an
// item at the same overlay version.
type ItemVersion struct {
	ID      string `json:"id"`
	Version uint64 `json:"version,string"`
	Conn    string `json:"conn"`
}

// PutKeyParams is the request for OpPutKey. PrivateKey is an unencrypted
// OpenSSH or PEM private key; the daemon derives everything else from it.
type PutKeyParams struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
}

// PutSnippetParams is the request for OpPutSnippet. A zero ItemID creates
// the snippet. The daemon sets Params from the command's {{name}}
// placeholders; whatever the caller put there is ignored.
type PutSnippetParams struct {
	Snippet model.Snippet `json:"snippet"`
}

// DeleteParams is the request for OpDelete.
type DeleteParams struct {
	ID string `json:"id"`
}

// KeyInfo describes a key without its private half.
type KeyInfo struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	KeyType        string `json:"key_type"`
	PublicKey      string `json:"public_key"`
	Fingerprint    string `json:"fingerprint"` // SHA256:...
	DedicatedGrant string `json:"dedicated_grant,omitempty"`
	ItemVersion    uint64 `json:"item_version"`
}

// CredentialInfo describes a credential without its password.
type CredentialInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

// HostSSH says how a host appears in the generated ssh config.
type HostSSH struct {
	Alias   string   `json:"alias,omitempty"`   // primary alias; empty if the host is not in the config
	Aliases []string `json:"aliases,omitempty"` // every Host block written for it
	Problem string   `json:"problem,omitempty"` // why it is not in the config
}

// ListResult answers OpList.
type ListResult struct {
	Hosts       []model.Host       `json:"hosts"`
	Keys        []KeyInfo          `json:"keys"`
	Credentials []CredentialInfo   `json:"credentials"`
	Snippets    []model.Snippet    `json:"snippets"`
	SSH         map[string]HostSSH `json:"ssh"` // by host ID
	Tailscale   *tailscale.Status  `json:"tailscale"`
	// Marks names the items, of any type, with a queued change that has
	// not reached the server: "pending", or "held" until hop sync resolve.
	// By item ID; absent items have none.
	Marks map[string]model.Mark `json:"marks,omitempty"`
	// SyncedAt is the end of the last successful pull, for a server-backed
	// vault that has had one.
	SyncedAt *time.Time `json:"synced_at,omitempty"`
}

// StatusResult answers OpStatus.
type StatusResult struct {
	Version       string    `json:"version"`
	PID           int       `json:"pid"`
	StartedAt     time.Time `json:"started_at"`
	ConfigDir     string    `json:"config_dir"`
	AgentSocket   string    `json:"agent_socket"`
	ControlSocket string    `json:"control_socket"`
	Hosts         int       `json:"hosts"`
	Keys          int       `json:"keys"`        // in the vault
	KeysInAgent   int       `json:"keys_loaded"` // served on the agent socket
	SSHHosts      int       `json:"ssh_hosts"`   // vault hosts with a Host block
	Warnings      []string  `json:"warnings,omitempty"`
	LoadedAt      time.Time `json:"loaded_at"`
	LastError     string    `json:"last_error,omitempty"` // the last reload that failed, if any
	// Vault describes the encrypted store: locked or not, the device key
	// store in use and the log head. Nil for other stores.
	Vault *store.Info `json:"vault,omitempty"`
	// Sync is sync.status without its device scan, for a store that syncs.
	Sync *SyncStatusResult `json:"sync,omitempty"`
	// EndedSessions is the ssh sessions the daemon told to end
	// (sessions.go): on a revocation, the max-offline lock or hop lock
	// --end-sessions.
	EndedSessions *EndedSessions `json:"ended_sessions,omitempty"`
	Tailscale     struct {
		Available bool   `json:"available"`
		Reason    string `json:"reason,omitempty"`
	} `json:"tailscale"`
}

// Sync states, SyncStatusResult.State.
const (
	SyncOff        = "off"         // local-only, or no server is recorded
	SyncLocked     = "locked"      // paused until the vault is unlocked (§11.2)
	SyncStarting   = "starting"    // no pull has finished since the daemon started or the vault unlocked
	SyncOnline     = "online"      // the last pull or push worked
	SyncBackingOff = "backoff"     // the last attempt failed; it is retried at Backoff.RetryAt
	SyncHalted     = "halted"      // stopped for good on an equivocation or a rule violation
	SyncRevoked    = "revoked"     // this device was revoked; nothing syncs again
	SyncLoggingOut = "logging_out" // a logout is resuming
	SyncLoggedOut  = "logged_out"  // the logout finished; nothing of the vault is left
)

// SyncStatusResult answers OpSyncStatus and OpSyncNow. It works while the
// vault is locked, with what can be read without the vault key.
type SyncStatusResult struct {
	State     string `json:"state"`
	Server    string `json:"server,omitempty"`
	Email     string `json:"email,omitempty"`
	VaultID   string `json:"vault_id,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	// Head is the last verified head; nil while locked.
	Head    *store.Head `json:"head,omitempty"`
	Pending int         `json:"pending"` // queued changes not held
	Held    int         `json:"held"`    // held until hop sync resolve
	// SyncedAt is the end of the last successful pull; null if there has
	// been none since the daemon started.
	SyncedAt    *time.Time   `json:"synced_at"`
	LastError   string       `json:"last_error,omitempty"`
	LastErrorAt *time.Time   `json:"last_error_at,omitempty"`
	Backoff     *SyncBackoff `json:"backoff,omitempty"`
	// Halted is why sync stopped for good; Equivocation says it was the
	// server showing two different entries at one position (§5.6).
	Halted       string `json:"halted,omitempty"`
	Equivocation bool   `json:"equivocation,omitempty"`
	// ServerRetirement is set when the server refused this device a
	// session and its retire-status said the device left the account.
	// Until its proof verifies that is the server's word only: the report
	// is recorded on disk and the vault stays locked, after a restart too,
	// until the server authenticates the device again, and nothing is
	// deleted. Once the proof verifies (Wiped), this device's copy of the
	// vault is gone.
	ServerRetirement *ServerRetirement `json:"server_retirement,omitempty"`
	// CheckSkipped says why the question to the server before the keys
	// loaded (at start or unlock) went unanswered, so they loaded without
	// it; "" once one is answered.
	CheckSkipped string `json:"check_skipped,omitempty"`
	// MaxOffline is the account's max-offline policy in seconds (0: off);
	// LastContact is the last time the server authenticated this device,
	// as last read; OfflineLocked says why the policy locked the vault.
	MaxOffline    int64      `json:"max_offline,omitempty"`
	LastContact   *time.Time `json:"last_contact,omitempty"`
	OfflineLocked string     `json:"offline_locked,omitempty"`
	// ServerUnconfirmed says why the server's answer kept the vault
	// locked: it did not confirm this device is still in the account
	// (store.ErrServerUnconfirmed). The next unlock or sync asks again.
	ServerUnconfirmed string `json:"server_unconfirmed,omitempty"`
	// What still needs the user, each also a sentence in Warnings.
	LostIntents        uint64                  `json:"lost_intents,omitempty"`
	LostJournals       *store.LostJournals     `json:"lost_journals,omitempty"`
	CheckpointDue      bool                    `json:"checkpoint_due,omitempty"`
	Checkpoint         *store.CheckpointStatus `json:"checkpoint,omitempty"`
	SecretKeyStale     bool                    `json:"secret_key_stale,omitempty"`
	UndeliveredDevices int                     `json:"undelivered_devices,omitempty"`
	Logout             string                  `json:"logout,omitempty"`
	Publishing         bool                    `json:"publishing,omitempty"`
	Merge              string                  `json:"merge,omitempty"`
	Warnings           []string                `json:"warnings,omitempty"`
}

// ServerRetirement is the server's report that this device left the
// account (SyncStatusResult.ServerRetirement).
type ServerRetirement struct {
	How        string `json:"how"`        // "retired" or "revoked"
	Seq        uint64 `json:"seq"`        // the entry the server says removed it
	Unverified bool   `json:"unverified"` // the proof has not verified (yet): nothing was deleted
	// Wiped means the revocation is proven (not Unverified) and the wipe
	// is done: this device's copy of the vault, its device key and the
	// ssh files hop wrote are gone.
	Wiped bool `json:"wiped,omitempty"`
	// WipeError says why a proven revocation's wipe has not finished yet.
	WipeError string `json:"wipe_error,omitempty"`
	// SSHFilesLeft means only the ssh files are left: this device's copy
	// of the vault and its device key are wiped, but the cleanup of the
	// ssh config hop generated from it has not finished (CleanupLeft).
	// The daemon retries it.
	SSHFilesLeft bool `json:"ssh_files_left,omitempty"`
	// ProofError says why the proof did not verify, or could not be had.
	ProofError string `json:"proof_error,omitempty"`
	// ReportCorrupt means the record of the server's report here does not
	// parse or its MAC does not verify: it keeps the vault locked, but How
	// and Seq are not shown as the server's.
	ReportCorrupt bool `json:"report_corrupt,omitempty"`
}

// SyncBackoff is the retry schedule after a failure.
type SyncBackoff struct {
	Attempt int       `json:"attempt"` // failures in a row
	RetryAt time.Time `json:"retry_at"`
}

// SyncHeldResult answers OpSyncHeld. Only the outbox head can be held
// (everything behind it waits), so Held has at most one record today.
type SyncHeldResult struct {
	Held []HeldChange `json:"held"`
}

// HeldChange is a held queued change. Seen, Want and Current are the
// item's plaintext JSON (null when absent): what this device's change
// started from, what it wants, and the item as verified from the server.
// A key's private_key and a credential's password are left out.
type HeldChange struct {
	N       uint64          `json:"n"` // pass back in SyncResolveParams
	Import  bool            `json:"import,omitempty"`
	Action  merge.Action    `json:"action"`
	ItemID  string          `json:"item_id"`
	Type    model.Type      `json:"type"`
	Seen    json.RawMessage `json:"seen"`
	Want    json.RawMessage `json:"want"`
	Current json.RawMessage `json:"current"`
	// Hold says why it is held now; nil if a retry would apply it.
	Hold *store.HoldInfo `json:"hold"`
	// Choices are the resolutions on offer: keep-mine, edit, take-theirs
	// and retry, less what the hold refuses.
	Choices []string `json:"choices"`
	// KeepMine is what keep-mine would write, with its token, or nil
	// when keep-mine is refused (KeepMineRefused says why).
	KeepMine        *Proposal `json:"keep_mine,omitempty"`
	KeepMineRefused string    `json:"keep_mine_refused,omitempty"`
}

// Proposal is the replacement a keep-mine or edit resolution writes, and
// the token that confirms it. Confirm is opaque: a MAC, under a key only
// this daemon process holds, of the proposal's §5.4 digest, which covers
// the secrets left out of Seen and Want. It reveals nothing about them,
// and it no longer confirms once the daemon restarts or anything in the
// replacement changes, secrets included.
type Proposal struct {
	N       uint64          `json:"n"`
	Choice  string          `json:"choice"`
	Action  merge.Action    `json:"action"`
	ItemID  string          `json:"item_id"`
	Type    model.Type      `json:"type"`
	Seen    json.RawMessage `json:"seen"`
	Want    json.RawMessage `json:"want"`
	NewID   string          `json:"new_id,omitempty"` // pass back in SyncResolveParams
	Confirm string          `json:"confirm"`          // pass back as SyncResolveParams.Confirm
}

// Resolution choices.
const (
	ChoiceKeepMine   = "keep-mine"
	ChoiceEdit       = "edit"
	ChoiceTakeTheirs = "take-theirs"
	ChoiceRetry      = "retry"
)

// SyncResolveParams is the request for OpSyncResolve. N names the held
// record (HeldChange.N). keep-mine and edit write only with Confirm, the
// token of the proposal (from HeldChange.KeepMine, or from a Propose
// call for edit); with Propose they return the proposal and write
// nothing. Edited is the edited item's plaintext JSON, for edit only, and
// only for hosts and snippets: a key's or credential's secret never
// crosses the control socket.
type SyncResolveParams struct {
	N       uint64          `json:"n"`
	Choice  string          `json:"choice"`
	Edited  json.RawMessage `json:"edited,omitempty"`
	NewID   string          `json:"new_id,omitempty"`
	Confirm string          `json:"confirm,omitempty"`
	Propose bool            `json:"propose,omitempty"`
}

// SyncResolveResult answers OpSyncResolve: the proposal for Propose,
// otherwise the sync status after the resolution.
type SyncResolveResult struct {
	Proposal *Proposal         `json:"proposal,omitempty"`
	Status   *SyncStatusResult `json:"status,omitempty"`
}

// DevicesResult answers OpDevicesList.
type DevicesResult struct {
	Devices []store.DeviceListing `json:"devices"`
}

func invalidf(format string, args ...any) *Error {
	return &Error{Code: CodeInvalid, Message: fmt.Sprintf(format, args...)}
}
