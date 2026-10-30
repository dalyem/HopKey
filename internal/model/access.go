package model

// Access is a record of a colleague's public key that hop access put on
// some of the user's hosts (type "access", crypto spec rev 17 Part 2, §5.1).
// It holds the public key only. Each target is one host's authorized_keys
// line, bound to the host key that host presented when the target was
// added (§7.6), and its state is what hop last recorded for it (§7.1).
//
// RecordID, not ItemID, is what the line's marker carries (hop-access:
// followed by RecordID), so the public log can't be linked to a host's
// file (§6.3). By is a system member: the device that signed the latest
// normal put, set by the writer and never merged (§5.0).
type Access struct {
	Header
	Label       string         `json:"label"`
	RecordID    ID             `json:"record_id"`
	PublicKey   string         `json:"public_key"`
	Fingerprint string         `json:"fingerprint"`
	Options     AccessOptions  `json:"options"`
	By          ID             `json:"by"`
	Targets     []AccessTarget `json:"targets"`
}

// AccessOptions are the authorized_keys options of an access line. They
// come only from flags (§6.2): no raw option string is ever stored.
type AccessOptions struct {
	From         []string `json:"from"` // canonical masked prefixes
	Restrict     bool     `json:"restrict"`
	NoForwarding bool     `json:"no_forwarding"`
}

// Target states (§7.1). Removed and abandoned are terminal: a terminal
// target never changes again.
const (
	AccessPending   = "pending"
	AccessInstalled = "installed"
	AccessFailed    = "failed"
	AccessRemoving  = "removing"
	AccessRemoved   = "removed"
	AccessAbandoned = "abandoned"
)

// AccessTerminal reports whether state is removed or abandoned.
func AccessTerminal(state string) bool {
	return state == AccessRemoved || state == AccessAbandoned
}

// AccessTarget is one host of an access record. (HostItemID, ServerKeyFP)
// and User never change once the target exists (§5.1 log rules).
type AccessTarget struct {
	HostItemID  ID           `json:"host_item_id"`
	User        string       `json:"user"`
	ServerKeyFP string       `json:"server_key_fp"`
	Gen         uint64       `json:"gen,string"`
	Alongside   bool         `json:"alongside"`
	State       string       `json:"state"`
	Time        Timestamp    `json:"time"`
	Error       string       `json:"error"`
	SameMachine *SameMachine `json:"same_machine"` // null unless the user made the --same-machine statement
}

// SameMachine is the user's statement, made with hop access rm --same-machine,
// that the other host records in HostItemIDs reach the same machine and
// account as the target (§7.6).
type SameMachine struct {
	Gen         uint64 `json:"gen,string"`
	ServerKeyFP string `json:"server_key_fp"`
	HostItemIDs []ID   `json:"host_item_ids"`
}
