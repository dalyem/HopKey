package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

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
	OpStatus    = "status"
	OpList      = "list"
	OpResolve   = "resolve"
	OpTailscale = "tailscale"
	OpPutHost   = "put_host"
	OpPutKey    = "put_key"
	OpDelete    = "delete"
	OpReload    = "reload"
	OpShutdown  = "shutdown"
)

// Error codes.
const (
	CodeInvalid  = "invalid"   // the request was malformed or its content refused
	CodeNotFound = "not_found" // no such item
	CodeLocked   = "locked"    // the vault is locked
	CodeInternal = "internal"
)

// Request is one control call.
type Request struct {
	Op     string          `json:"op"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response answers one Request.
type Response struct {
	OK     bool            `json:"ok"`
	Error  *Error          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
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
}

// ResolveResult answers OpResolve.
type ResolveResult struct {
	Result *resolve.Result `json:"result"`
	// Host, Route and the ssh fields are set when Result matched a host.
	Host       *model.Host    `json:"host,omitempty"`
	Route      *resolve.Route `json:"route,omitempty"`
	RouteError string         `json:"route_error,omitempty"`
	// SSHAlias is the name of the host's Host block in the generated ssh
	// config. Empty means the host has none; SSHProblem then says why.
	SSHAlias   string `json:"ssh_alias,omitempty"`
	SSHProblem string `json:"ssh_problem,omitempty"`
}

// PutHostParams is the request for OpPutHost. A zero ItemID creates the host.
type PutHostParams struct {
	Host model.Host `json:"host"`
}

// PutKeyParams is the request for OpPutKey. PrivateKey is an unencrypted
// OpenSSH or PEM private key; the daemon derives everything else from it.
type PutKeyParams struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
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
	Vault     *store.Info `json:"vault,omitempty"`
	Tailscale struct {
		Available bool   `json:"available"`
		Reason    string `json:"reason,omitempty"`
	} `json:"tailscale"`
}

func invalidf(format string, args ...any) *Error {
	return &Error{Code: CodeInvalid, Message: fmt.Sprintf(format, args...)}
}
