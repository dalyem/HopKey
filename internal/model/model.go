// Package model holds the plaintext item types stored in a HopKey vault and
// the Store interface the CLI and daemon read them through.
//
// The JSON shapes are normative: they are the closed schemas in crypto spec
// §6.5 (https://plan.23d.dev/p/xuu5z9q2). Encryption, the vault log and
// schema validation live in internal/crypto and internal/vaultlog; this
// package only names the data.
package model

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ID is a 16-byte random identifier, written as 32 lowercase hex characters.
type ID [16]byte

// IsZero reports whether id is the zero ID, which the schemas write as "".
func (id ID) IsZero() bool { return id == ID{} }

func (id ID) String() string { return hex.EncodeToString(id[:]) }

// MarshalText writes the zero ID as "" (an absent reference) and any other
// ID as 32 lowercase hex characters.
func (id ID) MarshalText() ([]byte, error) {
	if id.IsZero() {
		return []byte{}, nil
	}
	return []byte(id.String()), nil
}

// UnmarshalText accepts "" as the zero ID and otherwise exactly 32 lowercase
// hex characters.
func (id *ID) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*id = ID{}
		return nil
	}
	parsed, err := ParseID(string(b))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// ParseID parses 32 lowercase hex characters.
func ParseID(s string) (ID, error) {
	var id ID
	if len(s) != 32 {
		return id, fmt.Errorf("model: id %q is not 32 hex characters", s)
	}
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return id, fmt.Errorf("model: id %q is not lowercase hex", s)
		}
	}
	if _, err := hex.Decode(id[:], []byte(s)); err != nil {
		return id, err
	}
	return id, nil
}

// Type is an item type from spec §6.5.
type Type string

const (
	TypeHost       Type = "host"
	TypeKey        Type = "key"
	TypeCredential Type = "credential"
	TypeSnippet    Type = "snippet"
	TypeGrant      Type = "grant"
)

// Header is the part every item plaintext shares. ItemVersion is a u64
// written as a decimal string in JSON (spec §3).
type Header struct {
	V           int    `json:"v"`
	ItemID      ID     `json:"item_id"`
	Type        Type   `json:"type"`
	ItemVersion uint64 `json:"item_version,string"`
}

// Tailscale links a host to a tailnet node by its stable ID.
type Tailscale struct {
	StableNodeID string `json:"stable_node_id"`
	DNSName      string `json:"dns_name"`
	SSH          string `json:"ssh"` // "yes" | "no" | "unknown"
}

// Host is a machine to connect to.
type Host struct {
	Header
	Name         string     `json:"name"`
	Aliases      []string   `json:"aliases"`
	Addresses    []string   `json:"addresses"`
	Port         uint32     `json:"port"`
	User         string     `json:"user"`
	KeyID        ID         `json:"key_id"`
	CredentialID ID         `json:"credential_id"`
	JumpHostID   ID         `json:"jump_host_id"`
	Tags         []string   `json:"tags"`
	Description  string     `json:"description"`
	Tailscale    *Tailscale `json:"tailscale"`
	Route        string     `json:"route"`     // "auto" | "tailnet" | "direct"
	HostKeys     []string   `json:"host_keys"` // OpenSSH public-key lines
	AgentAccess  string     `json:"agent_access"`
}

// Key is an SSH key pair. PrivateKey is unencrypted OpenSSH PEM.
type Key struct {
	Header
	Name           string `json:"name"`
	KeyType        string `json:"key_type"` // "ed25519" | "ecdsa-p256" | "rsa"
	PrivateKey     string `json:"private_key"`
	PublicKey      string `json:"public_key"`
	DedicatedGrant ID     `json:"dedicated_grant"`
}

// Credential is a username and password for password-only hosts.
type Credential struct {
	Header
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Snippet is a saved command with named parameters ({{name}}).
type Snippet struct {
	Header
	Name        string   `json:"name"`
	Command     string   `json:"command"`
	Params      []string `json:"params"`
	Description string   `json:"description"`
}

// Grant is the management record for a token grant (spec §6.5, type
// "grant"). It never holds the token seed or the token's KEM private key.
// TokenKEMPK is a b64 member: encode grants with internal/canonjson, which
// writes []byte as base64url without padding (spec §3).
type Grant struct {
	Header
	GrantID        ID        `json:"grant_id"`
	Name           string    `json:"name"`
	ExpiresAt      Timestamp `json:"expires_at"`
	TokenKEMPK     []byte    `json:"token_kem_pk"`
	Items          []ID      `json:"items"` // sorted, unique
	HostKeyMap     map[ID]ID `json:"host_key_map"`
	KeyPolicy      string    `json:"key_policy"` // "dedicated" | "shared"
	DedicatedKeyID ID        `json:"dedicated_key_id"`
	ReissuedFrom   ID        `json:"reissued_from"`
}

// TimestampLayout is the spec §3 ts format.
const TimestampLayout = "2006-01-02T15:04:05Z"

// Timestamp is a ts value (spec §3): a UTC instant with one-second
// precision, stored as Unix seconds and written YYYY-MM-DDTHH:MM:SSZ.
type Timestamp int64

// TimestampOf truncates t to whole seconds.
func TimestampOf(t time.Time) Timestamp { return Timestamp(t.Unix()) }

// Time returns ts as a UTC time.Time.
func (ts Timestamp) Time() time.Time { return time.Unix(int64(ts), 0).UTC() }

func (ts Timestamp) String() string { return ts.Time().Format(TimestampLayout) }

// MarshalText fails for instants outside years 0000 to 9999, which the
// four-digit year cannot express.
func (ts Timestamp) MarshalText() ([]byte, error) {
	s := ts.String()
	if len(s) != len(TimestampLayout) {
		return nil, fmt.Errorf("model: timestamp %d outside years 0000-9999", int64(ts))
	}
	return []byte(s), nil
}

// UnmarshalText accepts exactly YYYY-MM-DDTHH:MM:SSZ with in-range fields.
func (ts *Timestamp) UnmarshalText(b []byte) error {
	t, err := time.Parse(TimestampLayout, string(b))
	if err != nil || len(b) != len(TimestampLayout) || t.Format(TimestampLayout) != string(b) {
		return fmt.Errorf("model: %q is not a YYYY-MM-DDTHH:MM:SSZ timestamp", b)
	}
	*ts = TimestampOf(t)
	return nil
}

// Snapshot is every live, decrypted item in a vault at one log head.
type Snapshot struct {
	Hosts       []Host
	Keys        []Key
	Credentials []Credential
	Snippets    []Snippet
}

// ErrNotFound means no live item has the requested ID.
var ErrNotFound = errors.New("model: item not found")

// ErrLocked means the vault is locked and must be unlocked first.
var ErrLocked = errors.New("model: vault is locked")

// Store reads and writes vault items. Implementations handle encryption,
// the vault log and sync; callers see plaintext only.
//
// Put creates the item when its ItemID is zero (assigning an ID and version
// 1) and otherwise replaces the live item, which must have the same type
// and the current ItemVersion; the store increments the version. Put and
// Delete enforce reference integrity (spec §5.3) and return an error rather
// than leave a dangling reference.
type Store interface {
	Snapshot(ctx context.Context) (Snapshot, error)
	PutHost(ctx context.Context, h Host) (Host, error)
	PutKey(ctx context.Context, k Key) (Key, error)
	PutCredential(ctx context.Context, c Credential) (Credential, error)
	PutSnippet(ctx context.Context, s Snippet) (Snippet, error)
	Delete(ctx context.Context, id ID) error
}
