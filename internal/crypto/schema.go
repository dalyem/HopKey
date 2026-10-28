package crypto

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// SchemaError reports a value that the closed schemas of §3 and §6.5 do not
// allow. Err, when set, names the rule (for example ErrSSHKeyLine).
type SchemaError struct {
	Field  string
	Reason string
	Err    error
}

func (e *SchemaError) Error() string { return "crypto: " + e.Field + ": " + e.Reason }

func (e *SchemaError) Unwrap() error { return e.Err }

func schemaErr(field, format string, args ...any) error {
	return &SchemaError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

// CheckStr enforces str≤n (§3): valid UTF-8, at most n bytes, and no
// control characters (Unicode general category Cc: C0, DEL and C1).
func CheckStr(field, s string, n int) error {
	return checkString(field, s, n, false)
}

// CheckText enforces text≤n (§3): like str≤n, except that LF (U+000A) and
// TAB (U+0009) are allowed. CR and every other Cc character are rejected;
// clients convert CRLF to LF on input (CRLFToLF).
func CheckText(field, s string, n int) error {
	return checkString(field, s, n, true)
}

func checkString(field, s string, n int, text bool) error {
	if !utf8.ValidString(s) {
		return schemaErr(field, "not valid UTF-8")
	}
	if len(s) > n {
		return schemaErr(field, "longer than %d bytes", n)
	}
	for _, r := range s {
		if text && (r == '\n' || r == '\t') {
			continue
		}
		if unicode.IsControl(r) {
			return schemaErr(field, "contains a control character")
		}
	}
	return nil
}

// CRLFToLF converts every CRLF in s to LF, the input conversion §3 asks of
// clients for text≤n fields. A CR that is not followed by LF is left in
// place, so CheckText still rejects it.
func CRLFToLF(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

func checkStrs(field string, ss []string, n int) error {
	for i, s := range ss {
		if err := CheckStr(fmt.Sprintf("%s[%d]", field, i), s, n); err != nil {
			return err
		}
	}
	return nil
}

// CheckID enforces a required id: non-zero (model.ID writes zero as "").
func CheckID(field string, id model.ID) error {
	if id.IsZero() {
		return schemaErr(field, "required id is empty")
	}
	return nil
}

func checkEnum(field, v string, allowed ...string) error {
	if !slices.Contains(allowed, v) {
		return schemaErr(field, "%q is not one of %v", v, allowed)
	}
	return nil
}

func checkHeader(h model.Header, t model.Type) error {
	if h.V != Version {
		return ErrUnsupported
	}
	if err := CheckID("item_id", h.ItemID); err != nil {
		return err
	}
	if h.Type != t {
		return schemaErr("type", "%q, want %q", h.Type, t)
	}
	return nil
}

// ValidateHost checks a host plaintext against §6.5.
func ValidateHost(h *model.Host) error {
	if err := checkHeader(h.Header, model.TypeHost); err != nil {
		return err
	}
	if err := CheckStr("name", h.Name, 64); err != nil {
		return err
	}
	if err := checkStrs("aliases", h.Aliases, 64); err != nil {
		return err
	}
	if err := checkStrs("addresses", h.Addresses, 255); err != nil {
		return err
	}
	if h.Port < 1 || h.Port > 65535 {
		return schemaErr("port", "%d outside 1..65535", h.Port)
	}
	if err := CheckStr("user", h.User, 64); err != nil {
		return err
	}
	if err := checkStrs("tags", h.Tags, 32); err != nil {
		return err
	}
	if err := CheckText("description", h.Description, 1024); err != nil {
		return err
	}
	if ts := h.Tailscale; ts != nil {
		if err := CheckStr("tailscale.stable_node_id", ts.StableNodeID, 64); err != nil {
			return err
		}
		if err := CheckStr("tailscale.dns_name", ts.DNSName, 255); err != nil {
			return err
		}
		if err := checkEnum("tailscale.ssh", ts.SSH, "yes", "no", "unknown"); err != nil {
			return err
		}
	}
	if err := checkEnum("route", h.Route, "auto", "tailnet", "direct"); err != nil {
		return err
	}
	if err := checkStrs("host_keys", h.HostKeys, 8192); err != nil {
		return err
	}
	// Each host_keys entry is an OpenSSH authorized_keys line (rev 10
	// item 11).
	for i, l := range h.HostKeys {
		if _, err := checkSSHKeyLine(fmt.Sprintf("host_keys[%d]", i), l); err != nil {
			return err
		}
	}
	return checkEnum("agent_access", h.AgentAccess, "allow", "deny")
}

// ValidateKey checks a key plaintext against §6.5. public_key is an
// OpenSSH authorized_keys line (rev 10 item 11). private_key is text≤16384
// and an unencrypted OpenSSH private key whose public key equals
// public_key's blob and whose algorithm matches key_type (rev 12).
func ValidateKey(k *model.Key) error {
	if err := checkHeader(k.Header, model.TypeKey); err != nil {
		return err
	}
	if err := CheckStr("name", k.Name, 64); err != nil {
		return err
	}
	if err := checkEnum("key_type", k.KeyType, "ed25519", "ecdsa-p256", "rsa"); err != nil {
		return err
	}
	if err := CheckText("private_key", k.PrivateKey, 16384); err != nil {
		return err
	}
	if err := CheckStr("public_key", k.PublicKey, 8192); err != nil {
		return err
	}
	blob, err := checkSSHKeyLine("public_key", k.PublicKey)
	if err != nil {
		return err
	}
	return checkPrivateKey(k.KeyType, k.PrivateKey, blob)
}

// ValidateCredential checks a credential plaintext against §6.5.
func ValidateCredential(c *model.Credential) error {
	if err := checkHeader(c.Header, model.TypeCredential); err != nil {
		return err
	}
	if err := CheckStr("name", c.Name, 64); err != nil {
		return err
	}
	if err := CheckStr("username", c.Username, 64); err != nil {
		return err
	}
	return CheckStr("password", c.Password, 1024)
}

// ValidateSnippet checks a snippet plaintext against §6.5.
func ValidateSnippet(s *model.Snippet) error {
	if err := checkHeader(s.Header, model.TypeSnippet); err != nil {
		return err
	}
	if err := CheckStr("name", s.Name, 64); err != nil {
		return err
	}
	if err := CheckText("command", s.Command, 8192); err != nil {
		return err
	}
	if err := checkStrs("params", s.Params, 32); err != nil {
		return err
	}
	return CheckText("description", s.Description, 1024)
}

// MaxPolicyOffline is the longest max_offline a policy may set: ten years.
const MaxPolicyOffline = 10 * 366 * 24 * 3600

// ValidatePolicy checks a policy plaintext: max_offline is 0 (off) or at
// least a minute and at most MaxPolicyOffline seconds.
func ValidatePolicy(p *model.Policy) error {
	if err := checkHeader(p.Header, model.TypePolicy); err != nil {
		return err
	}
	if p.MaxOffline != 0 && (p.MaxOffline < 60 || p.MaxOffline > MaxPolicyOffline) {
		return schemaErr("max_offline", "%d seconds is not 0 or between a minute and ten years", p.MaxOffline)
	}
	return nil
}

// ValidateGrant checks a grant record plaintext against §6.5. Rules that
// need the other items (item types, §8.7) are in CheckGrantRecord.
func ValidateGrant(g *model.Grant) error {
	if err := checkHeader(g.Header, model.TypeGrant); err != nil {
		return err
	}
	if err := CheckID("grant_id", g.GrantID); err != nil {
		return err
	}
	if err := CheckStr("name", g.Name, 64); err != nil {
		return err
	}
	if _, err := g.ExpiresAt.MarshalText(); err != nil {
		return schemaErr("expires_at", "%v", err)
	}
	for i, id := range g.Items {
		if err := CheckID(fmt.Sprintf("items[%d]", i), id); err != nil {
			return err
		}
		if i > 0 && string(g.Items[i-1][:]) >= string(id[:]) {
			return schemaErr("items", "not sorted ascending without duplicates")
		}
	}
	for h, k := range g.HostKeyMap {
		if err := CheckID("host_key_map key", h); err != nil {
			return err
		}
		if err := CheckID("host_key_map value", k); err != nil {
			return err
		}
	}
	return checkEnum("key_policy", g.KeyPolicy, "dedicated", "shared")
}

// Item is one decoded §6.5 plaintext: *model.Host, *model.Key,
// *model.Credential, *model.Snippet, *model.Grant or *model.Policy.
type Item any

// ItemHeader returns the shared header of an Item.
func ItemHeader(it Item) (model.Header, error) {
	switch v := it.(type) {
	case *model.Host:
		return v.Header, nil
	case *model.Key:
		return v.Header, nil
	case *model.Credential:
		return v.Header, nil
	case *model.Snippet:
		return v.Header, nil
	case *model.Grant:
		return v.Header, nil
	case *model.Policy:
		return v.Header, nil
	default:
		return model.Header{}, fmt.Errorf("crypto: %T is not an item plaintext", it)
	}
}

// ValidateItem dispatches to the per-type validator.
func ValidateItem(it Item) error {
	switch v := it.(type) {
	case *model.Host:
		return ValidateHost(v)
	case *model.Key:
		return ValidateKey(v)
	case *model.Credential:
		return ValidateCredential(v)
	case *model.Snippet:
		return ValidateSnippet(v)
	case *model.Grant:
		return ValidateGrant(v)
	case *model.Policy:
		return ValidatePolicy(v)
	default:
		return fmt.Errorf("crypto: %T is not an item plaintext", it)
	}
}

// ParseItem decodes a plaintext of type t under its closed schema and
// validates it.
func ParseItem(t model.Type, b []byte) (Item, error) {
	var it Item
	switch t {
	case model.TypeHost:
		it = new(model.Host)
	case model.TypeKey:
		it = new(model.Key)
	case model.TypeCredential:
		it = new(model.Credential)
	case model.TypeSnippet:
		it = new(model.Snippet)
	case model.TypeGrant:
		it = new(model.Grant)
	case model.TypePolicy:
		it = new(model.Policy)
	default:
		return nil, schemaErr("type", "unknown item type %q", t)
	}
	if err := canonjson.Unmarshal(b, it); err != nil {
		return nil, err
	}
	if err := ValidateItem(it); err != nil {
		return nil, err
	}
	return it, nil
}

// MarshalItem validates it and returns JCS(plaintext).
func MarshalItem(it Item) ([]byte, error) {
	if err := ValidateItem(it); err != nil {
		return nil, err
	}
	return canonjson.Marshal(it)
}

var errNotBundleType = errors.New("crypto: grant records are never placed in a bundle")

// isBundleType reports whether t may appear in a grant's items and bundle.
func isBundleType(t model.Type) bool {
	switch t {
	case model.TypeHost, model.TypeKey, model.TypeCredential, model.TypeSnippet:
		return true
	}
	return false
}
