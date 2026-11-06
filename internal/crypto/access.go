package crypto

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/model"
)

// Limits of the access item (crypto spec rev 17, Part 2, §5.1).
const (
	AccessMaxFrom        = 16
	AccessMaxTargets     = 256
	AccessMaxSameMachine = 16
	accessMinRSABits     = 3072
)

// accessKeyTypes are the key types an access record may hold (§5.1). FIDO
// keys (sk-*) and certificates are not among them.
var accessKeyTypes = map[string]bool{
	ssh.KeyAlgoED25519:  true,
	ssh.KeyAlgoECDSA256: true,
	ssh.KeyAlgoECDSA384: true,
	ssh.KeyAlgoECDSA521: true,
	ssh.KeyAlgoRSA:      true,
}

// CheckAccessPublicKey is the §5.1 rule for access.public_key: an OpenSSH
// key line with no comment, of an allowed type, RSA at 3072 bits or more.
// It returns the key.
func CheckAccessPublicKey(line string) (ssh.PublicKey, error) {
	blob, err := ParseSSHKeyLine(line)
	if err != nil {
		return nil, &SchemaError{Field: "public_key", Reason: err.Error(), Err: ErrSSHKeyLine}
	}
	typ, rest, _ := splitSSHField(line)
	if _, comment, _ := splitSSHField(rest); comment != "" {
		return nil, schemaErr("public_key", "has a comment")
	}
	if !accessKeyTypes[typ] {
		return nil, schemaErr("public_key", "key type %q is not ssh-ed25519, ecdsa-sha2-nistp256/384/521 or ssh-rsa", typ)
	}
	pk, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, &SchemaError{Field: "public_key", Reason: err.Error(), Err: ErrSSHKeyLine}
	}
	if typ == ssh.KeyAlgoRSA {
		cpk, ok := pk.(ssh.CryptoPublicKey)
		r, isRSA := cpk.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || !isRSA || r.N.BitLen() < accessMinRSABits {
			return nil, schemaErr("public_key", "RSA keys need at least %d bits", accessMinRSABits)
		}
	}
	return pk, nil
}

var b64RawStd = base64.RawStdEncoding.Strict()

// IsSSHFingerprint reports whether s has the ssh_pk_fp form: "SHA256:" and
// 43 characters of unpadded standard base64 (§10.3).
func IsSSHFingerprint(s string) bool {
	b64, ok := strings.CutPrefix(s, "SHA256:")
	if !ok || len(b64) != 43 {
		return false
	}
	raw, err := b64RawStd.DecodeString(b64)
	return err == nil && len(raw) == 32
}

// CanonicalFrom returns the stored form of a --from entry: a netip.Prefix
// after Masked(), as text (§6.2). A bare address is a /32 or /128.
func CanonicalFrom(s string) (string, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil || a.Zone() != "" {
			return "", fmt.Errorf("%q is not an address or CIDR prefix", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	return p.Masked().String(), nil
}

// ValidateAccess checks an access plaintext against §5.1.
func ValidateAccess(a *model.Access) error {
	if err := checkHeader(a.Header, model.TypeAccess); err != nil {
		return err
	}
	if err := CheckStr("label", a.Label, 64); err != nil {
		return err
	}
	if a.Label == "" {
		return schemaErr("label", "is empty")
	}
	if err := CheckID("record_id", a.RecordID); err != nil {
		return err
	}
	if err := CheckStr("public_key", a.PublicKey, 8192); err != nil {
		return err
	}
	if _, err := CheckAccessPublicKey(a.PublicKey); err != nil {
		return err
	}
	if err := CheckStr("fingerprint", a.Fingerprint, 64); err != nil {
		return err
	}
	if fp, err := SSHFingerprint(a.PublicKey); err != nil || fp != a.Fingerprint {
		return schemaErr("fingerprint", "is not the fingerprint of public_key")
	}
	if err := checkAccessOptions(a.Options); err != nil {
		return err
	}
	if err := CheckID("by", a.By); err != nil {
		return err
	}
	return checkAccessTargets(a.Targets)
}

func checkAccessOptions(o model.AccessOptions) error {
	if len(o.From) > AccessMaxFrom {
		return schemaErr("options.from", "has more than %d entries", AccessMaxFrom)
	}
	seen := map[string]bool{}
	for i, f := range o.From {
		field := fmt.Sprintf("options.from[%d]", i)
		if err := CheckStr(field, f, 49); err != nil {
			return err
		}
		p, err := netip.ParsePrefix(f)
		if err != nil || p.Masked().String() != f {
			return schemaErr(field, "%q is not a canonical masked prefix", f)
		}
		if seen[f] {
			return schemaErr(field, "%q is listed twice", f)
		}
		seen[f] = true
	}
	if o.Restrict && o.NoForwarding {
		return schemaErr("options", "restrict and no_forwarding are both set")
	}
	return nil
}

func checkAccessTargets(ts []model.AccessTarget) error {
	if len(ts) < 1 || len(ts) > AccessMaxTargets {
		return schemaErr("targets", "has %d entries, want 1 to %d", len(ts), AccessMaxTargets)
	}
	live := map[model.ID]bool{}
	for i, t := range ts {
		field := fmt.Sprintf("targets[%d]", i)
		if err := CheckID(field+".host_item_id", t.HostItemID); err != nil {
			return err
		}
		if err := CheckStr(field+".user", t.User, 64); err != nil {
			return err
		}
		if t.User == "" {
			return schemaErr(field+".user", "is empty")
		}
		if err := CheckStr(field+".server_key_fp", t.ServerKeyFP, 64); err != nil {
			return err
		}
		if !IsSSHFingerprint(t.ServerKeyFP) {
			return schemaErr(field+".server_key_fp", "%q is not a SHA256 fingerprint", t.ServerKeyFP)
		}
		if t.Gen < 1 {
			return schemaErr(field+".gen", "is 0")
		}
		if err := checkEnum(field+".state", t.State, model.AccessPending, model.AccessInstalled, model.AccessFailed,
			model.AccessRemoving, model.AccessRemoved, model.AccessAbandoned); err != nil {
			return err
		}
		if _, err := t.Time.MarshalText(); err != nil {
			return schemaErr(field+".time", "%v", err)
		}
		if err := CheckStr(field+".error", t.Error, 256); err != nil {
			return err
		}
		if t.Error != "" && t.State != model.AccessFailed && t.State != model.AccessRemoving {
			return schemaErr(field+".error", "is set on a %s target", t.State)
		}
		if i > 0 {
			p := ts[i-1]
			if c := strings.Compare(string(p.HostItemID[:]), string(t.HostItemID[:])); c > 0 || c == 0 && p.ServerKeyFP >= t.ServerKeyFP {
				return schemaErr("targets", "not sorted by (host_item_id, server_key_fp) without duplicates")
			}
		}
		if !model.AccessTerminal(t.State) {
			if live[t.HostItemID] {
				return schemaErr("targets", "host %v has two targets that are not removed or abandoned", t.HostItemID)
			}
			live[t.HostItemID] = true
		}
		if err := checkSameMachine(field+".same_machine", t); err != nil {
			return err
		}
	}
	return nil
}

func checkSameMachine(field string, t model.AccessTarget) error {
	sm := t.SameMachine
	if sm == nil {
		return nil
	}
	if sm.ServerKeyFP != t.ServerKeyFP {
		return schemaErr(field+".server_key_fp", "differs from the target's")
	}
	if sm.Gen < 1 || sm.Gen > t.Gen {
		return schemaErr(field+".gen", "%d is not between 1 and the target's gen %d", sm.Gen, t.Gen)
	}
	if n := len(sm.HostItemIDs); n < 1 || n > AccessMaxSameMachine {
		return schemaErr(field+".host_item_ids", "has %d entries, want 1 to %d", n, AccessMaxSameMachine)
	}
	for i, id := range sm.HostItemIDs {
		if err := CheckID(fmt.Sprintf("%s.host_item_ids[%d]", field, i), id); err != nil {
			return err
		}
		if id == t.HostItemID {
			return schemaErr(field+".host_item_ids", "names the target's own host")
		}
		if i > 0 && string(sm.HostItemIDs[i-1][:]) >= string(id[:]) {
			return schemaErr(field+".host_item_ids", "not sorted ascending without duplicates")
		}
	}
	switch t.State {
	case model.AccessRemoving, model.AccessRemoved, model.AccessAbandoned:
		return nil
	}
	return schemaErr(field, "is set on a %s target", t.State)
}
