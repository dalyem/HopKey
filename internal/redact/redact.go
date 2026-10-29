// Package redact finds secrets in text that hop mcp hands to an agent: the
// values hop holds (Literals), which the daemon looks for in the vault's
// secrets and hop mcp in its own, and well-known token formats hop never
// saw (Patterns). It only finds them. The caller replaces every Hit in one
// pass over the text, so that no replacement breaks up a secret another one
// overlaps.
//
// None of this applies to what a person runs: hop exec, hop <target> and
// ssh show the remote's output as it is.
package redact

import (
	"strings"
)

// Hit is a stretch of text to replace: bytes Lo to Hi, and the kind of
// secret found there, which the replacement names (Marker).
type Hit struct {
	Lo   int    `json:"lo"`
	Hi   int    `json:"hi"`
	Kind string `json:"kind"`
}

// Secret is a value to look for verbatim, and its kind.
type Secret struct {
	Kind  string
	Value string
}

// Kinds of what hop holds. The pattern kinds are in patterns.go.
const (
	KindHopSecret        = "hop-secret"         // hop mcp's own: the hop auth values and the device key passphrase
	KindPrivateKey       = "private-key"        // a private key block, from any source
	KindVaultPrivateKey  = "vault-private-key"  // a vault key's private half, or a line of it
	KindVaultPassword    = "vault-password"     // a vault credential's password
	KindVaultSecretKey   = "vault-secret-key"   // the account Secret Key
	KindVaultRecoveryKey = "vault-recovery-key" // the Recovery Key of a kit not yet confirmed
	KindVaultDeviceKey   = "vault-device-key"   // this device's own key material
)

// Marker is what stands where a secret of kind was.
func Marker(kind string) string { return "[redacted by hop: " + kind + "]" }

// Rank orders kinds for a stretch where hits of several kinds overlap and
// are replaced as one: the lowest rank names it. A key block comes first,
// then what hop holds, then the formats it guesses at.
func Rank(kind string) int {
	switch {
	case kind == KindPrivateKey:
		return 0
	case strings.HasPrefix(kind, "vault-"):
		return 1
	case kind == KindHopSecret:
		return 2
	case kind == KindSecretValue:
		return 4
	}
	return 3
}

// The marks hop mcp puts around text the agent typed. They are taken out
// of the text before it is searched, so a secret holding one is looked for
// without it too (Literals).
const (
	MarkOpen  = ""
	MarkClose = ""
)

// Unmark removes the marks from s.
var Unmark = strings.NewReplacer(MarkOpen, "", MarkClose, "")

// Literals is every place a secret's value stands in t, left to right per
// secret, overlapping ones included: in "abababa" the value "ababa" stands
// at 0 and at 2, and the caller joins the two, where taking only the first
// would leave "ba". t has had the marks taken out, so a value holding a
// mark is looked for as it stands there too. Every non-empty value counts,
// however short.
func Literals(t string, secrets []Secret) []Hit {
	var out []Hit
	for _, s := range secrets {
		vs := []string{s.Value}
		if u := Unmark.Replace(s.Value); u != s.Value {
			vs = append(vs, u)
		}
		for _, v := range vs {
			if v == "" {
				continue
			}
			for i := 0; ; {
				j := strings.Index(t[i:], v)
				if j < 0 {
					break
				}
				out = append(out, Hit{Lo: i + j, Hi: i + j + len(v), Kind: s.Kind})
				i += j + 1
			}
		}
	}
	return out
}
