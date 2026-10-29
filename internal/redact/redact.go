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
	"slices"
	"strings"
)

// MinKeyLine is the shortest line of a private key's body looked for on
// its own: the last line of a block can be a few characters, which would
// match ordinary text.
const MinKeyLine = 16

// PrivateKeyForms is a vault key's private half as a remote may print it:
// whole, its body without line breaks, and each body line long enough to
// stand alone (MinKeyLine).
func PrivateKeyForms(privateKey string) []Secret {
	if privateKey == "" {
		return nil
	}
	out := []Secret{{Kind: KindVaultPrivateKey, Value: privateKey}}
	var body []string
	for _, l := range strings.Split(strings.ReplaceAll(privateKey, "\r\n", "\n"), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "-----") {
			continue
		}
		body = append(body, l)
		if len(l) >= MinKeyLine {
			out = append(out, Secret{Kind: KindVaultPrivateKey, Value: l})
		}
	}
	if joined := strings.Join(body, ""); len(joined) >= MinKeyLine {
		out = append(out, Secret{Kind: KindVaultPrivateKey, Value: joined})
	}
	return out
}

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
	KindVaultAccountKey  = "vault-account-key"  // the account's private keys and the vault key
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

// Before reports whether kind a names a stretch where hits of kinds a and
// b overlap: the lower rank, and between kinds of one rank the first by
// name, so that the same text is always named the same way whatever order
// its hits were found in.
func Before(a, b string) bool {
	if ra, rb := Rank(a), Rank(b); ra != rb {
		return ra < rb
	}
	return a < b
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
// mark is looked for as it stands there too. So is each form a program
// that escapes what it prints may show it in (Escaped): ssh, say, prints
// a server's message with a backslash doubled. A hit covers the form as
// it stands in t. Every non-empty value counts, however short.
func Literals(t string, secrets []Secret) []Hit { return Prepare(secrets).Find(t) }

// Matcher is secrets with the forms Literals looks for worked out once,
// for looking in many texts: one request's, or every answer of a process.
type Matcher struct {
	forms   []Secret // each form of each secret, in order, with its kind
	longest int
}

// Prepare works out the forms of secrets that Literals looks for.
func Prepare(secrets []Secret) Matcher {
	var m Matcher
	for _, s := range secrets {
		vs := []string{s.Value}
		if u := Unmark.Replace(s.Value); u != s.Value {
			vs = append(vs, u)
		}
		for _, v := range vs {
			for _, e := range Escaped(v) {
				if !slices.Contains(vs, e) {
					vs = append(vs, e)
				}
			}
		}
		for _, v := range vs {
			if v != "" {
				m.forms = append(m.forms, Secret{Kind: s.Kind, Value: v})
				m.longest = max(m.longest, len(v))
			}
		}
	}
	return m
}

// Longest is the length of the longest form m looks for: a stretch of
// text that holds none of them whole cannot gain one but within this many
// bytes of a change.
func (m Matcher) Longest() int { return m.longest }

// Find is Literals for the secrets m was prepared from.
func (m Matcher) Find(t string) []Hit {
	var out []Hit
	for _, f := range m.forms {
		for i := 0; ; {
			j := strings.Index(t[i:], f.Value)
			if j < 0 {
				break
			}
			out = append(out, Hit{Lo: i + j, Hi: i + j + len(f.Value), Kind: f.Kind})
			i += j + 1
		}
	}
	return out
}
