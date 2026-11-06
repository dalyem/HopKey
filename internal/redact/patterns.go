package redact

import (
	"regexp"
	"strings"
)

// Kinds of the formats Patterns finds.
const (
	KindAWSAccessKeyID = "aws-access-key-id"
	KindAWSSecretKey   = "aws-secret-key"
	KindGitHubToken    = "github-token"
	KindGitLabToken    = "gitlab-token"
	KindSlackToken     = "slack-token"
	KindStripeKey      = "stripe-key"
	KindGoogleAPIKey   = "google-api-key"
	KindJWT            = "jwt"
	KindAuthorization  = "authorization"
	KindURLPassword    = "url-password"
	// KindSecretValue is the value of a key=value, key: value or JSON
	// member whose key names a secret (secretKey).
	KindSecretValue = "secret-value"
)

// A token is a run of tokenByte: a format below matches only a whole one,
// so that it is not found inside a longer word.
func tokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// tokenFormats are the prefixed formats services issue tokens in. Each is
// matched only as a whole token.
var tokenFormats = []struct {
	kind string
	re   *regexp.Regexp
}{
	{KindAWSAccessKeyID, regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA|AROA|AIDA|AGPA|ANPA|ANVA|APKA)[0-9A-Z]{16}`)},
	{KindGitHubToken, regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,255}|github_pat_[0-9A-Za-z_]{22,255}`)},
	{KindGitLabToken, regexp.MustCompile(`glpat-[0-9A-Za-z_\-]{20,}`)},
	{KindSlackToken, regexp.MustCompile(`xox[abprs]-[0-9A-Za-z\-]{10,}`)},
	{KindStripeKey, regexp.MustCompile(`(?:sk|rk)_live_[0-9A-Za-z]{16,}`)},
	{KindGoogleAPIKey, regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	// A JWT: a header and a payload that are JSON objects (eyJ is how
	// base64url writes `{"`), and a signature.
	{KindJWT, regexp.MustCompile(`eyJ[0-9A-Za-z_\-]{5,}\.eyJ[0-9A-Za-z_\-]{5,}\.[0-9A-Za-z_\-]{8,}`)},
}

// valueFormats find a secret by what stands before it; group 1 is the
// secret.
var valueFormats = []struct {
	kind string
	re   *regexp.Regexp
}{
	{KindAWSSecretKey, regexp.MustCompile(`(?i)aws_?secret_?access_?key[0-9a-z_.\-]*["']?[ \t]*[:=][ \t]*["']?([0-9A-Za-z/+=]{40})`)},
	{KindAuthorization, regexp.MustCompile(`(?i)\bauthorization["']?[ \t]*[:=][ \t]*["']?(?:bearer|basic|token)[ \t]+([0-9A-Za-z\-._~+/]+=*)`)},
	// scheme://user:password@: the password goes, the user stays.
	{KindURLPassword, regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/?#@'"]+:([^\s/?#@'"]+)@`)},
}

// The forms of a key and its value. Group 1 is the key, group 2 the value,
// quotes and all; only what is inside the quotes goes.
var (
	// KEY=value, as in an environment, a .env file, a shell line, a
	// command's --flag=value or a URL's query.
	assignRe = regexp.MustCompile(`(?:^|[\s;'"(,{?&])(-{0,2}[A-Za-z_][A-Za-z0-9_.\-]*)=("[^"\n]*"|'[^'\n]*'|[^\s'"&;|,)}]+)`)
	// key: value at the start of a line, as in YAML or a config file: the
	// value is the rest of the line. The key may be words ("DB password").
	lineRe = regexp.MustCompile(`(?m)^[ \t]*(?:-[ \t]+)?([A-Za-z_][A-Za-z0-9_.\-]*(?: [A-Za-z0-9_.\-]+){0,3})[ \t]*:[ \t]+(\S[^\n]*?)[ \t]*$`)
	// key: value elsewhere in a line, as in a header: one word of value.
	inlineRe = regexp.MustCompile(`(?:^|[\s,;({])([A-Za-z_][A-Za-z0-9_.\-]*)[ \t]*:[ \t]+("[^"\n]*"|'[^'\n]*'|[^\s"',;)}]+)`)
	// "key": "value" in JSON, or 'key': 'value' as Python prints a dict.
	jsonRe   = regexp.MustCompile(`"([^"\\\n]{1,64})"[ \t]*:[ \t]*("(?:[^"\\\n]|\\.)*")`)
	pyDictRe = regexp.MustCompile(`'([^'\\\n]{1,64})'[ \t]*:[ \t]*('(?:[^'\\\n]|\\.)*')`)
)

// Patterns finds the secrets in t that have a well-known form: tokens in a
// service's prefixed format (AWS access key IDs, GitHub, GitLab, Slack,
// Stripe and Google keys, JWTs), an AWS secret access key, an
// Authorization header's credentials, a URL's password, and the value of a
// key whose name says it is secret. It does not guess at random-looking
// strings: a checksum, a commit or an ID looks the same as a key, and would
// be redacted too.
func Patterns(t string) []Hit {
	var out []Hit
	for _, f := range tokenFormats {
		for _, m := range f.re.FindAllStringIndex(t, -1) {
			if (m[0] > 0 && tokenByte(t[m[0]-1])) || (m[1] < len(t) && tokenByte(t[m[1]])) {
				continue
			}
			out = append(out, Hit{Lo: m[0], Hi: m[1], Kind: f.kind})
		}
	}
	for _, f := range valueFormats {
		for _, m := range f.re.FindAllStringSubmatchIndex(t, -1) {
			out = append(out, Hit{Lo: m[2], Hi: m[3], Kind: f.kind})
		}
	}
	for _, re := range []*regexp.Regexp{assignRe, lineRe, inlineRe, jsonRe, pyDictRe} {
		for _, m := range re.FindAllStringSubmatchIndex(t, -1) {
			if !secretKey(t[m[2]:m[3]]) {
				continue
			}
			lo, hi := m[4], m[5]
			if v := t[lo:hi]; len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
				lo, hi = lo+1, hi-1
			}
			if v := t[lo:hi]; v == "" || blockScalar[v] {
				continue
			}
			out = append(out, Hit{Lo: lo, Hi: hi, Kind: KindSecretValue})
		}
	}
	return out
}

// blockScalar is a YAML value that says the value follows on the next
// lines, which this does not follow.
var blockScalar = map[string]bool{"|": true, "|-": true, "|+": true, ">": true, ">-": true, ">+": true}

// secretWords name a secret in a key: as a word of it (DB_PASSWORD,
// dbPassword, "db password"), or, for the two-word ones, as two words in a
// row (API_KEY, apiKey, x-api-key).
var (
	secretWords = map[string]bool{"password": true, "passwd": true, "passphrase": true, "secret": true, "token": true,
		"apikey": true, "accesskey": true, "privatekey": true}
	secretPairs = map[[2]string]bool{{"api", "key"}: true, {"access", "key"}: true, {"private", "key"}: true}
	// notSecret, after the secret word, makes the key about the secret
	// rather than the secret itself: password_file, token_type, secret_name.
	notSecret = map[string]bool{"type": true, "file": true, "path": true, "dir": true, "url": true, "uri": true,
		"endpoint": true, "name": true, "count": true, "length": true, "len": true, "size": true, "ttl": true,
		"expiry": true, "expires": true, "expiration": true, "lifetime": true, "policy": true, "prompt": true,
		"required": true, "enabled": true, "hint": true, "label": true, "format": true, "version": true,
		"algorithm": true, "method": true, "header": true, "env": true, "var": true}
)

// secretKey reports whether key names a secret (secretWords), and nothing
// after that word says it names something about one (notSecret).
func secretKey(key string) bool {
	words := keyWords(strings.TrimLeft(key, "-"))
	at := -1
	for i, w := range words {
		if secretWords[w] {
			at = i
		}
		if i > 0 && secretPairs[[2]string{words[i-1], w}] {
			at = i
		}
	}
	if at < 0 {
		return false
	}
	for _, w := range words[at+1:] {
		if notSecret[w] {
			return false
		}
	}
	return true
}

// keyWords splits a key into lowercase words at '_', '.', '-' and spaces,
// and where camel case starts a word: dbPassword, APIKey.
func keyWords(key string) []string {
	var out []string
	var cur []byte
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	upper := func(c byte) bool { return c >= 'A' && c <= 'Z' }
	lower := func(c byte) bool { return c >= 'a' && c <= 'z' }
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c == '_' || c == '.' || c == '-' || c == ' ':
			flush()
			continue
		case upper(c) && i > 0 && (lower(key[i-1]) || upper(key[i-1]) && i+1 < len(key) && lower(key[i+1])):
			flush()
		}
		cur = append(cur, c)
	}
	flush()
	return out
}
