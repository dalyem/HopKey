package redact

import (
	"slices"
	"strings"
	"testing"
)

// found is what would be replaced of t for what Patterns finds: hits that
// overlap joined, as hop mcp joins them, each named for the kind that
// ranks first.
func found(t string) []string {
	hits := Patterns(t)
	slices.SortFunc(hits, func(a, b Hit) int { return a.Lo - b.Lo })
	var out []string
	for i := 0; i < len(hits); {
		lo, hi, kind := hits[i].Lo, hits[i].Hi, hits[i].Kind
		for i++; i < len(hits) && hits[i].Lo < hi; i++ {
			hi = max(hi, hits[i].Hi)
			if Rank(hits[i].Kind) < Rank(kind) {
				kind = hits[i].Kind
			}
		}
		out = append(out, kind+"="+t[lo:hi])
	}
	slices.Sort(out)
	return out
}

func TestPatternsFind(t *testing.T) {
	for _, c := range []struct {
		text string
		want []string
	}{
		// AWS.
		{"key AKIAIOSFODNN7EXAMPLE in use", []string{"aws-access-key-id=AKIAIOSFODNN7EXAMPLE"}},
		{"ASIAY34FZKBOKMUTVV7A", []string{"aws-access-key-id=ASIAY34FZKBOKMUTVV7A"}},
		{"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", []string{"aws-secret-key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}},
		// The key=value form finds it too; the AWS kind names it.
		{"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", []string{"aws-secret-key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}},
		// GitHub, GitLab, Slack, Stripe, Google.
		{"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", []string{"github-token=ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}},
		{"(gho_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8)", []string{"github-token=gho_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}},
		{"ghu_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8 ghs_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8 ghr_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", []string{
			"github-token=ghr_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "github-token=ghs_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "github-token=ghu_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}},
		{"github_pat_11ABCDEFG0123456789_abcdefghijABCDEFGHIJ", []string{"github-token=github_pat_11ABCDEFG0123456789_abcdefghijABCDEFGHIJ"}},
		{"glpat-" + "xxxxXXXX1234567890ab", []string{"gitlab-token=glpat-" + "xxxxXXXX1234567890ab"}},
		{"xoxb-1234567890-0987654321-AbCdEfGhIjKl", []string{"slack-token=xoxb-1234567890-0987654321-AbCdEfGhIjKl"}},
		{"xoxp-1234567890-abc", []string{"slack-token=xoxp-1234567890-abc"}},
		{"sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc", []string{"stripe-key=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"}},
		{"rk_live_" + "4eC39HqLyjWDarjtT1zdp7dc", []string{"stripe-key=rk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"}},
		{"AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY", []string{"google-api-key=AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"}},
		// A JWT.
		{"id eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U end", []string{
			"jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}},
		// Authorization headers: the credentials go, the scheme stays.
		{"Authorization: Bearer abc.def-ghi_jkl", []string{"authorization=abc.def-ghi_jkl"}},
		{`curl -H "authorization: basic dXNlcjpwYXNz"`, []string{"authorization=dXNlcjpwYXNz"}},
		// A URL's password, not its user.
		{"postgres://app:s3cr3t-pw@db.internal:5432/x", []string{"url-password=s3cr3t-pw"}},
		{"git clone https://deploy:hunter2@git.example.com/r.git", []string{"url-password=hunter2"}},
		// key=value, key: value and JSON, by the key's name.
		{"DB_PASSWORD=hunter2", []string{"secret-value=hunter2"}},
		{"export GITHUB_TOKEN='abc def'", []string{"secret-value=abc def"}},
		{`API_KEY="k-123"`, []string{"secret-value=k-123"}},
		{"mysql --password=hunter2 -u root", []string{"secret-value=hunter2"}},
		{"GET /cb?access_token=abc123&state=x", []string{"secret-value=abc123"}},
		{"password: correct horse battery", []string{"secret-value=correct horse battery"}},
		{"  client_secret: 'quoted value'", []string{"secret-value=quoted value"}},
		{"- privateKey: zzz", []string{"secret-value=zzz"}},
		{"DB Password: hunter2", []string{"secret-value=hunter2"}},
		{"X-Api-Key: abc123", []string{"secret-value=abc123"}},
		{"ts=1 level=info token: abc123 path=/", []string{"secret-value=abc123"}},
		{`{"user": "u", "password": "p\"w"}`, []string{`secret-value=p\"w`}},
		{`{'apiKey': 'abc'}`, []string{"secret-value=abc"}},
		{"passwd=x apikey=y accessKey=z SECRET=w passphrase=v", []string{
			"secret-value=v", "secret-value=w", "secret-value=x", "secret-value=y", "secret-value=z"}},
	} {
		if got := found(c.text); !slices.Equal(got, c.want) {
			t.Errorf("Patterns(%q) = %q, want %q", c.text, got, c.want)
		}
	}
}

// Near misses: what looks random, or names a secret without holding one.
func TestPatternsLeaveAlone(t *testing.T) {
	for _, text := range []string{
		"commit 3f786850e387550fdab836ed7e6dc881de23001b",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty.txt",
		"sha512: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		"id 123e4567-e89b-12d3-a456-426614174000",
		"SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
		"AKIA1234",                         // too short
		"XAKIAIOSFODNN7EXAMPLE",            // inside a longer word
		"ghp_short",                        // too short
		"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4", // 32 characters
		// a test key
		"sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
		"xoxb-123",
		"eyJhbGciOiJIUzI1NiJ9 alone",
		"ssh://git@github.com/org/repo.git",
		"https://example.com:8443/path",
		"http://user@host/",
		"Password:",
		"Enter password: ",
		"password=",
		"max_tokens=1024",
		"tokens: 3",
		"password_file=/etc/app/pw",
		"token_type: bearer",
		`{"token_expires": "3600", "secret_name": "db"}`,
		"TOKEN_PATH=/run/secrets/x",
		"passwordless sudo is on",
		"root:x:0:0:root:/root:/bin/bash",
		"Authorization: none given",
		"password: |",
	} {
		if got := found(text); len(got) > 0 {
			t.Errorf("Patterns(%q) = %q, want nothing", text, got)
		}
	}
}

func TestLiterals(t *testing.T) {
	s := []Secret{{Kind: "k", Value: "ababa"}, {Kind: "m", Value: "x" + MarkOpen + "y"}, {Kind: "e", Value: ""}}
	got := Literals("abababa xy", s)
	want := []Hit{{0, 5, "k"}, {2, 7, "k"}, {8, 10, "m"}}
	if !slices.Equal(got, want) {
		t.Errorf("Literals = %v, want %v", got, want)
	}
}

// A secret stands escaped in text that programs quote: Go's %q, JSON,
// and OpenSSH's client printing a server's message (through its log) or
// banner (in a C and in a UTF-8 locale). Literals finds each form whole.
func TestLiteralsFindEscapedForms(t *testing.T) {
	v := `a\b"c<` + "\t\x01\u00e9"
	secrets := []Secret{{Kind: KindVaultPassword, Value: v}}
	for name, form := range map[string]string{
		"raw":              v,
		"go %q":            `a\\b\"c<\t\x01` + "\u00e9",
		"json":             `a\\b\"c<\t\u0001` + "\u00e9",
		"json html":        `a\\b\"c\u003c\t\u0001` + "\u00e9",
		"ssh log":          `a\\b"c<` + "\t" + `\001\303\251`,
		"ssh banner":       `a\b"c<` + "\t" + `\001\303\251`,
		"ssh banner utf-8": `a\b"c<` + "\t" + `\001` + "\u00e9",
	} {
		text := "x " + form + " y"
		hits := Literals(text, secrets)
		if !slices.ContainsFunc(hits, func(h Hit) bool { return h.Lo <= 2 && 2+len(form) <= h.Hi }) {
			t.Errorf("%s: Literals(%q) = %v, want %q covered", name, text, hits, form)
		}
	}
}

// Escaped lists each form once, and only forms that differ from the
// value. The OpenSSH forms are what the 9.2 client prints: a disconnect
// message through its log, a banner in a C and in a UTF-8 locale.
func TestEscaped(t *testing.T) {
	for _, c := range []struct {
		v    string
		want []string
	}{
		{"", nil},
		{"hunter2-credential-password", nil},
		{`a\b"c`, []string{`a\\b\"c`, `a\\b"c`}},
		{"<\u00e9>", []string{`\u003c` + "\u00e9" + `\u003e`, `<\303\251>`}},
		{"a\tb\x01\n\a", []string{`a\tb\x01\n\a`, `a\tb\u0001\n\u0007`, "a\tb\\001\n\a", "a\tb\\001\n\\007"}},
		{"\u2028\xff", []string{`\u2028\xff`, `\u2028` + "\ufffd", `\342\200\250\377`}}, // encoding/json writes a bad byte as U+FFFD
		{"\u00a0\u200b", []string{`\u00a0\u200b`, `\302\240\342\200\213`}},
	} {
		if got := Escaped(c.v); !slices.Equal(got, c.want) {
			t.Errorf("Escaped(%q) = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestKeyWords(t *testing.T) {
	for in, want := range map[string]string{
		"DB_PASSWORD": "db password", "dbPassword": "db password", "APIKey": "api key", "x-api-key": "x api key",
		"client.secret": "client secret", "DB Password": "db password", "--password": "password",
	} {
		if got := strings.Join(keyWords(strings.TrimLeft(in, "-")), " "); got != want {
			t.Errorf("keyWords(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRank(t *testing.T) {
	order := []string{KindPrivateKey, KindVaultPassword, KindHopSecret, KindGitHubToken, KindSecretValue}
	for i := 1; i < len(order); i++ {
		if Rank(order[i-1]) >= Rank(order[i]) {
			t.Errorf("%s does not rank before %s", order[i-1], order[i])
		}
	}
}
