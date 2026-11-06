package email

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	ok := map[string]string{
		"alice@example.com":                      "alice@example.com",
		" \tAlice.B+tag@EXAMPLE.Com\t ":          "Alice.B+tag@example.com",
		"a!#$%&'*+-/=?^_`{|}~@x.io":              "a!#$%&'*+-/=?^_`{|}~@x.io",
		"u@xn--bcher-kva.example":                "u@xn--bcher-kva.example",
		"u@localhost":                            "u@localhost",
		strings.Repeat("l", 64) + "@example.com": strings.Repeat("l", 64) + "@example.com",
	}
	for in, want := range ok {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "@example.com", "alice@", "alice", "a@@example.com", "a@b@example.com",
		`"a b"@example.com`, "a@[127.0.0.1]", ".a@example.com", "a.@example.com", "a..b@example.com",
		"a b@example.com", "a@exa mple.com", "a\n@example.com", "a@example.com\n", "a\x7f@example.com",
		"ä@example.com", "a@exämple.com", "a@-example.com", "a@example-.com", "a@example..com", "a@example.com.",
		"a@ex_ample.com", "a(b)@example.com", "a,b@example.com",
		strings.Repeat("l", 65) + "@example.com",
		"a@" + strings.Repeat("x", 64) + ".com",
		"a@" + strings.Repeat(strings.Repeat("x", 60)+".", 5) + "com",
		" a@example.com",
	} {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q, want an error", in, got)
		}
	}
}
