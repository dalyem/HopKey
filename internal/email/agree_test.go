package email_test

import (
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/email"
	"github.com/dalyem/hopkey/internal/store"
)

// The store still has its own copy of the R4 rules. Until it uses this
// package, both must accept the same addresses and normalize them to the
// same bytes, or a client would sign a proof for an email the server
// spells differently.
func TestStoreAgrees(t *testing.T) {
	for _, in := range []string{
		"alice@example.com",
		" \tAlice.B+tag@EXAMPLE.Com\t ",
		"a!#$%&'*+-/=?^_`{|}~@x.io",
		"u@xn--bcher-kva.example",
		"u@XN--BCHER-KVA.example",
		"u@localhost",
		"Me@Example.COM",
		strings.Repeat("l", 64) + "@example.com",
		strings.Repeat("l", 65) + "@example.com",
		"a@" + strings.Repeat("x", 63) + ".com",
		"a@" + strings.Repeat("x", 64) + ".com",
		"a@" + strings.Repeat(strings.Repeat("x", 60)+".", 4) + "com",
		"a@" + strings.Repeat(strings.Repeat("x", 60)+".", 5) + "com",
		strings.Repeat("l", 64) + "@" + strings.Repeat(strings.Repeat("x", 62)+".", 3) + "com",
		strings.Repeat("l", 64) + "@" + strings.Repeat(strings.Repeat("x", 62)+".", 3) + "comm",
		"", " ", "@", "@example.com", "alice@", "alice", "a@@example.com", "a@b@example.com",
		`"a b"@example.com`, `"a"@example.com`, "a@[127.0.0.1]", ".a@example.com", "a.@example.com",
		"a..b@example.com", "a b@example.com", "a@exa mple.com", "a\n@example.com", "a@example.com\n",
		"a\x7f@example.com", "a\x00@example.com", "ä@example.com", "a@exämple.com", "a@-example.com",
		"a@example-.com", "a@example..com", "a@example.com.", "a@.example.com", "a@ex_ample.com",
		"a(b)@example.com", "a,b@example.com", "a;b@example.com", "a\\b@example.com",
		" a@example.com", "a@example.com ", "\r\na@example.com", "\ta@example.com\t",
		"A@B", "a@1.2.3.4", "a@xn--", "a@x-y.z", "a@" + strings.Repeat("x", 63),
	} {
		got, err := email.Normalize(in)
		sgot, serr := store.NormalizeEmail(in)
		if (err == nil) != (serr == nil) || got != sgot {
			t.Errorf("%q: email.Normalize = %q, %v; store.NormalizeEmail = %q, %v", in, got, err, sgot, serr)
		}
	}
}
