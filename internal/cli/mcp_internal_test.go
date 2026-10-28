package cli

import (
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
)

// A hidden name is masked where it stands as a whole host token: next to
// ':', brackets, spaces or a sentence's last '.', but not inside a longer
// name or address, of an allowed host or any other.
func TestMaskerHidesWholeHostTokens(t *testing.T) {
	l := &daemon.ListResult{Hosts: []model.Host{
		{Header: model.Header{ItemID: model.ID{1}}, Name: "db", AgentAccess: "deny", Addresses: []string{"10.0.0.1"}},
		{Header: model.Header{ItemID: model.ID{2}}, Name: "web", AgentAccess: "allow", Aliases: []string{"db.prod.example"}, Addresses: []string{"10.0.0.10"}},
	}}
	m := (&mcpServer{}).masker(l)
	for in, want := range map[string]string{
		"ssh: connect to host db.prod.example port 22": "ssh: connect to host db.prod.example port 22",
		"db:5432 refused":                                "<hidden host>:5432 refused",
		"through the jump host db.":                      "through the jump host <hidden host>.",
		"DB, then db-2 and x.db":                         "<hidden host>, then db-2 and x.db",
		"10.0.0.1:22 and 10.0.0.10:22":                   "<hidden host>:22 and 10.0.0.10:22",
		"[10.0.0.1]:22 is 10.0.0.1.":                     "[<hidden host>]:22 is <hidden host>.",
		"connect to host 10.0.0.1 port 22: refused (db)": "connect to host <hidden host> port 22: refused (<hidden host>)",
	} {
		if got := m.hide(in); got != want {
			t.Errorf("hide(%q) = %q, want %q", in, got, want)
		}
	}
}

// Private key blocks are found before secrets are replaced and names
// hidden: a secret "-" or a hidden host named PRIVATE would otherwise break
// the BEGIN and END lines, and the body would pass.
func TestRedactFindsKeysFirst(t *testing.T) {
	const key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBkZXBsb3kta2V5LWJvZHktZm9yLXRoZS10ZXN0AAAAAAAAAA==\n-----END OPENSSH PRIVATE KEY-----\n"
	const body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ"
	cut := key[len("-----BEGIN OPENSSH PRIVATE KEY-----\n"):] // the tail lost the BEGIN line
	l := &daemon.ListResult{Hosts: []model.Host{{Header: model.Header{ItemID: model.ID{1}}, Name: "PRIVATE", AgentAccess: "deny"}}}
	for _, secrets := range [][]string{{"-"}, {"KEY", "BEGIN", "-----"}, {"OPENSSH PRIVATE"}} {
		s := &mcpServer{secrets: secrets}
		m := s.masker(l)
		for _, text := range []string{key, "out: " + key + "more", cut, cut + key} {
			for name, got := range map[string]string{"redact": s.redact(text), "hide": m.hide(text), "audit": s.auditText(text)} {
				if strings.Contains(got, body) {
					t.Errorf("%s with secrets %q kept the key body: %q", name, secrets, got)
				}
			}
		}
	}
}
