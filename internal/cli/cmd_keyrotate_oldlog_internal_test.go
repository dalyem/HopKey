package cli

import (
	"strings"
	"testing"
)

// The -vv log lines oldKeyVerdict reads, in OpenSSH 9.6's wording (the
// format strings in Ubuntu 24.04's ssh), with the \r\n ssh ends them with.
func TestOldKeyVerdictReadsTheSSHLog(t *testing.T) {
	const fp = "SHA256:Hq8mDn4mQyQnI1xg8qJ7zSxN0bHn2vH2rVfE0wNqv0Y"
	const other = "SHA256:otherotherotherotherotherotherotherotherot"
	lines := map[string]string{
		"proto":   "debug1: Remote protocol version 2.0, remote software version OpenSSH_9.6p1 Ubuntu-3ubuntu13",
		"auth":    "debug1: Authenticating to 203.0.113.10:2222 as 'deploy'",
		"offer":   "debug1: Offering public key: /run/hop/rotate-1/old/id ED25519 " + fp + " explicit agent",
		"offer2":  "debug1: Offering public key: /run/hop/rotate-1/old/id ED25519 " + other + " explicit agent",
		"accepts": "debug1: Server accepts key: /run/hop/rotate-1/old/id ED25519 " + fp + " explicit agent",
		"signerr": `debug1: sign_and_send_pubkey: signing failed for ED25519 "/run/hop/rotate-1/old/id" from agent: agent refused operation`,
		"nomore":  "debug1: No more authentication methods to try.",
		"denied":  "deploy@203.0.113.10: Permission denied (publickey).",
		"closed":  "kex_exchange_identification: Connection closed by remote host",
	}
	log := func(names ...string) string {
		var b strings.Builder
		for _, n := range names {
			b.WriteString(lines[n] + "\r\n")
		}
		return b.String()
	}
	for _, c := range []struct {
		name, log, want string
	}{
		{"refused", log("proto", "auth", "offer", "nomore", "denied"), ""},
		{"proxy failed", log("closed", "denied"), whyNotReached},
		{"another server", strings.Replace(log("proto", "auth", "offer", "denied"), ":2222 ", ":22 ", 1), "does not show a login to 203.0.113.10 port 2222"},
		{"another key offered", log("proto", "auth", "offer2", "denied"), "did not offer the old key"},
		{"nothing offered", log("proto", "auth", "nomore", "denied"), "did not offer the old key"},
		{"accepted, not signed", log("proto", "auth", "offer", "accepts", "signerr", "denied"), "could not sign"},
		{"accepted", log("proto", "auth", "offer", "accepts", "denied"), "still accepts the old key"},
		{"no refusal", log("proto", "auth", "offer"), "without the server refusing"},
		{"password prompt only", log("proto", "auth", "offer") + "Permission denied, please try again.\r\n", "without the server refusing"},
		{"the server's own debug message", log("proto", "auth", "offer") + "debug1: Remote: deploy@203.0.113.10: Permission denied (publickey).\r\n", "without the server refusing"},
		// Small wording differences: another debug level, other methods.
		{"other methods", strings.ReplaceAll(log("proto", "auth", "offer"), "debug1:", "debug2:") + "deploy@203.0.113.10: Permission denied (publickey,keyboard-interactive).\r\n", ""},
		// ssh logs the host name in lower case.
		{"host name", strings.Replace(log("proto", "auth", "offer", "denied"), "203.0.113.10", "web.example", 1), ""},
	} {
		addr := "203.0.113.10"
		if c.name == "host name" {
			addr = "Web.Example"
		}
		got := oldKeyVerdict(c.log, fp, addr, 2222)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
