package access

import (
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ErrUnbound is the preflight's refusal (crypto spec rev 17, §7.6): hop
// can't tell which pinned key the server presented. Nothing is committed.
var ErrUnbound = errors.New("hop can't tell which pinned key the server presented")

// hostKeyMarker is the text that makes a log line a key line, wherever it
// appears in the line.
const hostKeyMarker = "Server host key:"

// BoundKey reads the -vv -E log of a preflight connection and returns the
// pin the server presented, failing closed (§7.6, N3):
//
//   - every line that contains "Server host key:" anywhere is a key line,
//     and must be exactly "debug1: Server host key: TYPE SHA256:FP" with
//     43 base64 characters and nothing after them (one trailing CR, which
//     OpenSSH's log writes, is removed first);
//   - there is at least one, and every one names the same type and
//     fingerprint (a rekey logs the key again);
//   - that fingerprint is one of pins', a plain key of that type (a host
//     certificate never is);
//   - ssh exited on its own with status 0, and the log ends in a complete
//     line.
//
// Anything else is ErrUnbound. A server can put text with a newline into
// the log, so no prefix proves a line is ssh's own; with
// StrictHostKeyChecking and only the pins known, the connection succeeded
// against a pin anyway, and this only selects which one.
//
// The format is OpenSSH's. It is tested against the log of OpenSSH 9.2p1
// (Debian 12, the check image's client, and a fixture in the tests); other
// versions are untested. A version that logs the key differently fails
// closed: the target isn't added.
func BoundKey(log string, exited0 bool, pins []ssh.PublicKey) (ssh.PublicKey, error) {
	if !exited0 || !strings.HasSuffix(log, "\n") {
		return nil, ErrUnbound
	}
	var typ, fp string
	for _, l := range strings.Split(strings.TrimSuffix(log, "\n"), "\n") {
		l = strings.TrimSuffix(l, "\r")
		if !strings.Contains(l, hostKeyMarker) {
			continue
		}
		rest, ok := strings.CutPrefix(l, "debug1: "+hostKeyMarker+" ")
		if !ok {
			return nil, ErrUnbound
		}
		t, f, ok := strings.Cut(rest, " ")
		if !ok || t == "" || strings.ContainsAny(f, " \t") || !isFingerprint(f) {
			return nil, ErrUnbound
		}
		if typ != "" && (t != typ || f != fp) {
			return nil, ErrUnbound
		}
		typ, fp = t, f
	}
	if fp == "" || strings.Contains(typ, "-cert-") {
		return nil, ErrUnbound
	}
	for _, p := range pins {
		if _, cert := p.(*ssh.Certificate); !cert && p.Type() == typ && ssh.FingerprintSHA256(p) == fp {
			return p, nil
		}
	}
	return nil, ErrUnbound
}

func isFingerprint(s string) bool {
	b, ok := strings.CutPrefix(s, "SHA256:")
	if !ok || len(b) != 43 {
		return false
	}
	_, err := rawStd.DecodeString(b)
	return err == nil
}
