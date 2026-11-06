package access

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The binding parse fixtures (spec rev 17, §8.4, an implementation gate):
// -vv -E logs of real connections, recorded on a leased VM by
// scripts/access-fixtures/run.sh (TestSSHDBindingLogs). Each directory
// testdata/openssh-VERSION-SYSTEM holds one OpenSSH version's logs and the host
// keys of the run (pins: target, jump1, jump2). For every log the parse
// binds to the target's key, given every pin; it binds to nothing given
// only the jump hosts' pins; no jump host's fingerprint is in the file;
// and the log cut short binds to nothing.
func TestBoundKeyRecordedLogs(t *testing.T) {
	dirs, _ := filepath.Glob(filepath.Join("testdata", "openssh-*"))
	if len(dirs) == 0 {
		t.Fatal("no recorded OpenSSH logs in testdata")
	}
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(dir, "pins"))
			if err != nil {
				t.Fatal(err)
			}
			pins := map[string]ssh.PublicKey{}
			for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				name, key, _ := strings.Cut(l, " ")
				k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
				if err != nil {
					t.Fatalf("pin %s: %v", name, err)
				}
				pins[name] = k
			}
			target, j1, j2 := pins["target"], pins["jump1"], pins["jump2"]
			if target == nil || j1 == nil || j2 == nil {
				t.Fatalf("pins: %v", pins)
			}
			all := []ssh.PublicKey{j1, j2, target}
			logs, _ := filepath.Glob(filepath.Join(dir, "*.log"))
			// direct, one jump and two jumps, through hop and through
			// ProxyJump, and a rekey
			if len(logs) < 6 {
				t.Fatalf("%d logs", len(logs))
			}
			for _, p := range logs {
				name := filepath.Base(p)
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				log := string(b)
				if k, err := BoundKey(log, true, all); err != nil || !bytes.Equal(k.Marshal(), target.Marshal()) {
					t.Errorf("%s: doesn't bind to the target: %v", name, err)
				}
				if _, err := BoundKey(log, true, []ssh.PublicKey{j1, j2}); err == nil {
					t.Errorf("%s: binds to a jump host", name)
				}
				for _, j := range []ssh.PublicKey{j1, j2} {
					if strings.Contains(log, ssh.FingerprintSHA256(j)) {
						t.Errorf("%s: names a jump host's key", name)
					}
				}
				if _, err := BoundKey(log[:len(log)-1], true, all); err == nil {
					t.Errorf("%s: binds when cut short", name)
				}
				if _, err := BoundKey(log, false, all); err == nil {
					t.Errorf("%s: binds when ssh failed", name)
				}
				if strings.Contains(name, "rekey") && strings.Count(log, "SSH2_MSG_NEWKEYS received") < 2 {
					t.Errorf("%s: no rekey in it", name)
				}
			}
		})
	}
}
