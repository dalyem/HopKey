package cli_test

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/store"
)

// A local-only vault is not signed in, whether or not it is locked: the
// daemon's sync state says "locked", not "off", while it is.
func TestAuthStatusOnALockedLocalVaultIsNotSignedIn(t *testing.T) {
	m := newMachine(t, &authWorld{}, "solo")
	initS := &session{secrets: initSecrets()}
	if code := m.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	m.must(t, nil, "lock")
	if a := m.authStatus(t); a.SignedIn || !a.Locked {
		t.Errorf("auth status --json: %+v", a)
	}
	out := m.must(t, nil, "auth", "status")
	if !strings.Contains(out, "signed in:    no; this vault is local-only") {
		t.Errorf("auth status: %q", out)
	}
}

// A publication that is not finished is not an account yet, and says so,
// locked or not.
func TestAuthStatusWithAPendingPublicationIsNotSignedIn(t *testing.T) {
	w := newAuthWorld(t)
	m := newMachine(t, w, "pub")
	initS := &session{secrets: initSecrets()}
	if code := m.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	refuse := func(rw http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/v1/signup" {
			return false
		}
		http.Error(rw, "down", http.StatusInternalServerError)
		return true
	}
	w.hook.Store(&refuse)
	s := &session{}
	if code := m.hop(t, s, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t)); code == 0 {
		t.Fatal("signup succeeded against a server that refuses it")
	}
	for _, locked := range []bool{false, true} {
		if locked {
			m.must(t, nil, "lock")
		}
		var a struct {
			SignedIn   bool `json:"signed_in"`
			Publishing bool `json:"publishing"`
			Locked     bool `json:"locked"`
		}
		decodeJSON(t, m.must(t, nil, "auth", "status", "--json"), &a)
		if a.SignedIn || !a.Publishing || a.Locked != locked {
			t.Errorf("locked %v: auth status --json: %+v", locked, a)
		}
		out := m.must(t, nil, "auth", "status")
		if !strings.Contains(out, "signed in:    no; this vault is being published") || !strings.Contains(out, "not finished") {
			t.Errorf("locked %v: auth status: %q", locked, out)
		}
	}
}

// A device key file that is gone, or cut short, is not described as a
// healthy sealed one: hop status names the file and what to do, and the
// lock reason points at the fix.
func TestStatusSaysTheDeviceKeyFileIsMissingOrDamaged(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(path string) error
		want   string
	}{
		{"missing", os.Remove, "is missing"},
		{"truncated", func(path string) error { return os.WriteFile(path, []byte(`{"v":1,"kdf_ver`), 0o600) }, "is damaged"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := sealedLocal(t)
			m.must(t, nil, "daemon", "stop")
			if err := tc.break_(keyFileOf(m)); err != nil {
				t.Fatal(err)
			}
			m.hop(t, &session{}, "ls") // starts a daemon, which finds the vault locked
			out := m.must(t, nil, "status")
			if !strings.Contains(out, "device key:") || !strings.Contains(out, "the file "+keyFileOf(m)+" "+tc.want) {
				t.Errorf("status does not say the key file %s:\n%s", tc.want, out)
			}
			if !strings.Contains(out, "hop lock, then hop unlock --password") {
				t.Errorf("status names no next step:\n%s", out)
			}
			if i := strings.Index(out, "unlock error:"); i < 0 || !strings.Contains(out[i:], "hop unlock --password") {
				t.Errorf("the lock reason has no pointer to the fix:\n%s", out)
			}
			if ok, err := store.SealedDeviceFile(m.data); err != nil || !ok {
				t.Fatalf("the vault is no longer sealed (%v)", err)
			}
		})
	}
}
