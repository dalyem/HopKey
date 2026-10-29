package cli_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// falseReport makes the server refuse device id a session and report it
// revoked at a seq it makes up, with no proof.
func falseReport(t *testing.T, w *authWorld, id string) {
	t.Helper()
	dev, err := model.ParseID(id)
	if err != nil {
		t.Fatal(err)
	}
	answer := func(rw http.ResponseWriter, status int, v any) bool {
		b, err := canonjson.Marshal(v)
		if err != nil {
			panic(err)
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(status)
		rw.Write(b)
		return true
	}
	hook := func(rw http.ResponseWriter, r *http.Request) bool {
		var body struct {
			DeviceID  model.ID `json:"device_id"`
			Operation string   `json:"operation"`
		}
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(b))
			json.Unmarshal(b, &body)
		}
		if body.DeviceID != dev {
			return false
		}
		fake := struct {
			DeviceID model.ID    `json:"device_id"`
			H        crypto.Hash `json:"h"`
			How      string      `json:"how"`
			Seq      uint64      `json:"seq,string"`
		}{dev, crypto.SHA256([]byte("made up")), "revoked", 1 << 20}
		switch {
		case r.URL.Path == "/v1/auth/challenge" && body.Operation == "session":
			return answer(rw, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "unauthorized", "message": "unauthorized"}})
		case r.URL.Path == "/v1/retire-status":
			return answer(rw, http.StatusOK, struct {
				Committed bool          `json:"committed"`
				Head      vaultlog.Head `json:"head"`
				Receipt   any           `json:"receipt"`
				Seq       *string       `json:"seq"`
			}{Head: vaultlog.Head{Seq: 1 << 20, H: fake.H}, Receipt: fake})
		case r.URL.Path == "/v1/retire-status/proof":
			return answer(rw, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "not_found", "message": "not found"}})
		}
		return false
	}
	w.hook.Store(&hook)
}

// A daemon started without the device passphrase (by the login service or
// hop mcp) on a device whose server made up a revocation: once the server
// accepts the device again, hop unlock on a terminal asks for the
// passphrase, and the vault unlocks.
func TestUnlockAsksForThePassphraseAfterAFalseReport(t *testing.T) {
	w := newAuthWorld(t)
	m := newMachine(t, w, "sealed")
	env := map[string]string{store.PassphraseEnv: unlockPassphrase}
	initS := &session{env: env, secrets: map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}}
	if code := m.hop(t, initS, "init", "--device-key-store", "file"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	m.must(t, env, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t))
	m.must(t, env, "unlock")
	id := m.authStatus(t).DeviceID
	if id == "" {
		t.Fatal("no device ID")
	}

	falseReport(t, w, id)
	s := &session{env: env}
	if code := m.hop(t, s, "unlock"); code == 0 || !strings.Contains(s.stderr.String(), "revoked") {
		t.Fatalf("hop unlock under the false report: exit %d: %s", code, s.stderr.String())
	}
	if a := m.authStatus(t); !a.RevokedUnverified {
		t.Fatalf("the report was not recorded: %+v", a)
	}

	w.hook.Store(nil) // the server accepts the device again
	s = &session{tty: true, secrets: map[string]string{"Device passphrase: ": unlockPassphrase}}
	if code := m.hop(t, s, "unlock"); code != 0 {
		t.Fatalf("hop unlock on a terminal: exit %d: %s", code, s.stderr.String())
	}
	if a := m.authStatus(t); a.Locked || !a.SignedIn || a.RevokedUnverified {
		t.Errorf("after hop unlock: %+v", a)
	}
}
