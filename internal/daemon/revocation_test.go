package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// A revocation the laptop can verify from its own log wipes it as a
// logout does, and leaves only the record hop auth status reads.
func TestProvenRevocationWipesTheDevice(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 5*time.Second, "web1 reaches the laptop", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })
	laptop := x.n2.st.Info().DeviceID
	// More history between the laptop's head and the checkpoint, which
	// the proof has to chain through.
	x.n2.pause(true)
	x.n1.putHost(webHost("web2", x.keyID, "203.0.113.17"))
	eventually(t, 5*time.Second, "the desk pushes", func() bool { return x.n1.status().Pending == 0 })
	x.revokeLaptop(t)
	x.n2.pause(false)

	eventually(t, 15*time.Second, "the laptop wipes itself", func() bool {
		r := x.n2.status().ServerRetirement
		return r != nil && r.Wiped
	})
	data := x.n2.cfg.DataDir
	for _, rel := range []string{"device.json", "device.key", "vault/state.json", "vault/entries", "vault/objects", "vault/account.json", "vault/server.json", "vault/server-revoked.json"} {
		if exists(t, filepath.Join(data, rel)) {
			t.Errorf("%s is still there after the wipe", rel)
		}
	}
	rec, err := store.ReadRevocation(data)
	if err != nil || rec == nil {
		t.Fatalf("the revocation record: %v, %v", rec, err)
	}
	if rec.DeviceID.String() != laptop || rec.How != "revoked" || rec.Email == "" {
		t.Errorf("the revocation record: %+v", rec)
	}
	eventually(t, 5*time.Second, "the ssh files go", func() bool {
		pending, _ := store.LogoutCleanupPending(data)
		return !pending && !strings.Contains(x.n2.config(), "Host ")
	})
	if keys, _ := filepath.Glob(filepath.Join(x.n2.paths.ConfigDir, "keys", "*")); len(keys) > 0 {
		t.Errorf("key files left: %v", keys)
	}
	assertCutOff(t, x.n2, "after the wipe")

	x.n2.c.Close()
	x.n2.d.Close()
	if _, err := store.Open(context.Background(), x.n2.cfg); !errors.Is(err, store.ErrNoVault) {
		t.Errorf("opening the wiped laptop: %v, want no vault", err)
	}
}

// hostile is a server that refuses the laptop a session and says it was
// revoked at a seq it makes up. Every other request goes to the real
// server.
func hostile(w *syncWorld, laptop model.ID, proof bool) {
	f := interceptor(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		var body struct {
			DeviceID  model.ID `json:"device_id"`
			Operation string   `json:"operation"`
		}
		if req.Body != nil {
			b, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(b))
			json.Unmarshal(b, &body)
		}
		if body.DeviceID != laptop {
			return false
		}
		fake := struct {
			DeviceID model.ID    `json:"device_id"`
			H        crypto.Hash `json:"h"`
			How      string      `json:"how"`
			Seq      uint64      `json:"seq,string"`
		}{laptop, crypto.SHA256([]byte("made up")), "revoked", 1 << 20}
		answer := func(v any) bool {
			b, err := canonjson.Marshal(v)
			if err != nil {
				panic(err)
			}
			rw.Header().Set("Content-Type", "application/json")
			rw.Write(b)
			return true
		}
		switch {
		case req.URL.Path == "/v1/auth/challenge" && body.Operation == "session":
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte(`{"error":{"code":"unauthorized","message":"unauthorized"}}`))
			return true
		case req.URL.Path == "/v1/retire-status":
			return answer(struct {
				Committed bool          `json:"committed"`
				Head      vaultlog.Head `json:"head"`
				Receipt   any           `json:"receipt"`
				Seq       *string       `json:"seq"`
			}{Head: vaultlog.Head{Seq: 1 << 20, H: fake.H}, Receipt: fake})
		case req.URL.Path == "/v1/retire-status/proof" && proof:
			return answer(struct {
				Entries []any `json:"entries"`
				Receipt any   `json:"receipt"`
			}{Entries: []any{}, Receipt: fake})
		case req.URL.Path == "/v1/retire-status/proof":
			http.Error(rw, `{"error":{"code":"not_found","message":"not found"}}`, http.StatusNotFound)
			return true
		}
		return false
	})
	w.intercept.Store(&f)
}

// A server that lies about a revocation can lock the device, but deletes
// nothing, and once a server authenticates the device again it unlocks.
func TestFalseRevocationReportLocksAndDeletesNothing(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 5*time.Second, "web1 reaches the laptop", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })
	id, err := model.ParseID(x.n2.st.Info().DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	hostile(x.w, id, true)
	x.w.restart(x.n2) // asserts that no key was served from the start
	assertCutOff(t, x.n2, "under the hostile server")
	eventually(t, 5*time.Second, "the proof is refused", func() bool {
		r := x.n2.status().ServerRetirement
		return r != nil && r.Unverified && strings.Contains(r.ProofError, "did not verify")
	})
	data := x.n2.cfg.DataDir
	for _, rel := range []string{"device.json", "vault/state.json", "vault/entries", "vault/account.json", "vault/server.json"} {
		if !exists(t, filepath.Join(data, rel)) {
			t.Errorf("%s was deleted on the server's word", rel)
		}
	}
	if rec, _ := store.ReadRevocation(data); rec != nil {
		t.Errorf("a revocation record was written on the server's word: %+v", rec)
	}

	// An honest server again: it authenticates the laptop, and the report
	// goes.
	x.w.intercept.Store(nil)
	x.n2.must(OpUnlock, nil, nil)
	if x.n2.agentKeys() != 1 {
		t.Error("the laptop's keys are not back")
	}
	if rep, _ := x.n2.st.Report(); rep != nil {
		t.Errorf("the report is still recorded: %+v", rep)
	}
	eventually(t, 10*time.Second, "the laptop syncs again", func() bool { return x.n2.status().State == SyncOnline })
}

// writeContact sets the laptop's last server contact.
func writeContact(t *testing.T, n *node, at time.Time) {
	t.Helper()
	b, err := canonjson.Marshal(struct {
		At model.Timestamp `json:"at"`
		V  int             `json:"v"`
	}{model.TimestampOf(at), 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(n.cfg.DataDir, "vault", "contact.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// restartContact restarts n's daemon with its last contact set to at.
func (w *syncWorld) restartContact(n *node, at time.Time) {
	t := n.t
	t.Helper()
	n.c.Close()
	n.d.Close()
	writeContact(t, n, at)
	st, err := store.Open(context.Background(), n.cfg)
	if err != nil {
		t.Fatal(err)
	}
	n.st = st
	w.start(n, st, SyncOptions{})
}

func (n *node) policy() int64 {
	n.t.Helper()
	var p PolicyResult
	n.must(OpPolicy, nil, &p)
	return p.MaxOffline
}

// The account's max-offline policy: off by default; once set (it syncs to
// every device), a device that has not reached the server for longer locks
// and refuses to unlock until it has, and so does one whose last contact is
// in the future.
func TestMaxOfflinePolicy(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	if p := x.n2.policy(); p != 0 {
		t.Fatalf("the policy is %d by default", p)
	}

	// Off: a long time offline changes nothing.
	x.w.down.Store(true)
	x.w.restartContact(x.n2, time.Now().Add(-48*time.Hour))
	if x.n2.agentKeys() != 1 {
		t.Fatal("with the policy off, a device long offline lost its keys")
	}
	if s := x.n2.status(); s.CheckSkipped == "" {
		t.Error("status does not say the check with the server was skipped")
	}
	x.w.down.Store(false)

	x.n1.must(OpPolicy, PolicyParams{MaxOffline: 3600}, nil)
	eventually(t, 10*time.Second, "the policy reaches the laptop", func() bool {
		x.n1.call(OpSyncNow, nil, nil)
		x.n2.call(OpSyncNow, nil, nil)
		return x.n2.policy() == 3600
	})

	x.w.down.Store(true)
	x.w.restartContact(x.n2, time.Now().Add(-2*time.Hour))
	if x.n2.agentKeys() != 0 {
		t.Error("a device offline for longer than the policy allows serves keys")
	}
	if s := x.n2.status(); s.OfflineLocked == "" || s.State != SyncLocked {
		t.Errorf("status: state %s, offline %q", s.State, s.OfflineLocked)
	}
	if err := x.n2.call(OpUnlock, nil, nil); !IsCode(err, CodeOffline) {
		t.Errorf("unlock while offline too long: %v", err)
	}
	// A contact clears it.
	x.w.down.Store(false)
	x.n2.must(OpUnlock, nil, nil)
	if x.n2.agentKeys() != 1 {
		t.Error("the keys are not back after the server answered")
	}

	// A last contact in the future: the clock was set back.
	x.w.down.Store(true)
	x.w.restartContact(x.n2, time.Now().Add(3*time.Hour))
	if x.n2.agentKeys() != 0 {
		t.Error("a device whose last contact is in the future serves keys")
	}
	if s := x.n2.status(); !strings.Contains(s.OfflineLocked, "future") {
		t.Errorf("status: offline %q", s.OfflineLocked)
	}
	x.w.down.Store(false)
	x.n2.must(OpUnlock, nil, nil)
	if x.n2.agentKeys() != 1 {
		t.Error("the keys are not back after the server answered")
	}

	// Off again.
	x.n2.must(OpPolicy, PolicyParams{MaxOffline: 0}, nil)
	if p := x.n2.policy(); p != 0 {
		t.Errorf("the policy is %d after turning it off", p)
	}
}

// A local-only vault has no policy and no server to ask.
func TestLocalOnlyVaultHasNoPolicy(t *testing.T) {
	cfg := syncStoreConfig(t, "solo")
	p, err := store.PrepareInit(cfg, store.InitOptions{Password: []byte(syncPassword)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	w := newSyncWorld(t)
	n := &node{t: t, name: "solo", cfg: cfg, st: s}
	w.start(n, s, SyncOptions{})
	if err := n.call(OpPolicy, PolicyParams{MaxOffline: 3600}, nil); !IsCode(err, CodeLocalOnly) {
		t.Errorf("setting a policy on a local-only vault: %v", err)
	}
	if err := n.call(OpUnlock, nil, nil); err != nil {
		t.Errorf("unlock: %v", err)
	}
}
