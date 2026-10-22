package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// v1Record is rec as phase 1 wrote it: JCS without local_key.
func v1Record(t *testing.T, rec *deviceRecord) []byte {
	t.Helper()
	b, err := canonjson.Marshal(deviceRecordV1{V: 1, AccountID: rec.AccountID, DeviceID: rec.DeviceID, KEMSK: rec.KEMSK, SigSeed: rec.SigSeed, SecretKey: rec.SecretKey})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A phase 1 record parses only to be upgraded, under its own closed
// schema.
func TestDeviceRecordV1Schema(t *testing.T) {
	f := newVault(t, testConfig(t))
	raw := v1Record(t, f.s.rec)
	rec, err := parseDeviceRecord(raw)
	if err != nil || rec.V != 1 || rec.LocalKey != nil || !bytes.Equal(rec.SigSeed, f.s.rec.SigSeed) {
		t.Fatalf("a v1 record: %+v %v", rec, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	with := func(change func(m map[string]any)) []byte {
		c := map[string]any{}
		for k, v := range m {
			c[k] = v
		}
		change(c)
		b, _ := json.Marshal(c)
		return b
	}
	for name, b := range map[string][]byte{
		"an unknown member": with(func(m map[string]any) { m["name"] = "x" }),
		"missing kem_sk":    with(func(m map[string]any) { delete(m, "kem_sk") }),
		"v 0":               with(func(m map[string]any) { m["v"] = 0 }),
		"sig_seed 31 bytes": with(func(m map[string]any) { m["sig_seed"] = "AAAA" }),
		"padded base64":     []byte(strings.Replace(string(raw), `"kem_sk":"`, `"kem_sk":"=`, 1)),
	} {
		if _, err := parseDeviceRecord(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// §11: a v1 record is upgraded the first time the vault unlocks, made
// durable, reread and checked byte for byte; the key is then stable.
func TestV1RecordIsUpgradedDurably(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	user := "device:" + f.kit.AccountID
	v1 := string(v1Record(t, f.s.rec))
	seed := bytes.Clone(f.s.rec.SigSeed)
	if err := cfg.Keyring.Set(keychainService, user, v1); err != nil {
		t.Fatal(err)
	}
	s := open(t, cfg)
	if s.Info().Locked {
		t.Fatalf("locked: %s", s.Info().LockReason)
	}
	stored := storedRecord(t, cfg, f.kit.AccountID)
	if stored.V != 2 || len(stored.LocalKey) != 32 || !bytes.Equal(stored.LocalKey, s.rec.LocalKey) || !bytes.Equal(stored.SigSeed, seed) {
		t.Fatalf("after the upgrade: v %d, local_key %d bytes", stored.V, len(stored.LocalKey))
	}
	if again := open(t, cfg); !bytes.Equal(again.rec.LocalKey, stored.LocalKey) {
		t.Error("local_key changed on the next unlock")
	}

	// Each failed durability step keeps the vault locked, even when the
	// record then reads back.
	for name, ring := range map[string]Keyring{
		"set refused":            &failRing{memRing: newMemRing(), fail: true},
		"set stored, then fails": &failRing{memRing: newMemRing(), failAfter: true},
		"reread differs":         &staleRing{memRing: newMemRing()},
	} {
		c := cfg
		c.Keyring = ring
		switch r := ring.(type) {
		case *failRing:
			r.memRing.Set(keychainService, user, v1)
		case *staleRing:
			r.memRing.Set(keychainService, user, v1)
		}
		info := open(t, c).Info()
		if !info.Locked || !strings.Contains(info.LockReason, "upgraded durably") {
			t.Errorf("%s: locked %v, reason %q", name, info.Locked, info.LockReason)
		}
	}
}

// staleRing accepts every Set but always returns what it held first.
type staleRing struct{ *memRing }

func (r *staleRing) Set(service, user, secret string) error {
	if _, err := r.memRing.Get(service, user); err == nil {
		return nil
	}
	return r.memRing.Set(service, user, secret)
}

// The file store: a v1 key file is upgraded; a v2 one is trusted only once
// device.key and its directory fsync.
func TestV1KeyFileIsUpgradedDurably(t *testing.T) {
	cfg := testConfig(t)
	p, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword), DeviceStore: DeviceStoreFile})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s)
	f := deviceKeyFile{V: 1, DeviceID: s.rec.DeviceID, Salt: []byte{}, Key: v1Record(t, s.rec)}
	b, err := canonjson.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.DataDir, "device.key")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s = open(t, cfg)
	if s.Info().Locked || s.rec.V != 2 || len(s.rec.LocalKey) != 32 {
		t.Fatalf("after the upgrade: %+v", s.Info())
	}
	if !strings.Contains(readFile(t, path), `"local_key"`) {
		t.Error("device.key was not rewritten as v2")
	}

	dataDir := s.l.data
	syncDir = func(dir string) error {
		if dir == dataDir {
			return errors.New("injected directory fsync failure")
		}
		return fsyncDir(dir)
	}
	t.Cleanup(func() { syncDir = fsyncDir })
	if info := open(t, cfg).Info(); !info.Locked || !strings.Contains(info.LockReason, "not durable") {
		t.Errorf("unlock with device.key not durable: %+v", info)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// §13: local_key carried over a password change.
func TestLocalKeyCarriedOverAPasswordChange(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	key := bytes.Clone(f.s.rec.LocalKey)
	if _, err := f.s.ChangePassword(context.Background(), []byte(testPassword), []byte(newPassword)); err != nil {
		t.Fatal(err)
	}
	if err := f.s.AckKit(); err != nil {
		t.Fatal(err)
	}
	stored := storedRecord(t, cfg, f.kit.AccountID)
	if !bytes.Equal(stored.LocalKey, key) || !bytes.Equal(f.s.rec.LocalKey, key) {
		t.Error("the password change replaced local_key")
	}
}

// §13: local_key carried over a replacement record. A password unlock with
// the old record readable gives the new device the old local_key, so the
// queued records stay valid and still push.
func TestLocalKeyCarriedOverAReplacementRecord(t *testing.T) {
	ctx := context.Background()
	f, r := serverVault(t)
	s := f.s
	_, h := addHost(t, s, "web")
	oldDev, key := s.dev.ID, bytes.Clone(s.rec.LocalKey)
	if err := s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), ""); err != nil {
		t.Fatal(err)
	}
	if s.dev.ID == oldDev || !bytes.Equal(s.rec.LocalKey, key) {
		t.Fatalf("new device %v (was %v), same local_key %v", s.dev.ID, oldDev, bytes.Equal(s.rec.LocalKey, key))
	}
	if stored := storedRecord(t, f.cfg, f.kit.AccountID); !bytes.Equal(stored.LocalKey, key) {
		t.Error("the stored record has another local_key")
	}
	if lost, err := s.LostIntents(); err != nil || lost != 0 {
		t.Errorf("lost %d, %v", lost, err)
	}
	if res := pushAll(t, s, r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	if _, ok := verifiedHost(t, s, h.ItemID); !ok {
		t.Error("the queued record did not commit after the replacement")
	}
	if headOf(t, s).H != r.head().H.String() {
		t.Error("the bootstrap is not the server's")
	}
}

// §13: a reported loss when the old record is unreadable. The queued
// records can never be opened again: they are counted and deleted before
// anything else is written, and the count is reported until acknowledged.
func TestLostIntentsAreReported(t *testing.T) {
	ctx := context.Background()
	f, r := serverVault(t)
	addHost(t, f.s, "web") // two records
	key := bytes.Clone(f.s.rec.LocalKey)
	f.cfg.Keyring.(*memRing).clear()
	s := open(t, f.cfg)
	if !s.Info().Locked {
		t.Fatal("unlocked without a device key")
	}
	if err := s.UnlockWithPassword(ctx, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrServerBacked) {
		t.Errorf("a local bootstrap in a server-backed vault: %v", err)
	}
	if err := s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); err != nil {
		t.Fatal(err)
	}
	if lost, err := s.LostIntents(); err != nil || lost != 2 {
		t.Errorf("lost %d, %v; want 2", lost, err)
	}
	info := s.Info()
	found := false
	for _, w := range info.Warnings {
		found = found || strings.Contains(w, "2 queued change(s)")
	}
	if !found {
		t.Errorf("warnings %q", info.Warnings)
	}
	if bytes.Equal(s.rec.LocalKey, key) || len(outboxFiles(t, f.cfg.DataDir)) != 0 {
		t.Error("the unreadable records or their key survived")
	}
	// The loss survives a restart, record numbers are not reused, and the
	// acknowledgment clears it.
	s = open(t, f.cfg)
	if lost, _ := s.LostIntents(); lost != 2 {
		t.Errorf("lost after a restart: %d", lost)
	}
	newCredential(t, s, "c")
	if recs := records(t, s); len(recs) != 1 || recs[0].N != 3 {
		t.Errorf("records after the loss: %+v", recs)
	}
	if err := s.AckLostIntents(); err != nil {
		t.Fatal(err)
	}
	if lost, _ := s.LostIntents(); lost != 0 || strings.Contains(strings.Join(s.Info().Warnings, "\n"), "queued change") {
		t.Errorf("after the ack: lost %d, warnings %q", lost, s.Info().Warnings)
	}
	if res := pushAll(t, s, r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	var names []string
	for _, c := range snapshot(t, s).Credentials {
		names = append(names, c.Name)
	}
	if len(names) != 1 || names[0] != "c" {
		t.Errorf("credentials %v", names)
	}
	_ = model.ID{}
}

// Logout guards: the queries slice D2 and the CLI use (§11.1).
func TestLogoutGuards(t *testing.T) {
	ctx := context.Background()
	f, r := serverVault(t)
	s := f.s
	if empty, err := s.OutboxEmpty(); err != nil || !empty {
		t.Errorf("empty outbox: %v %v", empty, err)
	}
	newCredential(t, s, "c")
	s.Lock()
	if empty, err := s.OutboxEmpty(); err != nil || empty {
		t.Errorf("OutboxEmpty while locked with a record: %v %v", empty, err)
	}
	if err := s.Unlock(ctx); err != nil {
		t.Fatal(err)
	}
	pushAll(t, s, r)
	if empty, _ := s.OutboxEmpty(); !empty {
		t.Error("outbox not empty after the push")
	}
	if j, err := s.HasCheckpointJournal(); err != nil || j {
		t.Errorf("checkpoint journal: %v %v", j, err)
	}
	if s.PendingKit() != nil {
		t.Error("a pending kit")
	}
	// A local vault with a pending kit has a checkpoint journal.
	g := newVault(t, testConfig(t))
	if _, err := g.s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword)); err != nil {
		t.Fatal(err)
	}
	if j, err := g.s.HasCheckpointJournal(); err != nil || !j || g.s.PendingKit() == nil {
		t.Errorf("after hop passwd: journal %v %v, kit %v", j, err, g.s.PendingKit() != nil)
	}
}
