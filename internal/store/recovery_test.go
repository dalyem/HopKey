package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

const newPassword = "a much better password"

func journalFiles(t *testing.T, cfg Config) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(cfg.DataDir, "vault", "journal"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func hasWarning(info Info, sub string) bool {
	return slices.ContainsFunc(info.Warnings, func(w string) bool { return strings.Contains(w, sub) })
}

// storedRecord reads the device record from the keychain, as a restart
// would.
func storedRecord(t *testing.T, cfg Config, accountID string) deviceRecord {
	t.Helper()
	raw, err := cfg.Keyring.Get(keychainService, "device:"+accountID)
	if err != nil {
		t.Fatal(err)
	}
	var rec deviceRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// Item 1, key still readable: a password change committed, its kit not yet
// confirmed, and then hop unlock --password replaces the device key. The
// kit is sealed to the new key before the old one goes, so it survives.
func TestPasswordUnlockKeepsAPendingKit(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	addHost(t, f.s, "web-1")
	ctx := context.Background()
	kit, err := f.s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword))
	if err != nil {
		t.Fatal(err)
	}
	oldDev := f.s.Info().DeviceID
	if err := f.s.UnlockWithPassword(ctx, []byte(newPassword), ""); err != nil {
		t.Fatal(err)
	}
	if info := f.s.Info(); info.DeviceID == oldDev || len(info.Warnings) != 1 || !hasWarning(info, "1 stale device") {
		t.Errorf("after the password unlock: %+v", info)
	}
	if p := f.s.PendingKit(); p == nil || *p != kit {
		t.Fatalf("pending kit after the password unlock = %+v, want the committed one", p)
	}
	// A restart reads it with the new device key.
	s := open(t, cfg)
	if p := s.PendingKit(); p == nil || p.RecoveryKey != kit.RecoveryKey {
		t.Fatalf("pending kit after a restart = %+v", p)
	}
	if hasWarning(s.Info(), "cannot be recovered") {
		t.Errorf("warnings = %q", s.Info().Warnings)
	}
	if err := s.AckKit(); err != nil {
		t.Fatal(err)
	}
	if n := journalFiles(t, cfg); len(n) != 0 {
		t.Errorf("journal after ack: %v", n)
	}
}

// Item 1, key gone: the journal cannot be opened. It is kept, never
// silently deleted, and hop status says the Recovery Key is lost and what
// to do. The next hop passwd supersedes it.
func TestPasswordUnlockWithTheKeyGoneKeepsTheJournal(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	addHost(t, f.s, "web-1")
	ctx := context.Background()
	kit, err := f.s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword))
	if err != nil {
		t.Fatal(err)
	}
	before := journalFiles(t, cfg)
	if len(before) != 1 {
		t.Fatalf("journal = %v", before)
	}
	cfg.Keyring.(*memRing).clear() // the device key is lost

	s := open(t, cfg)
	if !s.Info().Locked {
		t.Fatal("opened without a device key")
	}
	if err := s.UnlockWithPassword(ctx, []byte(newPassword), kit.SecretKey); err != nil {
		t.Fatal(err)
	}
	check := func(s *Store, when string) {
		t.Helper()
		info := s.Info()
		if s.PendingKit() != nil || info.KitPending {
			t.Errorf("%s: a kit is pending that nothing can open", when)
		}
		if !hasWarning(info, "cannot be recovered") || !hasWarning(info, "run hop passwd") {
			t.Errorf("%s: warnings = %q", when, info.Warnings)
		}
		if got := journalFiles(t, cfg); !slices.Equal(got, before) {
			t.Errorf("%s: journal = %v, want %v kept", when, got, before)
		}
	}
	check(s, "after the password unlock")
	check(open(t, cfg), "after a restart")

	s = open(t, cfg)
	next, err := s.ChangePassword(ctx, []byte(newPassword), []byte(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if hasWarning(s.Info(), "cannot be recovered") {
		t.Errorf("warnings after a new passwd = %q", s.Info().Warnings)
	}
	if got := journalFiles(t, cfg); slices.Contains(got, before[0]) {
		t.Errorf("the superseded journal is still there: %v", got)
	}
	if p := s.PendingKit(); p == nil || *p != next {
		t.Errorf("pending kit = %+v", p)
	}
}

// Item 2: a journal of an older checkpoint that did commit (A, confirmed,
// then B, confirmed, then A's journal restored from a backup) is not the
// account's kit any more. It is discarded, and nothing of it is installed
// or shown.
func TestStaleCommittedJournalIsDiscarded(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	addHost(t, f.s, "web-1")
	ctx := context.Background()
	if _, err := f.s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword)); err != nil {
		t.Fatal(err)
	}
	names := journalFiles(t, cfg)
	if len(names) != 1 {
		t.Fatalf("journal = %v", names)
	}
	pathA := filepath.Join(cfg.DataDir, "vault", "journal", names[0])
	journalA, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.AckKit(); err != nil {
		t.Fatal(err)
	}
	kitB, err := f.s.ChangePassword(ctx, []byte(newPassword), []byte(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.AckKit(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathA, journalA, 0o600); err != nil {
		t.Fatal(err)
	}

	s := open(t, cfg)
	if p := s.PendingKit(); p != nil {
		t.Errorf("the old journal's kit is pending: %+v", p)
	}
	if s.rec.SecretKey != kitB.SecretKey {
		t.Error("the Secret Key in memory is not the current one")
	}
	if got := storedRecord(t, cfg, f.kit.AccountID).SecretKey; got != kitB.SecretKey {
		t.Error("the stored Secret Key is not the current one")
	}
	if got := journalFiles(t, cfg); len(got) != 0 {
		t.Errorf("journal = %v, want the stale one discarded", got)
	}
	if err := s.UnlockWithPassword(ctx, []byte(testPassword), ""); err != nil {
		t.Errorf("password unlock with the stored Secret Key: %v", err)
	}
}

// failRing is a memRing whose Set can fail, and can fail after storing.
type failRing struct {
	*memRing
	fail      bool // Set fails and stores nothing
	failAfter bool // Set stores, then reports a failure
}

func (r *failRing) Set(service, user, secret string) error {
	switch {
	case r.fail:
		return errors.New("keychain write refused")
	case r.failAfter:
		r.memRing.Set(service, user, secret)
		return errors.New("keychain write timed out")
	}
	return r.memRing.Set(service, user, secret)
}

// Item 3: the new Secret Key reaches memory only after the device key store
// holds it. While it cannot be saved the kit stays pending and AckKit
// refuses; a retry checks the stored record, so it does only what is
// missing.
func TestKitSecretKeyIsSavedBeforeItIsUsed(t *testing.T) {
	cfg := testConfig(t)
	ring := &failRing{memRing: newMemRing()}
	cfg.Keyring = ring
	f := newVault(t, cfg)
	addHost(t, f.s, "web-1")
	ctx := context.Background()

	ring.fail = true
	kit, err := f.s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword))
	if err != nil {
		t.Fatalf("a committed change hides its kit: %v", err)
	}
	if f.s.rec.SecretKey != f.kit.SecretKey {
		t.Error("the new Secret Key is in memory, but the save failed")
	}
	if got := storedRecord(t, cfg, f.kit.AccountID).SecretKey; got != f.kit.SecretKey {
		t.Error("the stored Secret Key changed although the save failed")
	}
	if !hasWarning(f.s.Info(), "not saved on this device") {
		t.Errorf("warnings = %q", f.s.Info().Warnings)
	}
	if err := f.s.AckKit(); err == nil || !strings.Contains(err.Error(), "stays pending") {
		t.Errorf("ack while the Secret Key is not saved: %v", err)
	}
	if f.s.PendingKit() == nil || len(journalFiles(t, cfg)) != 1 {
		t.Fatal("the kit was dropped")
	}

	// The keychain stores the record but reports a failure: memory keeps
	// the old key. The next retry finds the record saved and is done
	// without writing again.
	ring.fail, ring.failAfter = false, true
	if err := f.s.AckKit(); err == nil {
		t.Error("ack after a failed save")
	}
	if f.s.rec.SecretKey != f.kit.SecretKey {
		t.Error("memory took the new Secret Key from a save that reported failure")
	}
	ring.fail, ring.failAfter = true, false
	if err := f.s.AckKit(); err != nil {
		t.Fatalf("ack with the record already saved: %v", err)
	}
	if f.s.rec.SecretKey != kit.SecretKey || storedRecord(t, cfg, f.kit.AccountID).SecretKey != kit.SecretKey {
		t.Error("the new Secret Key is not in use after the ack")
	}
	if len(journalFiles(t, cfg)) != 0 || f.s.PendingKit() != nil || len(f.s.Info().Warnings) != 0 {
		t.Errorf("after the ack: journal %v, warnings %q", journalFiles(t, cfg), f.s.Info().Warnings)
	}
	ring.fail = false
	if err := open(t, cfg).UnlockWithPassword(ctx, []byte(newPassword), ""); err != nil {
		t.Errorf("password unlock with the stored Secret Key: %v", err)
	}
}

func stateHead(t *testing.T, cfg Config) vaultlog.Head {
	t.Helper()
	st, err := vaultlog.ParseState(readState(t, cfg))
	if err != nil {
		t.Fatal(err)
	}
	return st.Head
}

// Item 7: an entry committed but its state.json write failed. The next
// write catches up, and the caught-up state is on disk before it is used
// in memory, even when that write itself is refused.
func TestCatchUpPersistsBeforeItInstalls(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	_, h := addHost(t, f.s, "web-1")
	ctx := context.Background()
	failed := false
	f.s.testHook = func(stage string) error {
		if stage == "state" && !failed {
			failed = true
			return errors.New("disk full")
		}
		return nil
	}
	if _, err := f.s.PutSnippet(ctx, model.Snippet{Name: "x", Command: "true"}); err == nil {
		t.Fatal("the failed state write was not reported")
	}
	// The next write is invalid: it names an old version of the host.
	stale := h
	stale.ItemVersion = 0
	if _, err := f.s.PutHost(ctx, stale); err == nil {
		t.Fatal("a stale replace was accepted")
	}
	mem, err := f.s.Head()
	if err != nil {
		t.Fatal(err)
	}
	if disk := stateHead(t, cfg); disk.Seq != mem.Seq || disk.H.String() != mem.H {
		t.Errorf("head in memory %+v, on disk %d %v", mem, disk.Seq, disk.H)
	}
	if mem.Seq != 3 {
		t.Errorf("head seq %d, want 3 (the snippet committed)", mem.Seq)
	}
	if s := open(t, cfg); len(snapshot(t, s).Snippets) != 1 {
		t.Error("the committed snippet is gone after a restart")
	}
}

// Item 11: state.json with the right head but other contents fails closed.
func TestTamperedStateFailsClosed(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	_, h := addHost(t, f.s, "web-1")
	good := readState(t, cfg)
	tamper := func(change func(st *vaultlog.State)) []byte {
		t.Helper()
		st, err := vaultlog.ParseState(good)
		if err != nil {
			t.Fatal(err)
		}
		change(st)
		b, err := st.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		rollBackState(t, cfg, b)
		return b
	}

	// An item's version, which nothing reads before the replay.
	b := tamper(func(st *vaultlog.State) {
		it := st.Items[h.ItemID]
		it.ItemVersion += 5
		st.Items[h.ItemID] = it
	})
	_, err := tryOpen(t, cfg)
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "differs from the verified log") {
		t.Fatalf("open with a tampered state.json: %v", err)
	}
	if !bytes.Equal(readState(t, cfg), b) {
		t.Error("the tampered state.json was rewritten")
	}
	t.Logf("tampered state: %v", err)

	// This device's certificate: the device key no longer opens its
	// unlock blob, so the vault stays locked, and a password unlock, which
	// replays the log, refuses the state.
	tamper(func(st *vaultlog.State) {
		for id, d := range st.Devices {
			d.Cert.Name = "renamed outside hop"
			st.Devices[id] = d
		}
	})
	s, err := tryOpen(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Info().Locked {
		t.Fatal("unlocked with a tampered certificate in state.json")
	}
	if err := s.UnlockWithPassword(context.Background(), []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrCorrupt) {
		t.Errorf("password unlock over a tampered state.json: %v", err)
	}

	// The untouched file still opens.
	rollBackState(t, cfg, good)
	if open(t, cfg).Info().Locked {
		t.Error("the original state.json does not open")
	}
}

// enrollOther adds a device by a bootstrap entry, as a second machine
// would. Its key is thrown away; only the log knows it.
func enrollOther(t *testing.T, s *Store) model.ID {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	rec, info, err := newDeviceRecord(s.state.Account.AccountID, "")
	if err != nil {
		t.Fatal(err)
	}
	rec.zero()
	info.Name = "another machine"
	w, st, sec, err := vaultlog.BuildBootstrap(s.state, s.sec, info, s.now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.commit(w, st); err != nil {
		t.Fatal(err)
	}
	s.state, s.sec = st, sec
	return info.ID
}

// Item 10: a password unlock leaves the old device stale; hop status says
// so, and hop passwd revokes it and nothing else.
func TestPasswdRevokesStaleDevicesOnly(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	addHost(t, f.s, "web-1")
	ctx := context.Background()
	old := f.s.dev.ID
	other := enrollOther(t, f.s)
	cfg.Keyring.(*memRing).clear()

	s := open(t, cfg)
	if err := s.UnlockWithPassword(ctx, []byte(testPassword), f.kit.SecretKey); err != nil {
		t.Fatal(err)
	}
	info := s.Info()
	if info.StaleDevices != 1 || !hasWarning(info, "1 stale device(s) from earlier password unlocks; run hop passwd to revoke") {
		t.Errorf("after the password unlock: %+v", info)
	}
	if len(s.state.Devices) != 3 {
		t.Fatalf("%d active devices, want 3", len(s.state.Devices))
	}
	cur := s.dev.ID
	// The count survives a restart.
	s = open(t, cfg)
	if s.Info().StaleDevices != 1 {
		t.Errorf("after a restart: %+v", s.Info())
	}

	if _, err := s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword)); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.state.Devices[old]; ok || !slices.Contains(s.state.Retired.DeviceIDs, old) {
		t.Error("the stale device was not revoked")
	}
	for _, id := range []model.ID{cur, other} {
		if _, ok := s.state.Devices[id]; !ok || slices.Contains(s.state.Retired.DeviceIDs, id) {
			t.Errorf("device %v was revoked", id)
		}
	}
	if info := s.Info(); info.StaleDevices != 0 || hasWarning(info, "stale") {
		t.Errorf("after passwd: %+v", info)
	}
	cfgFile, err := s.readDeviceConfig()
	if err != nil || len(cfgFile.StaleDevices) != 0 || cfgFile.DeviceID != cur {
		t.Errorf("device.json after passwd: %+v %v", cfgFile, err)
	}
	// The checkpoint in the log says the same, read back from disk.
	if s := open(t, cfg); len(s.state.Devices) != 2 {
		t.Errorf("%d devices after a restart, want 2", len(s.state.Devices))
	}
}

// Item 9: device.key is the rev 14 file, sealed or not.
func TestDeviceKeyFileFormat(t *testing.T) {
	for _, sealed := range []bool{false, true} {
		t.Run(fmt.Sprintf("sealed=%v", sealed), func(t *testing.T) {
			cfg := testConfig(t)
			pass := ""
			if sealed {
				pass = "device passphrase 1"
			}
			cfg.Getenv = func(k string) string {
				if k == PassphraseEnv {
					return pass
				}
				return ""
			}
			p, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword), DeviceStore: DeviceStoreFile})
			if err != nil {
				t.Fatal(err)
			}
			s, err := p.Commit()
			if err != nil {
				t.Fatal(err)
			}
			track(t, cfg, s)
			want := "file (unsealed)"
			if sealed {
				want = "file (sealed)"
			}
			if got := s.Info().DeviceStore; got != want {
				t.Errorf("device store %q, want %q", got, want)
			}
			path := filepath.Join(cfg.DataDir, "device.key")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if c, err := canonjson.Canonicalize(raw); err != nil || !bytes.Equal(c, raw) {
				t.Errorf("device.key is not JCS: %v", err)
			}
			var m map[string]json.RawMessage
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			keys := slices.Sorted(func(yield func(string) bool) {
				for k := range m {
					if !yield(k) {
						return
					}
				}
			})
			if strings.Join(keys, ",") != "device_id,kdf_version,key,salt,v" {
				t.Errorf("members %v", keys)
			}
			devID := s.Info().DeviceID
			wantKDF, wantSalt := "0", `""`
			if sealed {
				wantKDF = "1"
			}
			if string(m["v"]) != "1" || string(m["kdf_version"]) != wantKDF || string(m["device_id"]) != `"`+devID+`"` {
				t.Errorf("header %s %s %s", m["v"], m["kdf_version"], m["device_id"])
			}
			var key map[string]json.RawMessage
			if err := json.Unmarshal(m["key"], &key); err != nil {
				t.Fatal(err)
			}
			if sealed {
				var salt string
				json.Unmarshal(m["salt"], &salt)
				if b, err := base64.RawURLEncoding.DecodeString(salt); err != nil || len(b) != 16 {
					t.Errorf("salt %s", m["salt"])
				}
				if _, ok := key["ct"]; !ok || len(key) != 4 {
					t.Errorf("sealed key is not an AEAD envelope: %s", m["key"])
				}
			} else {
				if string(m["salt"]) != wantSalt {
					t.Errorf("unsealed salt %s", m["salt"])
				}
				if string(key["device_id"]) != `"`+devID+`"` || key["kem_sk"] == nil {
					t.Errorf("unsealed key is not the device private keys: %v", slices.Collect(func(yield func(string) bool) {
						for k := range key {
							yield(k)
						}
					}))
				}
			}

			// Another device's ID in the file: refused.
			other, _ := vaultlog.NewID()
			swapped := bytes.Replace(raw, []byte(`"device_id":"`+devID+`"`), []byte(`"device_id":"`+other.String()+`"`), 1)
			if bytes.Equal(swapped, raw) {
				t.Fatal("device_id not found in the file")
			}
			lockedWith := func(b []byte, sub string) {
				t.Helper()
				if err := os.WriteFile(path, b, 0o600); err != nil {
					t.Fatal(err)
				}
				info := open(t, cfg).Info()
				if !info.Locked || !strings.Contains(info.LockReason, sub) {
					t.Errorf("locked=%v reason %q, want it to mention %q", info.Locked, info.LockReason, sub)
				}
			}
			if sealed {
				lockedWith(swapped, "does not open")
			} else {
				lockedWith(swapped, "names device")
			}
			if !sealed {
				// An unsealed file where device.json says sealed is refused
				// below; here, a sealed-looking header is refused too.
				lockedWith(bytes.Replace(raw, []byte(`"kdf_version":0`), []byte(`"kdf_version":1`), 1), "is sealed")
				return
			}
			// One flipped bit in the ciphertext.
			i := bytes.Index(raw, []byte(`"ct":"`)) + 10
			tampered := slices.Clone(raw)
			if tampered[i] == 'A' {
				tampered[i] = 'B'
			} else {
				tampered[i] = 'A'
			}
			lockedWith(tampered, "does not open")
			// The wrong passphrase.
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			pass = "the wrong passphrase"
			if info := open(t, cfg).Info(); !info.Locked || !strings.Contains(info.LockReason, "does not open") {
				t.Errorf("wrong passphrase: %+v", info)
			}
			// An unsealed file in its place: no silent downgrade.
			pass = "device passphrase 1"
			s = open(t, cfg)
			rec := s.rec.clone()
			unsealed := s.deviceStore(deviceConfig{V: 1, Store: DeviceStoreFile, AccountID: s.devCfg.AccountID})
			if err := unsealed.save(rec); err != nil {
				t.Fatal(err)
			}
			if info := open(t, cfg).Info(); !info.Locked || !strings.Contains(info.LockReason, "should be sealed") {
				t.Errorf("unsealed file under a sealed config: %+v", info)
			}
		})
	}
}

// The passphrase follows the master password rules (§4.1): init refuses a
// short one before it writes anything.
func TestShortDevicePassphraseIsRefused(t *testing.T) {
	cfg := testConfig(t)
	cfg.Getenv = func(k string) string {
		if k == PassphraseEnv {
			return "short"
		}
		return ""
	}
	if _, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword), DeviceStore: DeviceStoreFile}); err == nil || !strings.Contains(err.Error(), PassphraseEnv) {
		t.Errorf("init with a 5-byte passphrase: %v", err)
	}
	if _, err := os.Stat(cfg.DataDir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("init wrote %s: %v", cfg.DataDir, err)
	}
}

// secretNeedles are the encodings of key material that must never be on
// disk: hex and each base64 alphabet, padded and not.
func secretNeedles(b []byte) []string {
	out := []string{hex.EncodeToString(b)}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		out = append(out, enc.EncodeToString(b))
	}
	return out
}

// keyNeedles are the device private keys, the account private keys and the
// VK of an unlocked store, in every encoding.
func keyNeedles(t *testing.T, s *Store) []string {
	t.Helper()
	kem, err := s.sec.Account.KEM.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, b := range [][]byte{s.rec.KEMSK, s.rec.SigSeed, kem, s.sec.Account.Sig.Seed(), s.sec.VK[:]} {
		out = append(out, secretNeedles(b)...)
	}
	return out
}

// Item 8, a sealed device key file: neither the Secret Key nor any key is
// on disk in any encoding. (Unsealed, device.key holds the device keys and
// the Secret Key in the clear by design; that is what "unsealed" says.)
func TestNoPlaintextOnDiskSealedFile(t *testing.T) {
	cfg := testConfig(t)
	cfg.Getenv = func(k string) string {
		if k == PassphraseEnv {
			return "device passphrase 1"
		}
		return ""
	}
	p, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword), DeviceStore: DeviceStoreFile})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s)
	k, h := addHost(t, s, "secret-host-name")
	needles := []string{h.Name, h.Addresses[0], testPassword, "device passphrase 1", p.Kit().SecretKey, p.Kit().RecoveryKey}
	needles = append(needles, pemSecretLines(k.PrivateKey)...)
	needles = append(needles, keyNeedles(t, s)...)
	scanForPlaintext(t, cfg.DataDir, needles)
}
