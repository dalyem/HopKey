package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

const testPassword = "correct horse battery staple"

// memRing is an in-memory Keyring.
type memRing struct {
	mu sync.Mutex
	m  map[string]string
}

func newMemRing() *memRing { return &memRing{m: map[string]string{}} }

func (r *memRing) Get(service, user string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.m[service+"/"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (r *memRing) Set(service, user, secret string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[service+"/"+user] = secret
	return nil
}

func (r *memRing) Delete(service, user string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, service+"/"+user)
	return nil
}

func (r *memRing) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.m)
}

type fixture struct {
	cfg Config
	kit Kit
	s   *Store
}

func testConfig(t *testing.T) Config {
	t.Helper()
	dir, err := os.MkdirTemp("", "hkstore")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return Config{
		DataDir: filepath.Join(dir, "data"), Keyring: newMemRing(),
		Getenv: func(string) string { return "" }, DeviceName: "test device",
	}
}

func newVault(t *testing.T, cfg Config) *fixture {
	t.Helper()
	p, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s)
	return &fixture{cfg: cfg, kit: p.Kit(), s: s}
}

// owners holds the Store that has each test vault open. One Store owns a
// vault at a time, so opening it again first closes the current owner, as
// restarting the daemon would.
var owners sync.Map // DataDir → *Store

func track(t *testing.T, cfg Config, s *Store) {
	owners.Store(cfg.DataDir, s)
	t.Cleanup(func() { s.Close() })
}

func release(cfg Config) {
	if v, ok := owners.LoadAndDelete(cfg.DataDir); ok {
		v.(*Store).Close()
	}
}

// tryOpen closes the vault's current owner and opens it again.
func tryOpen(t *testing.T, cfg Config) (*Store, error) {
	t.Helper()
	release(cfg)
	s, err := Open(context.Background(), cfg)
	if err == nil {
		track(t, cfg, s)
	}
	return s, err
}

func open(t *testing.T, cfg Config) *Store {
	t.Helper()
	s, err := tryOpen(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// sshKey returns a real unencrypted OpenSSH ed25519 key: the PEM and the
// public-key line.
func sshKey(t *testing.T) (string, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block)), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

// addHost puts a key and a host using it, and returns both.
func addHost(t *testing.T, s *Store, name string) (model.Key, model.Host) {
	t.Helper()
	ctx := context.Background()
	privPEM, pub := sshKey(t)
	k, err := s.PutKey(ctx, model.Key{Name: name + "-key", KeyType: "ed25519", PrivateKey: privPEM, PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.PutHost(ctx, model.Host{
		Name: name, Aliases: []string{name + "-alias"}, Addresses: []string{name + ".internal.example"},
		Port: 22, User: "deploy", KeyID: k.ItemID, Route: "auto", AgentAccess: "allow",
	})
	if err != nil {
		t.Fatal(err)
	}
	return k, h
}

func snapshot(t *testing.T, s *Store) model.Snapshot {
	t.Helper()
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func names(snap model.Snapshot) []string {
	var out []string
	for _, h := range snap.Hosts {
		out = append(out, h.Name)
	}
	return out
}

func TestInitWriteAndReopen(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	k, h := addHost(t, f.s, "web-1")
	if h.ItemVersion != 1 || h.KeyID != k.ItemID {
		t.Fatalf("host = %+v", h.Header)
	}
	// Replace: the caller names the current version, the store writes the next.
	h.Description = "front end"
	h2, err := f.s.PutHost(context.Background(), h)
	if err != nil || h2.ItemVersion != 2 {
		t.Fatalf("replace: %+v %v", h2.Header, err)
	}
	if _, err := f.s.PutHost(context.Background(), h); err == nil {
		t.Error("a replace naming a stale version was accepted")
	}
	head, err := f.s.Head()
	if err != nil || head.Seq != 3 {
		t.Fatalf("head = %+v, %v; want seq 3 (genesis and three writes)", head, err)
	}

	again := open(t, cfg)
	snap := snapshot(t, again)
	if len(snap.Hosts) != 1 || snap.Hosts[0].Description != "front end" || snap.Hosts[0].ItemVersion != 2 || len(snap.Keys) != 1 {
		t.Errorf("reopened snapshot = %+v", snap)
	}
	if h2, _ := again.Head(); h2 != head {
		t.Errorf("reopened head %+v, want %+v", h2, head)
	}
	info := again.Info()
	if info.Locked || info.DeviceStore != "keychain" || info.Head == nil {
		t.Errorf("info = %+v", info)
	}

	// Reference integrity: the key cannot go while the host uses it.
	if err := again.Delete(context.Background(), k.ItemID); err == nil {
		t.Error("deleting a key a host refers to was accepted")
	}
	if err := again.Delete(context.Background(), h.ItemID); err != nil {
		t.Fatal(err)
	}
	if err := again.Delete(context.Background(), h.ItemID); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("deleting twice: %v, want ErrNotFound", err)
	}

	// Every directory is 0700 and every file 0600.
	filepath.WalkDir(cfg.DataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		fi, _ := d.Info()
		want := fs.FileMode(0o600)
		if d.IsDir() {
			want = 0o700
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %v", path, fi.Mode().Perm(), want)
		}
		return nil
	})
}

func TestInitRefusesAnExistingVault(t *testing.T) {
	cfg := testConfig(t)
	newVault(t, cfg)
	if _, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword)}); !errors.Is(err, ErrVaultExists) {
		t.Errorf("second init: %v, want ErrVaultExists", err)
	}
	// A short password is refused before anything is generated.
	if _, err := PrepareInit(testConfig(t), InitOptions{Password: []byte("short")}); err == nil {
		t.Error("a 5-byte password was accepted")
	}
}

// An init that stopped after device.json and before its genesis entry left
// no vault: Open says so and init can run again.
func TestInitAfterAnInterruptedInit(t *testing.T) {
	cfg := testConfig(t)
	p, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword)})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.s.l.ensureDirs(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.s.l.deviceConfig(), []byte(`{"v":1,"store":"keychain","account_id":"`+p.Kit().AccountID+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tryOpen(t, cfg); !errors.Is(err, ErrNoVault) {
		t.Errorf("open after an interrupted init: %v, want ErrNoVault", err)
	}
	f := newVault(t, cfg)
	if s := open(t, cfg); s.Info().Locked || s.Info().AccountID != f.kit.AccountID {
		t.Errorf("after init again: %+v", s.Info())
	}
}

func TestKitTextAndTypeBack(t *testing.T) {
	f := newVault(t, testConfig(t))
	text := f.kit.Text()
	for _, want := range []string{f.kit.AccountID, f.kit.SecretKey, f.kit.RecoveryKey, "Keep this offline"} {
		if !strings.Contains(text, want) {
			t.Errorf("kit lacks %q:\n%s", want, text)
		}
	}
	last := LastGroup(f.kit.SecretKey)
	if len(last) != 6 || !SameGroup(strings.ToLower(last), last) || SameGroup(last[:5], last) {
		t.Errorf("last group %q of %q", last, f.kit.SecretKey)
	}
	if got := LastGroup(f.kit.RecoveryKey); len(got) != 5 {
		t.Errorf("recovery key last group %q", got)
	}
}

// A wrong byte in any object makes the vault fail to open, with the
// digest error and the file named.
func TestTamperedObjectFailsClosed(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	addHost(t, f.s, "web-1")
	st := f.s.state
	var target string
	for _, it := range st.Items {
		if it.Type == model.TypeHost {
			target = filepath.Join(cfg.DataDir, "vault", "objects", it.BodySHA256.String())
		}
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(b, []byte(`"ct":"`)) + 10
	b[i] ^= 1
	if err := os.WriteFile(target, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = tryOpen(t, cfg)
	if !errors.Is(err, ErrObjectDigest) || !strings.Contains(err.Error(), filepath.Base(target)) {
		t.Fatalf("open with a tampered object: %v, want ErrObjectDigest naming the file", err)
	}
	t.Logf("tampered object: %v", err)
}

// A wrong byte in an entry's signature fails its signature check.
func TestTamperedEntryFailsClosed(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	addHost(t, f.s, "web-1")
	path := filepath.Join(cfg.DataDir, "vault", "entries", "1.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(b, []byte(`"sig":"`)) + 12
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = tryOpen(t, cfg)
	if !errors.Is(err, ErrCorrupt) || !strings.HasPrefix(string(vaultlog.RuleOf(err)), "sig.") {
		t.Fatalf("open with a tampered entry: %v (rule %q), want a signature failure", err, vaultlog.RuleOf(err))
	}
	t.Logf("tampered entry: %v", err)
}

// state.json ahead of the entries: the last entry was deleted.
func TestDeletedLastEntryIsDetected(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	addHost(t, f.s, "web-1")
	head, _ := f.s.Head()
	if err := os.Remove(filepath.Join(cfg.DataDir, "vault", "entries", fmt.Sprintf("%d.json", head.Seq))); err != nil {
		t.Fatal(err)
	}
	_, err := tryOpen(t, cfg)
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "state head") {
		t.Fatalf("open with the last entry gone: %v", err)
	}
	t.Logf("deleted entry: %v", err)
}

// rollBackState writes the old state.json back, as if the process died
// after writing an entry and before writing the state.
func rollBackState(t *testing.T, cfg Config, old []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "vault", "state.json"), old, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readState(t *testing.T, cfg Config) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(cfg.DataDir, "vault", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCrashBetweenEntryAndStateIsRecovered(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	addHost(t, f.s, "web-1")
	before := readState(t, cfg)
	addHost(t, f.s, "web-2")
	want, _ := f.s.Head()
	rollBackState(t, cfg, before)

	s := open(t, cfg)
	if got, _ := s.Head(); got != want {
		t.Errorf("head after recovery %+v, want %+v", got, want)
	}
	if got := names(snapshot(t, s)); strings.Join(got, ",") != "web-1,web-2" {
		t.Errorf("hosts after recovery = %v", got)
	}
	if string(readState(t, cfg)) == string(before) {
		t.Error("state.json was not brought forward")
	}
	if !slices.ContainsFunc(s.Info().Warnings, func(w string) bool { return strings.Contains(w, "crash interrupted") }) {
		t.Errorf("warnings = %q", s.Info().Warnings)
	}
}

// An entry past the state head is applied only if it verifies: a bad one
// is refused, not skipped and not trusted.
func TestUnverifiedEntryPastStateIsRefused(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	addHost(t, f.s, "web-1")
	before := readState(t, cfg)
	addHost(t, f.s, "web-2") // entries 3 and 4
	rollBackState(t, cfg, before)
	path := filepath.Join(cfg.DataDir, "vault", "entries", "4.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(b, []byte(`"sig":"`)) + 12
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	os.WriteFile(path, b, 0o600)

	s, err := tryOpen(t, cfg)
	if err == nil {
		t.Fatalf("a tampered entry past the state head was accepted; hosts %v", names(snapshot(t, s)))
	}
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "past the state head") {
		t.Errorf("err = %v", err)
	}
}

// One Store owns a vault: a second Open, which a second process would
// make, is refused until the owner closes. The daemon is that owner.
func TestSecondOpenIsRefused(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg) // Commit's store owns the vault
	if _, err := Open(context.Background(), cfg); !errors.Is(err, ErrVaultBusy) {
		t.Fatalf("open while init's store is open: %v, want ErrVaultBusy", err)
	}
	addHost(t, f.s, "web-1")
	s := open(t, cfg) // closes f.s first
	if _, err := Open(context.Background(), cfg); !errors.Is(err, ErrVaultBusy) || !strings.Contains(err.Error(), "another hop process owns it") {
		t.Fatalf("second open: %v, want ErrVaultBusy saying another process owns the vault", err)
	}
	if got := names(snapshot(t, s)); len(got) != 1 {
		t.Errorf("hosts = %v", got)
	}
	// A closed store holds nothing and cannot be unlocked again.
	if err := f.s.Unlock(context.Background()); err == nil {
		t.Error("a closed store unlocked")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open after close: %v", err)
	}
	again.Close()
}

func TestLockDropsSecrets(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	addHost(t, f.s, "web-1")
	f.s.Lock()
	ctx := context.Background()
	if _, err := f.s.Snapshot(ctx); !errors.Is(err, model.ErrLocked) {
		t.Errorf("snapshot while locked: %v", err)
	}
	if _, err := f.s.PutSnippet(ctx, model.Snippet{Name: "x", Command: "true"}); !errors.Is(err, model.ErrLocked) {
		t.Errorf("put while locked: %v", err)
	}
	if _, err := f.s.Head(); !errors.Is(err, model.ErrLocked) {
		t.Errorf("head while locked: %v", err)
	}
	if !f.s.Info().Locked {
		t.Error("info does not say locked")
	}
	if err := f.s.Unlock(ctx); err != nil {
		t.Fatal(err)
	}
	if got := names(snapshot(t, f.s)); len(got) != 1 {
		t.Errorf("hosts after unlock = %v", got)
	}
}

// The keychain backend through go-keyring's own mock provider, and the
// refusal to fall back when the keychain is unusable.
func TestKeychainBackend(t *testing.T) {
	keyring.MockInit()
	cfg := testConfig(t)
	cfg.Keyring = OSKeyring{}
	f := newVault(t, cfg)
	raw, err := keyring.Get(keychainService, deviceSlot(t, cfg))
	if err != nil {
		t.Fatalf("no device key in the keychain: %v", err)
	}
	if rec, err := parseDeviceRecord([]byte(raw)); err != nil || rec.SecretKey != f.kit.SecretKey {
		t.Errorf("keychain record: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "device.key")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("device.key exists with the keychain store: %v", err)
	}
	addHost(t, f.s, "web-1")
	if s := open(t, cfg); s.Info().Locked {
		t.Errorf("reopen through the keychain: %+v", s.Info())
	}

	// Entry gone from the keychain: the store opens locked and says why.
	keyring.Delete(keychainService, deviceSlot(t, cfg))
	s := open(t, cfg)
	if info := s.Info(); !info.Locked || !strings.Contains(info.LockReason, "keychain") {
		t.Errorf("info without the keychain entry = %+v", info)
	}

	keyring.MockInitWithError(errors.New("no Secret Service on this bus"))
	cfg2 := testConfig(t)
	cfg2.Keyring = OSKeyring{}
	_, err = PrepareInit(cfg2, InitOptions{Password: []byte(testPassword)})
	if !errors.Is(err, ErrKeychainUnusable) || !strings.Contains(err.Error(), "--device-key-store=file") {
		t.Errorf("init with a broken keychain: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg2.DataDir, "device.key")); !errors.Is(err, os.ErrNotExist) {
		t.Error("init fell back to the file store")
	}
	keyring.MockInit()
}

func TestFileBackend(t *testing.T) {
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
			addHost(t, s, "web-1")
			raw, err := os.ReadFile(filepath.Join(cfg.DataDir, "device.key"))
			if err != nil {
				t.Fatal(err)
			}
			if got := bytes.Contains(raw, []byte(p.Kit().SecretKey)); got == sealed {
				t.Errorf("sealed=%v but the Secret Key in device.key is visible=%v", sealed, got)
			}
			if s := open(t, cfg); s.Info().Locked || !strings.HasPrefix(s.Info().DeviceStore, "file ") {
				t.Errorf("reopen: %+v", s.Info())
			}
			if !sealed {
				return
			}
			pass = ""
			if info := open(t, cfg).Info(); !info.Locked || !strings.Contains(info.LockReason, PassphraseEnv) {
				t.Errorf("no passphrase: %+v", info)
			}
			pass = "wrong passphrase"
			if info := open(t, cfg).Info(); !info.Locked {
				t.Errorf("wrong passphrase: %+v", info)
			}
		})
	}
}

func TestUnlockWithPassword(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	addHost(t, f.s, "web-1")
	ring := cfg.Keyring.(*memRing)
	oldDev := f.s.Info().DeviceID
	ring.clear() // the keychain entry is lost

	s := open(t, cfg)
	if !s.Info().Locked {
		t.Fatal("opened without a device key")
	}
	ctx := context.Background()
	if err := s.UnlockWithPassword(ctx, []byte("not the password"), f.kit.SecretKey); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("wrong password: %v", err)
	}
	if err := s.UnlockWithPassword(ctx, []byte(testPassword), ""); !errors.Is(err, ErrNeedSecretKey) {
		t.Errorf("no stored Secret Key: %v", err)
	}
	if !s.Info().Locked {
		t.Error("unlocked after failures")
	}
	if err := s.UnlockWithPassword(ctx, []byte(testPassword), strings.ToLower(f.kit.SecretKey)); err != nil {
		t.Fatal(err)
	}
	info := s.Info()
	if info.Locked || info.DeviceID == oldDev {
		t.Errorf("after password unlock: %+v (old device %s)", info, oldDev)
	}
	if got := names(snapshot(t, s)); len(got) != 1 {
		t.Errorf("hosts = %v", got)
	}
	if n := len(s.state.Devices); n != 2 {
		t.Errorf("%d devices, want 2 (the bootstrap adds one)", n)
	}
	// The new device key, with the Secret Key, is stored: a plain reopen works.
	again := open(t, cfg)
	if again.Info().Locked || again.Info().DeviceID != info.DeviceID {
		t.Errorf("reopen after password unlock: %+v", again.Info())
	}
	// And a later password unlock needs no Secret Key.
	if err := again.UnlockWithPassword(ctx, []byte(testPassword), ""); err != nil {
		t.Errorf("password unlock with the stored Secret Key: %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	addHost(t, f.s, "web-1")
	ctx := context.Background()
	const newPassword = "a much better password"
	if _, err := f.s.ChangePassword(ctx, []byte("wrong current"), []byte(newPassword)); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong current password: %v", err)
	}
	before := snapshot(t, f.s)
	kit, err := f.s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword))
	if err != nil {
		t.Fatal(err)
	}
	if kit.SecretKey == f.kit.SecretKey || kit.RecoveryKey == f.kit.RecoveryKey || kit.AccountID != f.kit.AccountID {
		t.Errorf("new kit %+v reuses the old one", kit)
	}
	if p := f.s.PendingKit(); p == nil || p.SecretKey != kit.SecretKey {
		t.Errorf("pending kit = %+v", p)
	}
	if _, err := f.s.ChangePassword(ctx, []byte(newPassword), []byte(testPassword)); !errors.Is(err, ErrKitPending) {
		t.Errorf("second change with a kit pending: %v", err)
	}
	if f.s.state.Account.AKV != 2 || f.s.state.KV != 2 {
		t.Errorf("akv %d kv %d after the checkpoint", f.s.state.Account.AKV, f.s.state.KV)
	}
	after := snapshot(t, f.s)
	if len(after.Hosts) != 1 || after.Hosts[0].Name != before.Hosts[0].Name || after.Hosts[0].ItemVersion != before.Hosts[0].ItemVersion+1 {
		t.Errorf("items after the checkpoint: %+v", after.Hosts)
	}
	if err := f.s.AckKit(); err != nil || f.s.PendingKit() != nil {
		t.Errorf("ack: %v", err)
	}
	if ents, _ := os.ReadDir(filepath.Join(cfg.DataDir, "vault", "journal")); len(ents) != 0 {
		t.Errorf("journal not cleared: %v", ents)
	}

	// Reopen with the device key; then the old password fails and the new
	// one works, with the stored (new) Secret Key.
	s := open(t, cfg)
	if s.Info().Locked {
		t.Fatalf("reopen after passwd: %+v", s.Info())
	}
	if err := s.UnlockWithPassword(ctx, []byte(testPassword), ""); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("old password: %v", err)
	}
	if err := s.UnlockWithPassword(ctx, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("old password with the old Secret Key: %v", err)
	}
	if err := s.UnlockWithPassword(ctx, []byte(newPassword), ""); err != nil {
		t.Errorf("new password: %v", err)
	}
	if got := names(snapshot(t, s)); len(got) != 1 {
		t.Errorf("hosts = %v", got)
	}
}

// A crash after the candidate is journaled and before its entry is written:
// the head is still its prev, so the next unlock writes the identical
// entry, verified, and the kit becomes pending (§5.4).
func TestPasswdCrashAfterJournal(t *testing.T) {
	testPasswdCrash(t, "journaled")
}

// A crash after the entry and before state.json: recovery verifies the
// checkpoint with the transition algorithm and finishes from the journal.
func TestPasswdCrashAfterEntry(t *testing.T) {
	testPasswdCrash(t, "entry")
}

func testPasswdCrash(t *testing.T, stage string) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	addHost(t, f.s, "web-1")
	ctx := context.Background()
	const newPassword = "a much better password"
	crash := errors.New("simulated crash")
	f.s.testHook = func(s string) error {
		if s == stage {
			return crash
		}
		return nil
	}
	if _, err := f.s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword)); !errors.Is(err, crash) {
		t.Fatalf("change: %v", err)
	}

	s := open(t, cfg)
	if s.Info().Locked {
		t.Fatalf("reopen: %+v", s.Info())
	}
	kit := s.PendingKit()
	if kit == nil || kit.SecretKey == f.kit.SecretKey {
		t.Fatalf("pending kit after recovery = %+v", kit)
	}
	if s.state.Account.AKV != 2 {
		t.Errorf("akv %d after recovery, want 2", s.state.Account.AKV)
	}
	if s.rec.SecretKey != kit.SecretKey {
		t.Error("the stored Secret Key was not updated")
	}
	if err := s.UnlockWithPassword(ctx, []byte(newPassword), ""); err != nil {
		t.Errorf("new password after recovery: %v", err)
	}
	if got := names(snapshot(t, s)); len(got) != 1 {
		t.Errorf("hosts = %v", got)
	}
}

// After every test above, nothing secret is on disk. This one checks it
// directly for a vault with a host, a key and a credential.
func TestNoPlaintextOnDisk(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	k, h := addHost(t, f.s, "secret-host-name")
	if _, err := f.s.PutCredential(context.Background(), model.Credential{Name: "db", Username: "db.admin.user", Password: "credential.password.xyzzy"}); err != nil {
		t.Fatal(err)
	}
	needles := []string{h.Name, h.Aliases[0], h.Addresses[0], testPassword, "credential.password.xyzzy", "db.admin.user",
		f.kit.SecretKey, f.kit.RecoveryKey}
	needles = append(needles, pemSecretLines(k.PrivateKey)...)
	needles = append(needles, keyNeedles(t, f.s)...)
	scanForPlaintext(t, cfg.DataDir, needles)

	// Again with a password change committed and its kit not confirmed:
	// the journal holds the new Secret Key and Recovery Key, sealed.
	kit, err := f.s.ChangePassword(context.Background(), []byte(testPassword), []byte("a much better password"))
	if err != nil {
		t.Fatal(err)
	}
	if f.s.PendingKit() == nil {
		t.Fatal("no kit pending")
	}
	needles = append(needles, kit.SecretKey, kit.RecoveryKey, "a much better password")
	needles = append(needles, keyNeedles(t, f.s)...)
	scanForPlaintext(t, cfg.DataDir, needles)
}

// pemSecretLines returns the PEM body lines that carry key material. The
// first line of every OpenSSH key is the same public header, and a short
// last line could turn up by chance, so both are left out.
func pemSecretLines(privPEM string) []string {
	lines := strings.Split(strings.TrimSpace(privPEM), "\n")
	var out []string
	for _, l := range lines[2 : len(lines)-1] {
		if len(l) >= 32 {
			out = append(out, l)
		}
	}
	return out
}

// scanForPlaintext reads every file under dir, the vault and the device
// key file, for the needles. The Emergency Kit file a user asks hop init or
// hop passwd to write (--kit-file) is the one place the Secret Key and the
// Recovery Key are meant to be in the clear; it is never under dir.
func scanForPlaintext(t *testing.T, dir string, needles []string) {
	t.Helper()
	files := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files++
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range needles {
			if bytes.Contains(b, []byte(n)) {
				t.Errorf("%s contains %q", path, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning %s: %v", dir, err)
	}
	if files < 5 {
		t.Fatalf("scanned only %d files under %s", files, dir)
	}
}
