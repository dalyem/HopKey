package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// checkpointOn posts to r a checkpoint built by s that revokes the devices
// in revoke and recertifies every other active one (§10.1), and returns
// the new account keys, as a login after it opens them from pw_blob.
func checkpointOn(t *testing.T, s *Store, r *fakeRemote, revoke []model.ID) *crypto.AccountKeys {
	t.Helper()
	acct, _ := checkpointKit(t, s, r, revoke)
	return acct
}

// checkpointKit is checkpointOn that also returns the new Secret Key.
func checkpointKit(t *testing.T, s *Store, r *fakeRemote, revoke []model.ID) (*crypto.AccountKeys, string) {
	t.Helper()
	pull(t, s, r)
	sk, err := crypto.NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	rk, err := crypto.NewRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	vk, err := crypto.NewSymKey()
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	acct, err := crypto.GenerateAccountKeys(s.state.Account.AccountID, s.state.Account.AKV+1)
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	creds, err := newCreds([]byte(testPassword), &sk, &rk, acct)
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	w, _, _, err := vaultlog.BuildCheckpoint(s.state, s.sec, s.dev, vaultlog.CheckpointParams{
		NewAccount: acct, NewVK: vk, Creds: creds, Time: s.now(), Revoke: revoke,
	})
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Post(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	pull(t, s, r)
	return cloneAccountKeys(t, acct), sk.String()
}

// prefix is a server holding only the first n entries of f's log: one
// that withholds the rest.
func (f *fakeRemote) prefix(n int) *fakeRemote {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := &fakeRemote{objects: map[crypto.Hash][]byte{}}
	g.entries = slices.Clone(f.entries[:n])
	g.hashes = slices.Clone(f.hashes[:n])
	for h, b := range f.objects {
		g.objects[h] = b
	}
	return g
}

// lenient makes the token outlive a credential change: a server that
// breaks plan R2, for tests of the client's own defenses.
func (s *signInRemote) lenient() *signInRemote {
	s.lax = true
	return s
}

// untrackedRecords lists the device records (not tombstones) in cfg's
// device key stores that device.json does not name: in the keychain, an
// entry whose account and device are not this device, its pending
// replacement, a stale device, or a merge's destination device or its
// stale ones; and device.key or device.next.key holding a record of a
// device device.json does not name there.
func untrackedRecords(t *testing.T, cfg Config) []string {
	t.Helper()
	tracked := map[string]bool{}
	dkey, dnext := map[model.ID]bool{}, map[model.ID]bool{}
	var dc *deviceConfig
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "device.json")); err == nil {
		c := diskDeviceConfig(t, cfg)
		dc = &c
		for _, id := range append(c.self(), c.StaleDevices...) {
			tracked[slotOf(c.AccountID, id)] = true
			dkey[id] = true
		}
		if c.Next != nil {
			for _, id := range append([]model.ID{c.Next.DeviceID}, c.Next.Stale...) {
				tracked[slotOf(c.Next.AccountID, id)] = true
			}
			dnext[c.Next.DeviceID] = true
		}
	}
	var out []string
	if ring, ok := cfg.Keyring.(*memRing); ok {
		ring.mu.Lock()
		for k, v := range ring.m {
			user, ok := strings.CutPrefix(k, keychainService+"/")
			if !ok || user == "probe" {
				continue
			}
			if _, tomb := parseTombstone([]byte(v)); !tomb && !tracked[user] {
				out = append(out, "keychain "+user)
			}
		}
		ring.mu.Unlock()
	}
	for name, ok := range map[string]map[model.ID]bool{"device.key": dkey, nextKeyName: dnext} {
		b, err := os.ReadFile(filepath.Join(cfg.DataDir, name))
		if err != nil {
			continue
		}
		var f struct {
			DeviceID model.ID `json:"device_id"`
			Revoked  bool     `json:"revoked"`
		}
		if json.Unmarshal(b, &f) != nil || (!f.Revoked && (dc == nil || !ok[f.DeviceID])) {
			out = append(out, name+" "+f.DeviceID.String())
		}
	}
	return out
}

func noUntrackedRecords(t *testing.T, cfg Config, when string) {
	t.Helper()
	if u := untrackedRecords(t, cfg); len(u) > 0 {
		t.Errorf("%s: device records device.json does not name: %v", when, u)
	}
}

// activeCount is how many devices are active on srv.
func activeCount(t *testing.T, srv *fakeServer) int {
	t.Helper()
	pub, _, _ := srv.public(t)
	return len(srv.activeDevices(t, pub))
}

// readFailRing fails every read of entries whose name holds match, as an
// unreachable Secret Service would, while on.
type readFailRing struct {
	*memRing
	mu      sync.Mutex
	match   string
	failSet string
}

var errKeychainDown = errors.New("keychain: the Secret Service is not answering")

func (r *readFailRing) set(match string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.match = match
}

// setFail fails every write of entries whose name holds match, as a
// keychain that refuses writes would, while on.
func (r *readFailRing) setFail(match string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failSet = match
}

func (r *readFailRing) Set(service, user, secret string) error {
	r.mu.Lock()
	m := r.failSet
	r.mu.Unlock()
	if m != "" && strings.Contains(user, m) {
		return errKeychainDown
	}
	return r.memRing.Set(service, user, secret)
}

func (r *readFailRing) Get(service, user string) (string, error) {
	r.mu.Lock()
	m := r.match
	r.mu.Unlock()
	if m != "" && strings.Contains(user, m) {
		return "", errKeychainDown
	}
	return r.memRing.Get(service, user)
}

// mergeFixIn is newMergeFix with the source's device key in store, and
// its keychain behind a readFailRing.
func mergeFixIn(t *testing.T, store string) (*mergeFix, *readFailRing) {
	t.Helper()
	ring := &readFailRing{memRing: newMemRing()}
	cfg := testConfig(t)
	cfg.Keyring = ring
	m := newMergeFix(t, cfg)
	if store == DeviceStoreFile {
		m.src = fileSource(t, m)
	}
	return m, ring
}

// nextOf is the destination device device.json names.
func nextOf(t *testing.T, cfg Config) *nextDevice {
	t.Helper()
	dc := diskDeviceConfig(t, cfg)
	if dc.Next == nil {
		t.Fatal("device.json names no destination device")
	}
	return dc.Next
}

// interruptedMerge seals a merge on m's source and runs a sign-in that
// stops at stage, and returns the destination device it named.
func interruptedMerge(t *testing.T, m *mergeFix, stage string) *nextDevice {
	t.Helper()
	s := m.src.s
	if _, err := s.MergeStart(); err != nil {
		t.Fatal(err)
	}
	s.testHook = crashAt(stage)
	if _, err := m.signIn(t, s); !errors.Is(err, errCrash) {
		t.Fatalf("sign-in: %v", err)
	}
	s.testHook = nil
	return nextOf(t, m.src.cfg)
}

// Finding 1: a destination record that holds a tombstone is terminal: the
// sign-in refuses, the tombstone is never overwritten and nothing is
// posted. Cancel then unfreezes the source.
func TestMergeNextTombstoneIsTerminal(t *testing.T) {
	for _, store := range []string{DeviceStoreKeychain, DeviceStoreFile} {
		t.Run(store, func(t *testing.T) {
			m, _ := mergeFixIn(t, store)
			next := interruptedMerge(t, m, "signin:post")
			dc := diskDeviceConfig(t, m.src.cfg)
			if err := m.src.s.nextStore(dc).tombstone(next.DeviceID); err != nil {
				t.Fatal(err)
			}
			posts := m.r.postCount()
			if _, err := m.signIn(t, m.src.s); !errors.Is(err, ErrSignInRevoked) {
				t.Fatalf("sign-in over a tombstone: %v", err)
			}
			if !nextTombstoned(t, m, next) {
				t.Error("the tombstone was overwritten")
			}
			if got := nextOf(t, m.src.cfg); got.DeviceID != next.DeviceID || len(got.Stale) != 0 {
				t.Errorf("device.json next %+v; want %+v unchanged", got, next)
			}
			if m.r.postCount() != posts {
				t.Error("a bootstrap was posted")
			}
			noUntrackedRecords(t, m.src.cfg, "after the refusal")
			if err := m.src.s.MergeCancel(MergeCancelOptions{}); err != nil {
				t.Fatalf("cancel with a tombstoned destination: %v", err)
			}
			if diskDeviceConfig(t, m.src.cfg).Next != nil {
				t.Error("cancel left the destination device in device.json")
			}
			m.sourceIntact(t, m.src.s)
		})
	}
}

// nextTombstoned reports whether the destination record of next is its
// tombstone.
func nextTombstoned(t *testing.T, m *mergeFix, next *nextDevice) bool {
	t.Helper()
	var raw []byte
	if diskDeviceConfig(t, m.src.cfg).Store == DeviceStoreFile {
		raw, _ = os.ReadFile(filepath.Join(m.src.cfg.DataDir, nextKeyName))
	} else if v, err := m.src.cfg.Keyring.Get(keychainService, slotOf(next.AccountID, next.DeviceID)); err == nil {
		raw = []byte(v)
	}
	tomb, ok := parseTombstone(raw)
	return ok && tomb.AccountID == next.AccountID
}

// Finding 1: a read of the destination record that is not conclusive
// changes nothing: no new record, nothing stale, nothing posted. Once it
// reads, the same device is used.
func TestMergeNextTransientReadChangesNothing(t *testing.T) {
	for _, store := range []string{DeviceStoreKeychain, DeviceStoreFile} {
		t.Run(store, func(t *testing.T) {
			m, ring := mergeFixIn(t, store)
			next := interruptedMerge(t, m, "signin:post")
			nextKey := filepath.Join(m.src.cfg.DataDir, nextKeyName)
			fileBefore, _ := os.ReadFile(nextKey)
			var fail *failKeyFile
			if store == DeviceStoreFile {
				fail = installFailKeyFile(t, m.src.cfg, syscall.EIO)
				fail.path = nextKey
				fail.set(true)
			} else {
				ring.set(next.DeviceID.String())
			}
			before := len(ring.memRing.m)
			posts := m.r.postCount()
			if _, err := m.signIn(t, m.src.s); !errors.Is(err, ErrKeyStoreUnavailable) {
				t.Fatalf("sign-in with an unreadable destination record: %v", err)
			}
			if got := nextOf(t, m.src.cfg); got.DeviceID != next.DeviceID || len(got.Stale) != 0 {
				t.Errorf("device.json next %+v; want %+v unchanged", got, next)
			}
			fileAfter, _ := os.ReadFile(nextKey)
			if len(ring.memRing.m) != before || string(fileAfter) != string(fileBefore) || m.r.postCount() != posts {
				t.Error("an inconclusive read created a record or posted")
			}
			ring.set("")
			if fail != nil {
				fail.set(false)
			}
			if _, err := m.signIn(t, m.src.s); err != nil {
				t.Fatal(err)
			}
			if dc := diskDeviceConfig(t, m.src.cfg); dc.DeviceID != next.DeviceID || len(dc.StaleDevices) != 0 {
				t.Errorf("device.json %+v; want the same destination device, nothing stale", dc)
			}
			if n := activeCount(t, m.srv); n != 2 {
				t.Errorf("%d active devices; want 2", n)
			}
		})
	}
}

// Finding 1: a destination record confirmed gone after its bootstrap
// committed is recorded as stale before another device is made, and once
// the destination is installed it is a stale device, active in the log,
// for hop passwd to revoke.
func TestMergeNextLostAfterBootstrapIsStale(t *testing.T) {
	for _, store := range []string{DeviceStoreKeychain, DeviceStoreFile} {
		t.Run(store, func(t *testing.T) {
			m, _ := mergeFixIn(t, store)
			s := m.src.s
			if _, err := s.MergeStart(); err != nil {
				t.Fatal(err)
			}
			m.srv.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
			if _, err := m.signIn(t, s); !errors.Is(err, errLostResponse) {
				t.Fatalf("sign-in: %v", err)
			}
			m.srv.onPost = nil
			lost := nextOf(t, m.src.cfg)
			if n := activeCount(t, m.srv); n != 2 {
				t.Fatalf("%d active devices; want the bootstrap committed", n)
			}
			if store == DeviceStoreFile {
				if err := os.Remove(filepath.Join(m.src.cfg.DataDir, nextKeyName)); err != nil {
					t.Fatal(err)
				}
			} else if err := m.src.cfg.Keyring.Delete(keychainService, slotOf(lost.AccountID, lost.DeviceID)); err != nil {
				t.Fatal(err)
			}
			s.testHook = crashAt("signin:fetch")
			if _, err := m.signIn(t, s); !errors.Is(err, errCrash) {
				t.Fatalf("sign-in: %v", err)
			}
			s.testHook = nil
			if got := nextOf(t, m.src.cfg); got.DeviceID == lost.DeviceID || !slices.Contains(got.Stale, lost.DeviceID) {
				t.Fatalf("device.json next %+v; want a new device with %v stale", got, lost.DeviceID)
			}
			if _, err := m.signIn(t, s); err != nil {
				t.Fatal(err)
			}
			dc := diskDeviceConfig(t, m.src.cfg)
			if !slices.Contains(dc.StaleDevices, lost.DeviceID) {
				t.Errorf("device.json stale %v; want %v, whose bootstrap committed", dc.StaleDevices, lost.DeviceID)
			}
			if info := s.Info(); info.StaleDevices != 1 {
				t.Errorf("Info reports %d stale devices; want 1", info.StaleDevices)
			}
			noUntrackedRecords(t, m.src.cfg, "after the sign-in")
		})
	}
}

// Finding 3: device.json names the destination device before its record
// is created, so an interrupted sign-in at any point leaves no record that
// device.json does not track, and the next attempt resolves it.
func TestMergeSignInLeavesNoUntrackedRecords(t *testing.T) {
	stages := []string{"signin:record", "signin:intent", "signin:next", "signin:fetch", "signin:post", "signin:drop", "signin:promote", "merge:enqueue"}
	for _, store := range []string{DeviceStoreKeychain, DeviceStoreFile} {
		for _, stage := range stages {
			t.Run(store+" "+stage, func(t *testing.T) {
				m, _ := mergeFixIn(t, store)
				s := m.src.s
				if _, err := s.MergeStart(); err != nil {
					t.Fatal(err)
				}
				s.testHook = crashAt(stage)
				if _, err := m.signIn(t, s); !errors.Is(err, errCrash) {
					t.Fatalf("sign-in: %v", err)
				}
				noUntrackedRecords(t, m.src.cfg, "after the crash")
				s = open(t, m.src.cfg)
				noUntrackedRecords(t, m.src.cfg, "after a restart")
				if !s.ServerBacked() {
					if _, err := m.signIn(t, s); err != nil {
						t.Fatal(err)
					}
				}
				noUntrackedRecords(t, m.src.cfg, "after the sign-in")
				if n := activeCount(t, m.srv); n != 2 {
					t.Errorf("%d active devices; want 2", n)
				}
			})
		}
	}
}

// Finding 2: a checkpoint after the bootstrap that keeps the destination
// device. A conforming server ends the login token with it (R2): the
// sign-in stops, and the next one, with the new account keys, anchors at
// the checkpoint and uses the same device. A server that keeps the token
// lets the sign-in cross the checkpoint, which it does as the destination
// device, opening its new unlock blob. Either way the vault reopens.
func TestMergeSignInCheckpointKeepsDevice(t *testing.T) {
	for _, lenient := range []bool{false, true} {
		t.Run(map[bool]string{false: "token ended", true: "token kept"}[lenient], func(t *testing.T) {
			m := newMergeFix(t, testConfig(t))
			s := m.src.s
			if _, err := s.MergeStart(); err != nil {
				t.Fatal(err)
			}
			var newAcct *crypto.AccountKeys
			posted, done := false, false
			m.srv.onPost = func(*vaultlog.Wire) (bool, error) { posted = true; return true, nil }
			m.r.onSince = func(context.Context) {
				if posted && !done {
					done = true
					newAcct = checkpointOn(t, m.dst.s, m.r, nil)
				}
			}
			r := m.srv.login(t)
			if lenient {
				r.lenient()
			}
			_, err := s.MergeSignIn(context.Background(), r, m.params(t))
			m.srv.onPost, m.r.onSince = nil, nil
			if !lenient {
				if !errors.Is(err, errTokenInvalid) {
					t.Fatalf("sign-in across a checkpoint: %v", err)
				}
				dev := nextOf(t, m.src.cfg).DeviceID
				p := m.params(t)
				p.Account = newAcct
				if _, err = s.MergeSignIn(context.Background(), m.srv.login(t), p); err != nil {
					t.Fatal(err)
				}
				if got := diskDeviceConfig(t, m.src.cfg).DeviceID; got != dev {
					t.Errorf("the sign-in installed device %v; want %v, the one the checkpoint kept", got, dev)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			akv := s.state.Account.AKV
			s.mu.Unlock()
			if akv != 2 {
				t.Errorf("installed at akv %d; want the checkpoint's", akv)
			}
			if n := activeCount(t, m.srv); n != 2 {
				t.Errorf("%d active devices; want 2", n)
			}
			s = open(t, m.src.cfg)
			if s.Info().Locked {
				t.Fatalf("the destination does not reopen: %s", s.Info().LockReason)
			}
			if res := pushAll(t, s, m.r); res.Outcome != PushEmpty {
				t.Fatalf("push: %+v", res)
			}
			m.imported(t)
		})
	}
}

// Finding 2: a checkpoint after the bootstrap that revokes the destination
// device. Met while the sign-in crosses it (a server that keeps the token),
// or at the anchor of the next sign-in (one that ends it), it is terminal:
// the record becomes a tombstone, and no later attempt uses it, after a
// restart too, even from a server that withholds the checkpoint.
func TestMergeSignInCheckpointRevokesDevice(t *testing.T) {
	for _, lenient := range []bool{false, true} {
		t.Run(map[bool]string{false: "token ended", true: "token kept"}[lenient], func(t *testing.T) {
			m := newMergeFix(t, testConfig(t))
			s := m.src.s
			if _, err := s.MergeStart(); err != nil {
				t.Fatal(err)
			}
			withheld := 0
			var newAcct *crypto.AccountKeys
			posted, done := false, false
			m.srv.onPost = func(*vaultlog.Wire) (bool, error) { posted = true; return true, nil }
			m.r.onSince = func(context.Context) {
				if posted && !done {
					done = true
					m.r.mu.Lock()
					withheld = len(m.r.entries)
					m.r.mu.Unlock()
					newAcct = checkpointOn(t, m.dst.s, m.r, []model.ID{nextOf(t, m.src.cfg).DeviceID})
				}
			}
			r := m.srv.login(t)
			if lenient {
				r.lenient()
			}
			_, err := s.MergeSignIn(context.Background(), r, m.params(t))
			m.srv.onPost, m.r.onSince = nil, nil
			next := nextOf(t, m.src.cfg)
			if !lenient {
				if !errors.Is(err, errTokenInvalid) {
					t.Fatalf("sign-in across a checkpoint: %v", err)
				}
				p := m.params(t)
				p.Account = newAcct
				_, err = s.MergeSignIn(context.Background(), m.srv.login(t), p)
			}
			if !errors.Is(err, ErrSignInRevoked) {
				t.Fatalf("sign-in with the device revoked: %v", err)
			}
			if !nextTombstoned(t, m, next) {
				t.Fatal("the revoked destination device's record is not a tombstone")
			}
			if errors.Is(err, ErrDeviceRevoked) || s.IsRevoked() {
				t.Error("the source vault was marked revoked")
			}
			m.sourceIntact(t, s)
			// A server that withholds the checkpoint, after a restart.
			s = open(t, m.src.cfg)
			hidden := newFakeServer(t, m.r.prefix(withheld))
			posts := hidden.postCount()
			if _, err := s.MergeSignIn(context.Background(), hidden.login(t), m.params(t)); !errors.Is(err, ErrSignInRevoked) {
				t.Fatalf("sign-in against a server that withholds the revocation: %v", err)
			}
			if hidden.postCount() != posts {
				t.Error("a bootstrap was posted")
			}
			m.sourceIntact(t, s)
			if err := s.MergeCancel(MergeCancelOptions{}); err != nil {
				t.Fatalf("cancel: %v", err)
			}
			m.sourceIntact(t, s)
		})
	}
}

// Finding 5: a password unlock after the merge's drop committed and its
// promotion failed promotes first, as an unlock does, so it works on the
// destination's device records, not the dropped source's.
func TestPasswordUnlockFinishesMergePromotion(t *testing.T) {
	for _, store := range []string{DeviceStoreKeychain, DeviceStoreFile} {
		t.Run(store, func(t *testing.T) {
			m, _ := mergeFixIn(t, store)
			s := m.src.s
			if _, err := s.MergeStart(); err != nil {
				t.Fatal(err)
			}
			s.testHook = crashAt("signin:promote")
			if _, err := m.signIn(t, s); !errors.Is(err, errCrash) {
				t.Fatalf("sign-in: %v", err)
			}
			s.testHook = nil
			if diskDeviceConfig(t, m.src.cfg).Next == nil {
				t.Fatal("the promotion happened")
			}
			if err := s.UnlockWithPasswordRemote(context.Background(), m.r, []byte(testPassword), m.dst.kit.SecretKey); err != nil {
				t.Fatalf("password unlock after a failed promotion: %v", err)
			}
			dc := diskDeviceConfig(t, m.src.cfg)
			if dc.AccountID != m.acct.AccountID || dc.Next != nil {
				t.Errorf("device.json %+v; want the destination's, promoted", dc)
			}
			if info := s.Info(); info.Locked || info.AccountID != m.dst.kit.AccountID {
				t.Fatalf("after the unlock: %+v", info)
			}
			if res := pushAll(t, s, m.r); res.Outcome != PushEmpty {
				t.Fatalf("push: %+v", res)
			}
			m.imported(t)
			noUntrackedRecords(t, m.src.cfg, "after the unlock")
		})
	}
}

// liar is a SignInRemote that changes what the server answers: its Since
// passes the true answer through lie.
type liar struct {
	*signInRemote
	lie func(cs []Committed, head vaultlog.Head) ([]Committed, vaultlog.Head)
}

func (l liar) Since(ctx context.Context, after uint64) ([]Committed, vaultlog.Head, error) {
	cs, head, err := l.signInRemote.Since(ctx, after)
	if err != nil {
		return nil, head, err
	}
	cs, head = l.lie(cs, head)
	return cs, head, nil
}

// lies are adversarial Since answers, each with the error a sign-in must
// fail with: a head behind the entries returned (a regression), a head at
// the last entry's seq with another H, and an entry at a seq already held
// with another H (both equivocations, §5.6).
func lies(t *testing.T) map[string]struct {
	lie  func(cs []Committed, head vaultlog.Head) ([]Committed, vaultlog.Head)
	want func(error) bool
} {
	isEq := func(err error) bool { var eq *vaultlog.EquivocationError; return errors.As(err, &eq) }
	return map[string]struct {
		lie  func(cs []Committed, head vaultlog.Head) ([]Committed, vaultlog.Head)
		want func(error) bool
	}{
		"head regression": {
			lie: func(cs []Committed, head vaultlog.Head) ([]Committed, vaultlog.Head) {
				if head.Seq > 0 {
					head.Seq--
				}
				return cs, head
			},
			want: func(err error) bool { return errors.Is(err, ErrServerBehind) },
		},
		"head with another H": {
			lie: func(cs []Committed, head vaultlog.Head) ([]Committed, vaultlog.Head) {
				head.H[0] ^= 1
				return cs, head
			},
			want: isEq,
		},
		"held entry with another H": {
			lie: func(cs []Committed, head vaultlog.Head) ([]Committed, vaultlog.Head) {
				if len(cs) == 0 {
					return cs, head
				}
				// The genesis entry again, re-signed by nobody: another
				// entry at seq 0.
				g := *cs[0].Wire
				g.Entry.Seq, g.Entry.Time = 0, g.Entry.Time+1
				h, err := g.Entry.Hash()
				if err != nil {
					t.Fatal(err)
				}
				return append([]Committed{{Seq: 0, H: h, Wire: &g}}, cs...), head
			},
			want: isEq,
		},
	}
}

// Finding 6: the sign-in's fetch checks every head the server reports
// against the log it holds: a regression and an equivocation are refused,
// and nothing is posted or installed.
func TestSignInFetchRejectsContradictoryHeads(t *testing.T) {
	for name, c := range lies(t) {
		t.Run("merge "+name, func(t *testing.T) {
			m := newMergeFix(t, testConfig(t))
			if _, err := m.src.s.MergeStart(); err != nil {
				t.Fatal(err)
			}
			posts := m.r.postCount()
			_, err := m.src.s.MergeSignIn(context.Background(), liar{m.srv.login(t), c.lie}, m.params(t))
			if !c.want(err) {
				t.Fatalf("sign-in: %v", err)
			}
			if m.r.postCount() != posts {
				t.Error("a bootstrap was posted")
			}
			m.sourceIntact(t, m.src.s)
		})
		t.Run("signin "+name, func(t *testing.T) {
			d := newSignInFix(t)
			cfg := testConfig(t)
			posts := d.r.postCount()
			_, _, err := SignIn(context.Background(), cfg, liar{d.srv.login(t), c.lie}, d.params(t))
			if !c.want(err) {
				t.Fatalf("sign-in: %v", err)
			}
			if d.r.postCount() != posts {
				t.Error("a bootstrap was posted")
			}
			if ok, _ := Exists(cfg.DataDir); ok {
				t.Error("a vault was installed")
			}
		})
	}
}

// Finding 6: a password unlock's catch-up checks the server's head as Pull
// does.
func TestPasswordUnlockRejectsHeadRegression(t *testing.T) {
	f, r := serverVault(t)
	addHost(t, f.s, "web")
	pushAll(t, f.s, r)
	f.s.Lock()
	lying := &lyingRemote{fakeRemote: r}
	if err := f.s.UnlockWithPasswordRemote(context.Background(), lying, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrServerBehind) {
		t.Fatalf("password unlock against a server whose head went back: %v", err)
	}
}

// lyingRemote reports a head one entry behind the log it returns.
type lyingRemote struct{ *fakeRemote }

func (l *lyingRemote) Since(ctx context.Context, after uint64) ([]Committed, vaultlog.Head, error) {
	cs, head, err := l.fakeRemote.Since(ctx, after)
	if err == nil && head.Seq > 0 {
		head.Seq--
	}
	return cs, head, err
}

// capture records a merge sign-in's secrets: the record and account keys
// when they are made, and the destination once it is verified.
type capture struct {
	o      *signInSecrets
	rec    *deviceRecord
	acct   *crypto.AccountKeys
	dev    *vaultlog.LocalDevice
	d      *destination
	states []*vaultlog.Secrets // every state the destination verified
}

func (c *capture) watch(o *signInSecrets) {
	c.o, c.rec, c.acct, c.dev = o, o.rec, o.acct, o.dev
	o.onState = func(sec *vaultlog.Secrets) { c.states = append(c.states, sec) }
}

func (c *capture) install(s *Store, crash func(string) error) {
	s.testSignIn = c.watch
	s.testHook = func(stage string) error {
		if c.o != nil && c.o.d != nil {
			c.d = c.o.d
		}
		if crash != nil {
			return crash(stage)
		}
		return nil
	}
}

func allZero(b []byte) bool { return !slices.ContainsFunc(b, func(x byte) bool { return x != 0 }) }

// zeroed requires every secret c saw to be zeroed.
func (c *capture) zeroed(t *testing.T, path string) {
	t.Helper()
	if c.rec == nil || c.acct == nil {
		t.Fatalf("%s: the sign-in made no record", path)
	}
	if !allZero(c.rec.KEMSK) || !allZero(c.rec.SigSeed) || !allZero(c.rec.LocalKey) || c.rec.SecretKey != "" {
		t.Errorf("%s: the destination device record is not zeroed", path)
	}
	if !allZero(c.acct.Sig) || c.acct.KEM != nil {
		t.Errorf("%s: the account keys are not zeroed", path)
	}
	if c.dev == nil || !allZero(c.dev.Sig) {
		t.Errorf("%s: the decoded device signing key is not zeroed", path)
	}
	if c.d == nil {
		t.Fatalf("%s: the sign-in verified no destination", path)
	}
	if !allZero(c.d.sec.VK[:]) || len(c.d.sec.Items) != 0 {
		t.Errorf("%s: the destination's secrets are not zeroed", path)
	}
	c.supersededZeroed(t, path, len(c.states))
}

// supersededZeroed requires the first n states the destination verified
// to be zeroed: their VK and item keys, and their account keys unless a
// later state still holds them.
func (c *capture) supersededZeroed(t *testing.T, path string, n int) {
	t.Helper()
	if len(c.states) == 0 {
		t.Fatalf("%s: the destination verified no state", path)
	}
	for i, sec := range c.states[:n] {
		if !allZero(sec.VK[:]) || len(sec.Items) != 0 {
			t.Errorf("%s: the secrets of verified state %d of %d are not zeroed", path, i+1, len(c.states))
		}
		if sec.Account != nil && (!allZero(sec.Account.Sig) || sec.Account.KEM != nil) {
			t.Errorf("%s: the account keys of verified state %d of %d are not zeroed", path, i+1, len(c.states))
		}
	}
}

// Finding 7: the secrets of a merge sign-in that does not install them are
// zeroed on every path: a failed post, a lock while it waits on the
// server, and a failed promotion after the drop. Installed, they belong to
// the store and are not.
func TestMergeSignInZeroesSecretsOnFailure(t *testing.T) {
	type path struct {
		name  string
		setup func(m *mergeFix, s *Store) func(string) error
		want  func(error) bool
	}
	for _, p := range []path{
		{"post failure", func(m *mergeFix, s *Store) func(string) error {
			m.srv.onPost = func(*vaultlog.Wire) (bool, error) { return false, errDown }
			return nil
		}, func(err error) bool { return errors.Is(err, errDown) }},
		{"lock", func(m *mergeFix, s *Store) func(string) error {
			m.srv.onPost = func(*vaultlog.Wire) (bool, error) { s.Lock(); return true, nil }
			return nil
		}, func(err error) bool { return errors.Is(err, ErrSyncInterrupted) }},
		{"promotion failure", func(m *mergeFix, s *Store) func(string) error {
			return crashAt("signin:promote")
		}, func(err error) bool { return errors.Is(err, errCrash) }},
	} {
		t.Run(p.name, func(t *testing.T) {
			m := newMergeFix(t, testConfig(t))
			s := m.src.s
			if _, err := s.MergeStart(); err != nil {
				t.Fatal(err)
			}
			c := &capture{}
			c.install(s, p.setup(m, s))
			if _, err := m.signIn(t, s); !p.want(err) {
				t.Fatalf("sign-in: %v", err)
			}
			c.zeroed(t, p.name)
		})
	}
	t.Run("installed", func(t *testing.T) {
		m := newMergeFix(t, testConfig(t))
		s := m.src.s
		if _, err := s.MergeStart(); err != nil {
			t.Fatal(err)
		}
		c := &capture{}
		c.install(s, nil)
		if _, err := m.signIn(t, s); err != nil {
			t.Fatal(err)
		}
		if allZero(c.rec.KEMSK) || allZero(c.acct.Sig) || allZero(c.d.sec.VK[:]) {
			t.Error("the installed secrets were zeroed")
		}
		s.mu.Lock()
		owned := s.rec == c.rec && s.sec == c.d.sec
		s.mu.Unlock()
		if !owned {
			t.Error("the store does not hold the sign-in's secrets")
		}
	})
}

// Finding 8: a lock that races the sign-in's completion. The store takes
// the secrets over under s.mu, and the sign-in touches only what it still
// owns, so this is free of data races (run under -race) and the secrets
// end zeroed exactly once, by the lock.
func TestMergeSignInCompletionRacesLock(t *testing.T) {
	m := newMergeFix(t, testConfig(t))
	s := m.src.s
	if _, err := s.MergeStart(); err != nil {
		t.Fatal(err)
	}
	c := &capture{}
	var wg sync.WaitGroup
	c.install(s, func(stage string) error {
		if stage == "signin:drop" {
			// s.mu is held here: the lock runs the moment the install
			// releases it, while the sign-in returns.
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.Lock()
			}()
		}
		return nil
	})
	_, err := m.signIn(t, s)
	wg.Wait()
	if err != nil && !errors.Is(err, model.ErrLocked) {
		t.Fatalf("sign-in: %v", err)
	}
	if !s.Info().Locked {
		t.Error("the lock did not take")
	}
	if !allZero(c.rec.KEMSK) || !allZero(c.acct.Sig) {
		t.Error("the lock left the sign-in's secrets in memory")
	}
	s = open(t, m.src.cfg)
	if !s.ServerBacked() || s.Info().Locked {
		t.Fatalf("after a restart: %+v", s.Info())
	}
}

// Finding 4: the logout journal names the device records to delete, so a
// cleanup that meets an unreadable or malformed device.json still deletes
// them, and then stops with the journal kept instead of reporting success.
func TestLogoutCleanupWithBrokenDeviceConfig(t *testing.T) {
	for _, broken := range []string{"unreadable", "malformed"} {
		t.Run(broken, func(t *testing.T) {
			ctx := context.Background()
			f, srv := retireFixture(t)
			who := idsOf(t, f.cfg)
			f.s.testHook = crashAt("retire:cache")
			if _, err := f.s.Logout(ctx, retirer{srv}, LogoutOptions{}); !errors.Is(err, errCrash) {
				t.Fatalf("logout: %v", err)
			}
			f.s.testHook = nil
			j := readRetire(t, f.cfg)
			if j == nil || j.State != StateRetired || j.KeyStore != DeviceStoreKeychain ||
				!slices.Contains(j.Records, retireRecord{AccountID: who.acct, DeviceID: who.dev}) {
				t.Fatalf("the journal %+v does not name this device's record", j)
			}
			path := filepath.Join(f.cfg.DataDir, "device.json")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if broken == "unreadable" {
				err := os.Mkdir(path, 0o700)
				if err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte(`{"v":1,"store":`), 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := f.s.Logout(ctx, nil, LogoutOptions{})
			if err == nil || res.Done {
				t.Fatalf("the cleanup reported %+v, %v with device.json %s", res, err, broken)
			}
			if _, err := f.cfg.Keyring.Get(keychainService, slotOf(who.acct, who.dev)); err == nil {
				t.Error("the device record is still in the keychain")
			}
			if readRetire(t, f.cfg) == nil {
				t.Fatal("the journal is gone")
			}
			if _, err := tryOpen(t, f.cfg); err == nil {
				t.Error("Open reports no error with the cleanup stopped")
			}
			// Repaired, the cleanup finishes.
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
			if _, err := tryOpen(t, f.cfg); !errors.Is(err, ErrLoggedOut) {
				t.Fatalf("open: %v", err)
			}
			loggedOut(t, f.cfg, who)
		})
	}
}

// Finding 4: a --local-only logout with no readable device.json journals
// nothing.
func TestLogoutLocalOnlyNeedsDeviceConfig(t *testing.T) {
	f, _ := retireFixture(t)
	path := filepath.Join(f.cfg.DataDir, "device.json")
	if err := os.WriteFile(path, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Logout(context.Background(), nil, LogoutOptions{LocalOnly: true}); err == nil {
		t.Fatal("a logout journaled without knowing the device records")
	}
	if readRetire(t, f.cfg) != nil {
		t.Error("a journal was written")
	}
}

// signInFix is a destination account on a fake server, for SignIn.
type signInFix struct {
	dst  *fixture
	r    *fakeRemote
	srv  *fakeServer
	acct *crypto.AccountKeys
}

func newSignInFix(t *testing.T) *signInFix {
	t.Helper()
	dst := newVault(t, testConfig(t))
	addHost(t, dst.s, "dest-web")
	r := newFakeRemote(t, dst.cfg.DataDir)
	if err := dst.s.EnableServerMode(); err != nil {
		t.Fatal(err)
	}
	return &signInFix{dst: dst, r: r, srv: newFakeServer(t, r), acct: cloneAccount(t, dst.s)}
}

func (d *signInFix) params(t *testing.T) SignInParams {
	t.Helper()
	return SignInParams{ServerURL: d.srv.origin, Email: testEmail, Account: cloneAccountKeys(t, d.acct), SecretKey: d.dst.kit.SecretKey, DeviceName: "laptop"}
}

// signedIn requires s to be the destination's vault, unlocked and
// server-backed, with this device's records tracked, and to sync.
func (d *signInFix) signedIn(t *testing.T, cfg Config, s *Store) {
	t.Helper()
	if info := s.Info(); info.Locked || info.AccountID != d.dst.kit.AccountID {
		t.Fatalf("after the sign-in: %+v", info)
	}
	if !s.ServerBacked() {
		t.Fatal("the vault is not server-backed")
	}
	snap := snapshot(t, s)
	hostNamed(t, snap, "dest-web")
	dc := diskDeviceConfig(t, cfg)
	if dc.DeviceID.IsZero() || dc.Pending != nil || dc.AccountID != d.acct.AccountID {
		t.Errorf("device.json %+v", dc)
	}
	si, err := s.ServerInfo()
	if err != nil || si.Server != d.srv.origin || si.Email != "Me@example.com" {
		t.Errorf("server info %+v %v", si, err)
	}
	noUntrackedRecords(t, cfg, "after the sign-in")
	// It syncs both ways.
	addHost(t, s, "from-laptop")
	if res := pushAll(t, s, d.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	pull(t, d.dst.s, d.r)
	hostNamed(t, snapshot(t, d.dst.s), "from-laptop")
}

// SignIn into an empty data directory, in either device key store: the
// verified destination, one durable install, and a device that reopens.
func TestSignIn(t *testing.T) {
	for _, store := range []string{DeviceStoreKeychain, DeviceStoreFile} {
		t.Run(store, func(t *testing.T) {
			d := newSignInFix(t)
			cfg := testConfig(t)
			p := d.params(t)
			p.DeviceStore = store
			acct := p.Account
			s, res, err := SignIn(context.Background(), cfg, d.srv.login(t), p)
			if err != nil {
				t.Fatal(err)
			}
			track(t, cfg, s)
			if res.CheckpointDue {
				t.Error("a password sign-in reports a checkpoint due")
			}
			if diskDeviceConfig(t, cfg).Store != store {
				t.Errorf("device key store %q; want %q", diskDeviceConfig(t, cfg).Store, store)
			}
			s.mu.Lock()
			owned := s.sec.Account == acct
			s.mu.Unlock()
			if !owned {
				t.Error("the store does not hold the sign-in's account keys")
			}
			if n := activeCount(t, d.srv); n != 2 {
				t.Errorf("%d active devices; want 2", n)
			}
			d.signedIn(t, cfg, s)
			s = open(t, cfg)
			if s.Info().Locked {
				t.Fatalf("the vault does not reopen: %s", s.Info().LockReason)
			}
			hostNamed(t, snapshot(t, s), "from-laptop")
		})
	}
}

// SignIn refuses a data directory with a vault, and hop init refuses one
// with a sign-in in progress.
func TestSignInNeedsAnEmptyDataDir(t *testing.T) {
	d := newSignInFix(t)
	other := newVault(t, testConfig(t))
	release(other.cfg)
	p := d.params(t)
	acct := p.Account
	if _, _, err := SignIn(context.Background(), other.cfg, d.srv.login(t), p); !errors.Is(err, ErrVaultExists) {
		t.Errorf("sign-in over a vault: %v", err)
	}
	if !allZero(acct.Sig) {
		t.Error("a refused sign-in left the account keys in memory")
	}
	cfg := testConfig(t)
	if _, _, err := signIn(context.Background(), cfg, d.srv.login(t), d.params(t), crashAt("signin:fetch")); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	if _, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword)}); !errors.Is(err, ErrVaultExists) {
		t.Errorf("init over a sign-in in progress: %v", err)
	}
}

// §4.5: a recovery sign-in leaves its checkpoint due, durably, until this
// device's own checkpoint commits with credentials past the generation it
// found (review round 2, finding 3). Another device's checkpoint, a
// password change elsewhere, does not clear it, nor does pulling this
// device's checkpoint: only the commit slice E's journaled checkpoint
// makes (clearRecoveryDue).
func TestSignInRecoveryCheckpointDue(t *testing.T) {
	d := newSignInFix(t)
	cfg := testConfig(t)
	p := d.params(t)
	p.Method = SignInRecovery
	s, res, err := SignIn(context.Background(), cfg, d.srv.login(t), p)
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s)
	if !res.CheckpointDue {
		t.Fatal("a recovery sign-in does not report its checkpoint due")
	}
	s = open(t, cfg)
	if si, err := s.ServerInfo(); err != nil || !si.CheckpointDue {
		t.Fatalf("after a restart: %+v %v", si, err)
	}
	s.Lock()
	if si, err := s.ServerInfo(); err != nil || !si.CheckpointDue {
		t.Errorf("locked: %+v %v", si, err)
	}
	if err := s.Unlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Another device changes the password: the recovery is not done.
	checkpointOn(t, d.dst.s, d.r, nil)
	pull(t, s, d.r)
	if si, err := s.ServerInfo(); err != nil || !si.CheckpointDue {
		t.Errorf("after another device's checkpoint: %+v %v", si, err)
	}
	other, otherSt := headEntry(t, s)
	// This device's own checkpoint, pulled: still due until its commit
	// clears it.
	checkpointOn(t, s, d.r, nil)
	if si, err := s.ServerInfo(); err != nil || !si.CheckpointDue {
		t.Errorf("after pulling this device's checkpoint: %+v %v", si, err)
	}
	own, ownSt := headEntry(t, s)
	f, err := s.l.readServerFile()
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	self := s.dev.ID
	s.mu.Unlock()
	if recoveryCheckpointDone(f, other, otherSt, self) {
		t.Error("another device's checkpoint ends the recovery")
	}
	if !recoveryCheckpointDone(f, own, ownSt, self) {
		t.Error("this device's checkpoint does not end the recovery")
	}
	if recoveryCheckpointDone(f, own, ownSt, other.Entry.Author) {
		t.Error("a checkpoint ends the recovery of a device that did not author it")
	}
	// What slice E's journaled checkpoint does in its commit.
	s.mu.Lock()
	unlock, err := s.lockFile()
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	tx := &txn{}
	cleared, err := s.clearRecoveryDue(tx, own, ownSt)
	if err == nil && cleared {
		err = s.commitTxn(tx)
	}
	unlock()
	s.mu.Unlock()
	if err != nil || !cleared {
		t.Fatalf("clearing the recovery: %v %v", cleared, err)
	}
	if si, err := s.ServerInfo(); err != nil || si.CheckpointDue {
		t.Errorf("after this device's checkpoint committed: %+v %v", si, err)
	}
	s = open(t, cfg)
	if si, err := s.ServerInfo(); err != nil || si.CheckpointDue {
		t.Errorf("after a restart: %+v %v", si, err)
	}
}

// headEntry is s's verified head: its entry and state.
func headEntry(t *testing.T, s *Store) (*vaultlog.Wire, *vaultlog.State) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	w, err := s.l.readEntry(s.state.Head.Seq)
	if err != nil {
		t.Fatal(err)
	}
	return w, s.state
}

// SignIn stopped at each point leaves no untracked record, and the next
// SignIn, with a new login, finishes it with one device added; once the
// install committed, it opens the vault instead.
func TestSignInCrashAtEachPoint(t *testing.T) {
	type crash struct {
		name string
		hook func() func(string) error
	}
	var crashes []crash
	for _, st := range []string{"signin:record", "signin:intent", "signin:next", "signin:fetch", "signin:post", "signin:install"} {
		crashes = append(crashes, crash{st, func() func(string) error { return crashAt(st) }})
	}
	for _, st := range []string{"wal:install:sync", "wal:op:0", "wal:op:2", "wal:applied", "wal:removed"} {
		crashes = append(crashes, crash{"install " + st, func() func(string) error { return crashAfter("signin:install", st) }})
	}
	for _, store := range []string{DeviceStoreKeychain, DeviceStoreFile} {
		for _, c := range crashes {
			t.Run(store+" "+c.name, func(t *testing.T) {
				d := newSignInFix(t)
				cfg := testConfig(t)
				p := d.params(t)
				p.DeviceStore = store
				if _, _, err := signIn(context.Background(), cfg, d.srv.login(t), p, c.hook()); !errors.Is(err, errCrash) {
					t.Fatalf("sign-in: %v", err)
				}
				noUntrackedRecords(t, cfg, "after the crash")
				p = d.params(t)
				p.DeviceStore = store
				s, _, err := SignIn(context.Background(), cfg, d.srv.login(t), p)
				if err != nil {
					t.Fatal(err)
				}
				track(t, cfg, s)
				if n := activeCount(t, d.srv); n != 2 {
					t.Errorf("%d active devices; want 2", n)
				}
				if dc := diskDeviceConfig(t, cfg); len(dc.StaleDevices) != 0 {
					t.Errorf("stale devices %v; none was enrolled", dc.StaleDevices)
				}
				d.signedIn(t, cfg, s)
			})
		}
	}
}

// An interrupted retry: the first sign-in stops before its post, the second
// after its bootstrap committed with the response lost, and stops at the
// install; the third finishes, with the same device.
func TestSignInInterruptedRetry(t *testing.T) {
	d := newSignInFix(t)
	cfg := testConfig(t)
	if _, _, err := signIn(context.Background(), cfg, d.srv.login(t), d.params(t), crashAt("signin:post")); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	dev := diskDeviceConfig(t, cfg).Pending.DeviceID
	d.srv.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
	if _, _, err := signIn(context.Background(), cfg, d.srv.login(t), d.params(t), nil); !errors.Is(err, errLostResponse) {
		t.Fatalf("sign-in: %v", err)
	}
	d.srv.onPost = nil
	if _, _, err := signIn(context.Background(), cfg, d.srv.login(t), d.params(t), crashAt("signin:install")); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	noUntrackedRecords(t, cfg, "after the interrupted retry")
	s, _, err := SignIn(context.Background(), cfg, d.srv.login(t), d.params(t))
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s)
	if got := diskDeviceConfig(t, cfg).DeviceID; got != dev {
		t.Errorf("installed device %v; want %v, the first attempt's", got, dev)
	}
	if n := activeCount(t, d.srv); n != 2 {
		t.Errorf("%d active devices; want 2", n)
	}
	d.signedIn(t, cfg, s)
}

// A checkpoint that revokes the device SignIn enrolled is terminal for the
// data directory: its record becomes a tombstone, and a later SignIn
// refuses, even against a server that withholds the checkpoint.
func TestSignInRevokedIsTerminal(t *testing.T) {
	d := newSignInFix(t)
	cfg := testConfig(t)
	withheld := 0
	posted, done := false, false
	d.srv.onPost = func(*vaultlog.Wire) (bool, error) { posted = true; return true, nil }
	d.r.onSince = func(context.Context) {
		if posted && !done {
			done = true
			d.r.mu.Lock()
			withheld = len(d.r.entries)
			d.r.mu.Unlock()
			checkpointOn(t, d.dst.s, d.r, []model.ID{diskDeviceConfig(t, cfg).Pending.DeviceID})
		}
	}
	p := d.params(t)
	acct := p.Account
	_, _, err := SignIn(context.Background(), cfg, d.srv.login(t).lenient(), p)
	d.srv.onPost, d.r.onSince = nil, nil
	if !errors.Is(err, ErrDeviceRevoked) || !errors.Is(err, ErrSignInRevoked) {
		t.Fatalf("sign-in with the device revoked: %v", err)
	}
	if !allZero(acct.Sig) {
		t.Error("the account keys are still in memory")
	}
	dc := diskDeviceConfig(t, cfg)
	raw, err := cfg.Keyring.Get(keychainService, slotOf(dc.AccountID, dc.Pending.DeviceID))
	if _, tomb := parseTombstone([]byte(raw)); err != nil || !tomb {
		t.Fatal("the revoked device's record is not a tombstone")
	}
	hidden := newFakeServer(t, d.r.prefix(withheld))
	posts := hidden.postCount()
	if _, _, err := SignIn(context.Background(), cfg, hidden.login(t), d.params(t)); !errors.Is(err, ErrSignInRevoked) {
		t.Fatalf("sign-in against a server that withholds the revocation: %v", err)
	}
	if hidden.postCount() != posts {
		t.Error("a bootstrap was posted")
	}
	if _, err := tryOpen(t, cfg); !errors.Is(err, ErrNoVault) {
		t.Errorf("open: %v", err)
	}
}

// The fake server enforces what a real one does (plan R1, R2, R6): it
// validates every post publicly before changing anything, a checkpoint
// ends a login token, and a token's one bootstrap is consumed with its
// commit, an identical retry returning that commit.
func TestFakeServerEnforcesTokens(t *testing.T) {
	ctx := context.Background()
	d := newSignInFix(t)
	bootstrap := func(t *testing.T) *vaultlog.Wire {
		t.Helper()
		rec, info, err := newDeviceRecord(d.acct.AccountID, d.dst.kit.SecretKey)
		if err != nil {
			t.Fatal(err)
		}
		rec.zero()
		info.Name = "x"
		pull(t, d.dst.s, d.r)
		d.dst.s.mu.Lock()
		w, _, _, err := vaultlog.BuildBootstrap(d.dst.s.state, d.dst.s.sec, info, d.dst.s.now())
		d.dst.s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	t.Run("validation", func(t *testing.T) {
		w := bootstrap(t)
		w.Sigs[0].Sig[0] ^= 1
		head := d.r.head()
		tok := d.srv.login(t)
		if _, err := tok.Post(ctx, w); !errors.Is(err, errRejected) {
			t.Errorf("a post with a bad signature: %v", err)
		}
		if d.r.head() != head {
			t.Error("a rejected post changed the log")
		}
		w.Sigs[0].Sig[0] ^= 1
		if _, err := tok.Post(ctx, w); err != nil {
			t.Errorf("the valid post after a rejected one: %v", err)
		}
	})
	t.Run("one bootstrap", func(t *testing.T) {
		tok := d.srv.login(t)
		w := bootstrap(t)
		stale := bootstrap(t)
		if _, err := tok.Post(ctx, w); err != nil {
			t.Fatal(err)
		}
		head, err := tok.Post(ctx, w)
		if wh, _ := w.Entry.Hash(); err != nil || !head.H.Equal(wh) {
			t.Errorf("an identical retry: %v %v", head, err)
		}
		if _, err := tok.Post(ctx, bootstrap(t)); !errors.Is(err, errTokenInvalid) {
			t.Errorf("a second bootstrap: %v", err)
		}
		other := d.srv.login(t)
		if _, err := other.Post(ctx, stale); !errors.Is(err, ErrHeadConflict) {
			t.Fatalf("a bootstrap on a moved head: %v", err)
		}
		if _, err := other.Post(ctx, bootstrap(t)); err != nil {
			t.Errorf("the token after a head conflict: %v", err)
		}
	})
	t.Run("checkpoint ends it", func(t *testing.T) {
		tok := d.srv.login(t)
		checkpointOn(t, d.dst.s, d.r, nil)
		if _, err := tok.EntryAt(ctx, 0); !errors.Is(err, errTokenInvalid) {
			t.Errorf("a read after a checkpoint: %v", err)
		}
		if _, _, err := tok.Since(ctx, 0); !errors.Is(err, errTokenInvalid) {
			t.Errorf("a read after a checkpoint: %v", err)
		}
		if _, err := tok.Post(ctx, bootstrap(t)); !errors.Is(err, errTokenInvalid) {
			t.Errorf("a post after a checkpoint: %v", err)
		}
	})
}

// vault/server.json keeps the server and the sign-in email for every way a
// vault becomes server-backed: a publication, a merge's sign-in and
// SignIn (TestSignIn), and reads back after a restart.
func TestServerInfoIsRecorded(t *testing.T) {
	ctx := context.Background()
	t.Run("publication", func(t *testing.T) {
		f, srv := publishFixture(t)
		if _, err := f.s.Publish(ctx, publisher{srv}, pubOpts); err != nil {
			t.Fatal(err)
		}
		s := open(t, f.cfg)
		if si, err := s.ServerInfo(); err != nil || si != (ServerInfo{Server: pubOpts.Server, Email: testEmail}) {
			t.Errorf("server info %+v %v", si, err)
		}
	})
	t.Run("merge", func(t *testing.T) {
		m := newMergeFix(t, testConfig(t))
		if _, err := m.src.s.MergeStart(); err != nil {
			t.Fatal(err)
		}
		if _, err := m.signIn(t, m.src.s); err != nil {
			t.Fatal(err)
		}
		s := open(t, m.src.cfg)
		if si, err := s.ServerInfo(); err != nil || si != (ServerInfo{Server: m.srv.origin, Email: testEmail}) {
			t.Errorf("server info %+v %v", si, err)
		}
	})
	t.Run("local-only", func(t *testing.T) {
		f := newVault(t, testConfig(t))
		if _, err := f.s.ServerInfo(); !errors.Is(err, ErrNotServerBacked) {
			t.Errorf("a local-only vault: %v", err)
		}
	})
}
