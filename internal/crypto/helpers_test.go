package crypto

import (
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model"
)

// fixedID returns an ID whose bytes are b, b+1, ..., b+15.
func fixedID(b byte) model.ID {
	var id model.ID
	for i := range id {
		id[i] = b + byte(i)
	}
	return id
}

// fixedBytes returns n bytes derived from a label, for deterministic test
// inputs.
func fixedBytes(label string, n int) []byte {
	var out []byte
	for i := 0; len(out) < n; i++ {
		s := sha256.Sum256([]byte{byte(i)})
		s = sha256.Sum256(append([]byte(label), s[:]...))
		out = append(out, s[:]...)
	}
	return out[:n]
}

func fixedKEM(t testing.TB, label string) hpke.PrivateKey {
	t.Helper()
	k, err := DeriveKEMKey(fixedBytes(label, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fixedSig(label string) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(fixedBytes(label, 32))
}

func fixedAccount(t testing.TB, akv uint32) *AccountKeys {
	t.Helper()
	k, err := NewAccountKeys(fixedID(0x10), akv, fixedKEM(t, "account-kem"), fixedBytes("account-sig", 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ts(t testing.TB, s string) model.Timestamp {
	t.Helper()
	var x model.Timestamp
	if err := x.UnmarshalText([]byte(s)); err != nil {
		t.Fatal(err)
	}
	return x
}

// memPersister keeps the last persisted state and can be told to fail.
type memPersister struct {
	state []byte
	saves int
	fail  bool
}

var errPersist = errors.New("persist failed")

func (m *memPersister) Persist(b []byte) error {
	if m.fail {
		return errPersist
	}
	m.state = slices.Clone(b)
	m.saves++
	return nil
}

// fakeClock is an adjustable Clock.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }
