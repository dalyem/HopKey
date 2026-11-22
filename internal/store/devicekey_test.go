package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// noServiceRing is a keychain with no Secret Service behind it.
type noServiceRing struct{ calls int }

var errNoService = errors.New("The name org.freedesktop.secrets was not provided by any .service files")

func (r *noServiceRing) Get(string, string) (string, error) { r.calls++; return "", errNoService }
func (r *noServiceRing) Set(string, string, string) error   { r.calls++; return errNoService }
func (r *noServiceRing) Delete(string, string) error        { r.calls++; return errNoService }

// KeychainProblem is the probe hop init runs, on its own: a working
// keychain gets one entry written and removed again, and nothing else
// anywhere; a broken one is reported with its reason, and the data
// directory is not even made.
func TestKeychainProblemChangesNothing(t *testing.T) {
	cfg := testConfig(t)
	ring := newMemRing()
	cfg.Keyring = ring
	if err := KeychainProblem(cfg); err != nil {
		t.Fatalf("a working keychain: %v", err)
	}
	if len(ring.m) != 0 {
		t.Errorf("the probe left %v in the keychain", ring.m)
	}
	if _, err := os.Lstat(cfg.DataDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the probe made the data directory: %v", err)
	}

	cfg.Keyring = &noServiceRing{}
	err := KeychainProblem(cfg)
	if !errors.Is(err, errNoService) {
		t.Fatalf("a broken keychain: %v", err)
	}
	if _, err := os.Lstat(cfg.DataDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the probe made the data directory: %v", err)
	}
}

// The keychain error says what to do next, names both ways forward, and
// does not lead with the package's prefix.
func TestKeychainUnusableNamesBothWaysForward(t *testing.T) {
	cfg := testConfig(t)
	cfg.Keyring = &noServiceRing{}
	_, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword)})
	if !errors.Is(err, ErrKeychainUnusable) {
		t.Fatalf("PrepareInit: %v", err)
	}
	for _, want := range []string{"--device-key-store=file", PassphraseEnv, "org.freedesktop.secrets", DeviceKeyFile(cfg.DataDir)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q does not say %q", err, want)
		}
	}
	if strings.HasPrefix(err.Error(), "store:") {
		t.Errorf("%q leads with an internal prefix", err)
	}
	if !errors.Is(KeychainUnusable(cfg, errNoService), ErrKeychainUnusable) {
		t.Error("KeychainUnusable does not match ErrKeychainUnusable")
	}
}

// A sign-in or an enrollment that has begun here recorded where its device
// key goes, and the plan reads it back: nothing is left to ask.
func TestPlannedDeviceKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if plan, err := PlannedDeviceKey(dir); err != nil || plan != (DeviceKeyPlan{}) {
		t.Fatalf("an empty data directory: %+v, %v", plan, err)
	}
	cfg := testConfig(t)
	for _, tc := range []struct {
		name   string
		pass   string
		store  string
		sealed bool
	}{
		{"keychain", "", DeviceStoreKeychain, false},
		{"unsealed file", "", DeviceStoreFile, false},
		{"sealed file", "a device passphrase", DeviceStoreFile, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfg
			cfg.DataDir = filepath.Join(t.TempDir(), "data")
			cfg.Getenv = func(k string) string {
				if k == PassphraseEnv {
					return tc.pass
				}
				return ""
			}
			p, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword), DeviceStore: tc.store})
			if err != nil {
				t.Fatal(err)
			}
			if plan, err := PlannedDeviceKey(cfg.DataDir); err != nil || plan != (DeviceKeyPlan{}) {
				t.Errorf("before the commit: %+v, %v", plan, err)
			}
			s, err := p.Commit()
			if err != nil {
				t.Fatal(err)
			}
			s.Close()
			plan, err := PlannedDeviceKey(cfg.DataDir)
			if err != nil || plan.Store != tc.store || plan.Sealed != tc.sealed {
				t.Errorf("plan %+v, %v; want %s sealed=%v", plan, err, tc.store, tc.sealed)
			}
		})
	}
}

// An enrollment by approval records its choice in enroll.json before any key
// exists; a restarted login follows that record.
func TestPlannedDeviceKeyOfAnEnrollment(t *testing.T) {
	cfg := testConfig(t)
	cfg.Getenv = func(k string) string {
		if k == PassphraseEnv {
			return "a device passphrase"
		}
		return ""
	}
	e, _, err := BeginEnrollment(cfg, EnrollParams{ServerURL: "https://hop.example", DeviceStore: DeviceStoreFile})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	plan, err := PlannedDeviceKey(cfg.DataDir)
	if err != nil || plan != (DeviceKeyPlan{Store: DeviceStoreFile, Sealed: true}) {
		t.Errorf("plan %+v, %v", plan, err)
	}
}
