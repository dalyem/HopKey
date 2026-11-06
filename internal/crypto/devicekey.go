package crypto

import (
	"fmt"

	"golang.org/x/crypto/argon2"

	"github.com/dalyem/hopkey/internal/model"
)

// Labels of the passphrase-sealed device key file (§11, rev 14).
const (
	LabelDevicePassphrase = "hopkey/v1/device-passphrase"
	LabelDeviceKeyFile    = "hopkey/v1/device-key-file"
)

// DevicePassphraseKey derives the key that seals the device key file (§11):
//
//	pk = HKDF(ikm=Argon2id(NFKC(passphrase), salt16, kdf_version 1 parameters),
//	          salt=device_id_bytes, info=lp("hopkey/v1/device-passphrase"))
//
// The passphrase follows the master password rules of §4.1
// (NormalizePassword), and every input is checked before Argon2 runs.
func DevicePassphraseKey(passphrase, salt []byte, deviceID model.ID) (*SymKey, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("crypto: salt must be %d bytes", SaltSize)
	}
	if deviceID.IsZero() {
		return nil, fmt.Errorf("crypto: zero device ID")
	}
	pw, err := NormalizePassword(passphrase)
	if err != nil {
		return nil, err
	}
	p := KDFv1
	ikm := argon2.IDKey(pw, salt, p.Time, p.MemoryKiB, p.Threads, p.KeyLen)
	clear(pw)
	defer clear(ikm)
	out, err := hkdf32(ikm, deviceID[:], lps(LabelDevicePassphrase))
	if err != nil {
		return nil, err
	}
	var k SymKey
	copy(k[:], out)
	clear(out)
	return &k, nil
}

// DeviceKeyFileAAD is the AAD of the sealed device key file (§11):
// lp("hopkey/v1/device-key-file") || lp(device_id_bytes).
func DeviceKeyFileAAD(deviceID model.ID) []byte {
	return cat(lps(LabelDeviceKeyFile), LP(deviceID[:]))
}
