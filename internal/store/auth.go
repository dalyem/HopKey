package store

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// Server authentication objects the store signs for the transport (§9, §4.3
// addendum, plan R3 and R5). The transport (slice E) fetches the challenge
// and sends the signature; the keys never leave the store. The objects are
// the ones slice C verifies:
//
//	device-auth = {"v":1, "origin":str≤256, "account_id":id, "device_id":id, "operation":str≤32, "challenge":b64}
//	signup-pop  = {"v":1, "origin":str≤256, "email":str≤254, "account_id":id, "vault_id":id,
//	               "upload_seq":u64s, "upload_h":h, "challenge":b64}
//
// TODO(slice E2 follow-up): these duplicate the server's types; switch to
// the shared ones once they exist on the phase branch.
const (
	labelDeviceAuth = "hopkey/v1/device-auth"
	labelSignupPoP  = "hopkey/v1/signup-pop"

	// OperationSession and OperationRetireStatus are the device-auth
	// operations (§9).
	OperationSession      = "session"
	OperationRetireStatus = "retire-status"

	challengeSize = 32
)

// ErrAuthClosed means a DeviceAuth or a signup proof was used after the
// operation that issued it ended, or after the vault was locked.
var ErrAuthClosed = errors.New("store: the device key is no longer available for signing")

type deviceAuthObject struct {
	V         int      `json:"v"`
	Origin    string   `json:"origin"`
	AccountID model.ID `json:"account_id"`
	DeviceID  model.ID `json:"device_id"`
	Operation string   `json:"operation"`
	Challenge []byte   `json:"challenge"`
}

type signupPoPObject struct {
	V         int         `json:"v"`
	Origin    string      `json:"origin"`
	Email     string      `json:"email"`
	AccountID model.ID    `json:"account_id"`
	VaultID   model.ID    `json:"vault_id"`
	UploadSeq uint64      `json:"upload_seq,string"`
	UploadH   crypto.Hash `json:"upload_h"`
	Challenge []byte      `json:"challenge"`
}

func checkChallenge(origin string, challenge []byte) error {
	if origin == "" {
		return errors.New("store: empty origin")
	}
	if err := crypto.CheckStr("origin", origin, 256); err != nil {
		return err
	}
	if len(challenge) != challengeSize {
		return fmt.Errorf("store: a challenge is %d bytes, not %d", challengeSize, len(challenge))
	}
	return nil
}

// DeviceAuth signs §9 device-authentication objects as one device, for the
// transport's session and retire-status calls. It signs only the two
// operations the server accepts. It is valid while the operation that
// issued it runs (a logout), or while the store stays unlocked in the
// generation it was issued in (Store.DeviceAuth).
type DeviceAuth struct {
	AccountID model.ID
	DeviceID  model.ID
	sign      func(obj *deviceAuthObject) ([]byte, error)
}

// Sign returns Sig(dev_sig, "hopkey/v1/device-auth", {"v":1, origin,
// account_id, device_id, operation, challenge}).
func (a DeviceAuth) Sign(origin, operation string, challenge []byte) ([]byte, error) {
	if a.sign == nil {
		return nil, ErrAuthClosed
	}
	if operation != OperationSession && operation != OperationRetireStatus {
		return nil, fmt.Errorf("store: device-auth operation %q", operation)
	}
	if err := checkChallenge(origin, challenge); err != nil {
		return nil, err
	}
	return a.sign(&deviceAuthObject{
		V: 1, Origin: origin, AccountID: a.AccountID, DeviceID: a.DeviceID,
		Operation: operation, Challenge: append([]byte(nil), challenge...),
	})
}

// DeviceAuth returns a signer for this device's §9 device authentication,
// for slice E's sessions. It works while the store stays unlocked in the
// generation it was issued in: a lock, a self-lock or a revocation ends it,
// as it fences the agent (Generation).
func (s *Store) DeviceAuth() (DeviceAuth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return DeviceAuth{}, s.lockedErr()
	}
	gen := s.gen.Load()
	a := DeviceAuth{AccountID: s.state.Account.AccountID, DeviceID: s.dev.ID}
	a.sign = func(obj *deviceAuthObject) ([]byte, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.gen.Load() != gen || s.state == nil || s.isRevoked.Load() {
			return nil, ErrAuthClosed
		}
		return crypto.Sign(s.dev.Sig, labelDeviceAuth, obj)
	}
	return a, nil
}

// sessionAuth is a DeviceAuth over a device key an operation holds, valid
// until close.
type sessionAuth struct {
	mu  sync.Mutex
	key ed25519.PrivateKey
}

func (k *sessionAuth) auth(accountID, deviceID model.ID) DeviceAuth {
	return DeviceAuth{AccountID: accountID, DeviceID: deviceID, sign: func(obj *deviceAuthObject) ([]byte, error) {
		k.mu.Lock()
		defer k.mu.Unlock()
		if k.key == nil {
			return nil, ErrAuthClosed
		}
		return crypto.Sign(k.key, labelDeviceAuth, obj)
	}}
}

func (k *sessionAuth) close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.key = nil
}
