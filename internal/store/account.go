package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// accountFile is account.json: what a server holds for the account (§4.2).
// In phase 1 it lives here; in phase 2 the server keeps it. It is derived
// from the verified state's creds and the blobs they name, and a password
// unlock starts from it as it would from a server's prelogin answer.
type accountFile struct {
	V           int                 `json:"v"`
	AccountID   model.ID            `json:"account_id"`
	AKV         uint32              `json:"akv"`
	Gen         uint32              `json:"gen"`
	KDFVersion  uint32              `json:"kdf_version"`
	Salt        []byte              `json:"salt"`
	AuthSHA256  crypto.Hash         `json:"auth_sha256"`
	RAuthSHA256 crypto.Hash         `json:"rauth_sha256"`
	PwBlob      crypto.AEADEnvelope `json:"pw_blob"`
	RkBlob      crypto.AEADEnvelope `json:"rk_blob"`
}

// accountOf builds account.json from a state and its objects.
func accountOf(st *vaultlog.State, objs vaultlog.ObjectFetcher) (*accountFile, error) {
	c := st.Creds
	pw, err := fetchAEAD(objs, c.PwBlobSHA256)
	if err != nil {
		return nil, err
	}
	rk, err := fetchAEAD(objs, c.RkBlobSHA256)
	if err != nil {
		return nil, err
	}
	return &accountFile{
		V: 1, AccountID: st.Account.AccountID, AKV: st.Account.AKV, Gen: c.Gen, KDFVersion: c.KDFVersion,
		Salt: c.Salt, AuthSHA256: c.AuthSHA256, RAuthSHA256: c.RAuthSHA256, PwBlob: pw, RkBlob: rk,
	}, nil
}

func fetchAEAD(objs vaultlog.ObjectFetcher, h crypto.Hash) (crypto.AEADEnvelope, error) {
	b, err := objs.FetchObject(h)
	if err != nil {
		return crypto.AEADEnvelope{}, fmt.Errorf("%w: object %v: %w", ErrCorrupt, h, err)
	}
	env, err := crypto.ParseAEADEnvelope(b)
	if err != nil {
		return crypto.AEADEnvelope{}, fmt.Errorf("%w: object %v: %v", ErrCorrupt, h, err)
	}
	return env, nil
}

// writeAccountFile brings account.json up to date with the verified state.
// The caller holds the file lock.
func (s *Store) writeAccountFile() error {
	a, err := accountOf(s.state, objectDir(s.l.objects()))
	if err != nil {
		return err
	}
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(s.l.accountFile()); err == nil && string(old) == string(b) {
		return nil
	}
	return writeFileAtomic(s.l.accountFile(), b)
}

// readAccountFile reads account.json, with state.json parsed and raw. If
// account.json is behind state.json (a crash between the two writes), it is
// rebuilt from state.json. Neither is trusted here: the account keys a
// password opens are checked against the log by the replay that follows.
func (s *Store) readAccountFile() (*accountFile, *vaultlog.State, []byte, error) {
	stored, raw, err := s.readStoredState()
	if err != nil {
		return nil, nil, nil, err
	}
	if stored == nil {
		return nil, nil, nil, fmt.Errorf("%w: a password unlock needs state.json", ErrCorrupt)
	}
	var a accountFile
	b, err := os.ReadFile(s.l.accountFile())
	if err == nil {
		err = json.Unmarshal(b, &a)
	}
	if err != nil || a.V != 1 || a.Gen != stored.Creds.Gen || a.AccountID != stored.Account.AccountID {
		fresh, ferr := accountOf(stored, objectDir(s.l.objects()))
		if ferr != nil {
			return nil, nil, nil, ferr
		}
		a = *fresh
	}
	return &a, stored, raw, nil
}

// Kit is the Emergency Kit (§4.3, §12): the Secret Key and the Recovery Key
// in their text forms, with the account ID and the date.
type Kit struct {
	AccountID   string    `json:"account_id"`
	SecretKey   string    `json:"secret_key"`
	RecoveryKey string    `json:"recovery_key"`
	Created     time.Time `json:"created"`
}

// Text renders the kit for printing or saving.
func (k Kit) Text() string {
	var b strings.Builder
	b.WriteString("HopKey Emergency Kit\n")
	b.WriteString("====================\n\n")
	fmt.Fprintf(&b, "Account ID:    %s\n", k.AccountID)
	fmt.Fprintf(&b, "Created:       %s\n\n", k.Created.UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "Secret Key:    %s\n", k.SecretKey)
	fmt.Fprintf(&b, "Recovery Key:  %s\n\n", k.RecoveryKey)
	b.WriteString("Keep this offline: print it or write it down, and store it away from\n")
	b.WriteString("this computer. A new device needs your master password and the Secret\n")
	b.WriteString("Key. The Recovery Key replaces the password if you forget it. Nobody,\n")
	b.WriteString("HopKey included, can recover either one for you.\n")
	return b.String()
}

// LastGroup is the final hyphen-separated group of a kit key, check symbol
// included: what the user types back (§4.3, §12).
func LastGroup(key string) string {
	if i := strings.LastIndexByte(key, '-'); i >= 0 {
		return key[i+1:]
	}
	return key
}

// SameGroup compares a typed group with the expected one under the §12
// reading rules: case-insensitive, hyphens and spaces ignored, I and L read
// as 1 and O as 0.
func SameGroup(typed, want string) bool { return normGroup(typed) == normGroup(want) }

func normGroup(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch r {
		case '-', ' ', '\t':
			continue
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// errBadPasswordShape wraps a password the KDF refuses (too short, not
// UTF-8, unassigned code points).
var errBadPasswordShape = errors.New("store: unusable password")

// newCreds generates a salt and derives everything creds needs (§4.1, §4.2)
// for acct under password, sk and rk.
func newCreds(password []byte, sk *crypto.SecretKey, rk *crypto.RecoveryKey, acct *crypto.AccountKeys) (vaultlog.CredsInput, error) {
	salt := make([]byte, crypto.SaltSize)
	if _, err := randRead(salt); err != nil {
		return vaultlog.CredsInput{}, err
	}
	lk, err := crypto.DeriveLoginKeys(password, salt, sk, acct.AccountID, crypto.KDFv1)
	if err != nil {
		return vaultlog.CredsInput{}, fmt.Errorf("%w: %v", errBadPasswordShape, err)
	}
	defer lk.Zero()
	pw, err := crypto.SealPwBlob(&lk.EncKey, acct)
	if err != nil {
		return vaultlog.CredsInput{}, err
	}
	rkKey, rAuth, err := crypto.RecoveryKeys(rk[:], acct.AccountID)
	if err != nil {
		return vaultlog.CredsInput{}, err
	}
	defer rkKey.Zero()
	defer clear(rAuth)
	rkBlob, err := crypto.SealRkBlob(&rkKey, acct)
	if err != nil {
		return vaultlog.CredsInput{}, err
	}
	return vaultlog.CredsInput{
		KDFVersion: crypto.KDFv1.Version, Salt: salt,
		AuthSHA256: lk.AuthHash(), RAuthSHA256: crypto.SHA256(rAuth),
		PwBlob: pw, RkBlob: rkBlob,
	}, nil
}

// openWithPassword derives the login keys for account a (§4.1), checks
// them against the verifier hash (the check a server makes, §4.4) and opens
// pw_blob.
func openWithPassword(a *accountFile, password []byte, sk *crypto.SecretKey) (*crypto.AccountKeys, error) {
	if a.KDFVersion != crypto.KDFv1.Version {
		return nil, fmt.Errorf("store: unsupported kdf_version %d", a.KDFVersion)
	}
	lk, err := crypto.DeriveLoginKeys(password, a.Salt, sk, a.AccountID, crypto.KDFv1)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWrongPassword, err)
	}
	defer lk.Zero()
	if !crypto.CheckSecretHash(a.AuthSHA256, lk.AuthKey[:]) {
		return nil, ErrWrongPassword
	}
	acct, err := crypto.OpenPwBlob(&lk.EncKey, a.PwBlob, a.AccountID, a.AKV)
	if err != nil {
		return nil, fmt.Errorf("%w: pw_blob does not open", ErrWrongPassword)
	}
	return acct, nil
}
