package crypto

import (
	"crypto/ed25519"
	"fmt"
	"net/url"
	"strings"

	"github.com/dalyem/hopkey/internal/model"
)

// Labels of the objects a client signs to authenticate to the server: the
// §9 device authentication and the §4.3 signup proof of possession (rev 16
// addendum).
const (
	LabelDeviceAuth = "hopkey/v1/device-auth"
	LabelSignupPoP  = "hopkey/v1/signup-pop"
)

// ChallengeSize is the size of a server challenge: 256 random bits (phase 2
// plan R3, R5).
const ChallengeSize = 32

// Device-auth operations (§9, plan R5).
const (
	OperationSession      = "session"
	OperationRetireStatus = "retire-status"
)

// DeviceAuth is the object a device signs to get a session or to query its
// retirement status (§9):
//
//	{"v":1, "origin":str≤256, "account_id":id, "device_id":id,
//	 "operation":str≤32, "challenge":b64}
//
// The server rebuilds it from the values it bound to the challenge; it never
// takes them from the request.
type DeviceAuth struct {
	V         int      `json:"v"`
	Origin    string   `json:"origin"`
	AccountID model.ID `json:"account_id"`
	DeviceID  model.ID `json:"device_id"`
	Operation string   `json:"operation"`
	Challenge []byte   `json:"challenge"`
}

// Validate checks the closed schema.
func (a *DeviceAuth) Validate() error {
	if a.V != Version {
		return schemaErr("device-auth.v", "is %d", a.V)
	}
	if err := checkOrigin("device-auth.origin", a.Origin); err != nil {
		return err
	}
	if err := CheckID("device-auth.account_id", a.AccountID); err != nil {
		return err
	}
	if err := CheckID("device-auth.device_id", a.DeviceID); err != nil {
		return err
	}
	if a.Operation == "" {
		return schemaErr("device-auth.operation", "is empty")
	}
	if err := CheckStr("device-auth.operation", a.Operation, 32); err != nil {
		return err
	}
	return checkChallenge("device-auth.challenge", a.Challenge)
}

// SignDeviceAuth returns Sig(dev_sig, "hopkey/v1/device-auth", a).
func SignDeviceAuth(devSig ed25519.PrivateKey, a *DeviceAuth) ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return Sign(devSig, LabelDeviceAuth, a)
}

// VerifyDeviceAuth checks sig as Sig(dev_sig_pk, "hopkey/v1/device-auth", a).
func VerifyDeviceAuth(devSigPK ed25519.PublicKey, a *DeviceAuth, sig []byte) error {
	if err := a.Validate(); err != nil {
		return err
	}
	return Verify(devSigPK, LabelDeviceAuth, a, sig)
}

// SignupPoP is the proof of possession that signup carries (§4.3 rev 16
// addendum), signed with the account signing key in effect at the upload
// head:
//
//	{"v":1, "origin":str≤256, "email":str≤254, "account_id":id,
//	 "vault_id":id, "upload_seq":u64s, "upload_h":h, "challenge":b64}
//
// email is the normalized address. The server takes the account and vault
// IDs and the upload head from the publication it validated, not from the
// request.
type SignupPoP struct {
	V         int      `json:"v"`
	Origin    string   `json:"origin"`
	Email     string   `json:"email"`
	AccountID model.ID `json:"account_id"`
	VaultID   model.ID `json:"vault_id"`
	UploadSeq uint64   `json:"upload_seq,string"`
	UploadH   Hash     `json:"upload_h"`
	Challenge []byte   `json:"challenge"`
}

// Validate checks the closed schema.
func (p *SignupPoP) Validate() error {
	if p.V != Version {
		return schemaErr("signup-pop.v", "is %d", p.V)
	}
	if err := checkOrigin("signup-pop.origin", p.Origin); err != nil {
		return err
	}
	if p.Email == "" {
		return schemaErr("signup-pop.email", "is empty")
	}
	if err := CheckStr("signup-pop.email", p.Email, 254); err != nil {
		return err
	}
	if err := CheckID("signup-pop.account_id", p.AccountID); err != nil {
		return err
	}
	if err := CheckID("signup-pop.vault_id", p.VaultID); err != nil {
		return err
	}
	return checkChallenge("signup-pop.challenge", p.Challenge)
}

// SignSignupPoP returns Sig(acct_sig, "hopkey/v1/signup-pop", p). acct must
// be the account key at the upload head's akv.
func SignSignupPoP(acct *AccountKeys, p *SignupPoP) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if acct == nil || acct.AccountID != p.AccountID {
		return nil, schemaErr("signup-pop.account_id", "does not match the signing account")
	}
	return Sign(acct.Sig, LabelSignupPoP, p)
}

// VerifySignupPoP checks sig as Sig(acct_sig_pk, "hopkey/v1/signup-pop", p).
func VerifySignupPoP(acctSigPK ed25519.PublicKey, p *SignupPoP, sig []byte) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return Verify(acctSigPK, LabelSignupPoP, p, sig)
}

func checkOrigin(field, origin string) error {
	if origin == "" {
		return schemaErr(field, "is empty")
	}
	return CheckStr(field, origin, 256)
}

func checkChallenge(field string, c []byte) error {
	if len(c) != ChallengeSize {
		return schemaErr(field, "is %d bytes, want %d", len(c), ChallengeSize)
	}
	return nil
}

// CanonicalOrigin returns the origin that device-auth and signup-pop
// objects carry for a server URL: lowercase scheme (https or http) and
// host, no default port, and no path, query, fragment or user info. The
// server binds challenges to this form of its configured origin, so a
// client signs CanonicalOrigin of the server URL it was given.
func CanonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSuffix(raw, "/"))
	if err != nil {
		return "", fmt.Errorf("crypto: origin: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "https" && scheme != "http") || u.Host == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery {
		return "", fmt.Errorf("crypto: origin %q is not scheme://host[:port]", raw)
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	origin := scheme + "://" + host
	if err := checkOrigin("origin", origin); err != nil {
		return "", err
	}
	return origin, nil
}
