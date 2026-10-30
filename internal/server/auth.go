package server

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/email"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Labels of the prelogin derivations for unknown emails (R4). They are
// server-internal; nothing outside the server computes them.
const (
	labelSyntheticAccountID = "hopkey/v1/server-prelogin-account-id"
	labelSyntheticSalt      = "hopkey/v1/server-prelogin-salt"
)

// synthetic returns HMAC-SHA256(secret, lp(label) || lp(email)) cut to 16
// bytes, the size of a real account ID or salt.
func (s *Server) synthetic(label, email string) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write(crypto.LP([]byte(label)))
	m.Write(crypto.LP([]byte(email)))
	return m.Sum(nil)[:16]
}

type preloginRequest struct {
	Email string `json:"email"`
}

type preloginResponse struct {
	AccountID  model.ID `json:"account_id"`
	KDFVersion uint32   `json:"kdf_version"`
	Salt       []byte   `json:"salt"`
}

// prelogin: POST /v1/prelogin {email} → {account_id, kdf_version, salt}.
// For an unknown email it returns a deterministic synthetic account ID and
// salt, so the response does not reveal whether the account exists (R4).
func (s *Server) prelogin(w http.ResponseWriter, r *http.Request, c *call) error {
	var req preloginRequest
	if err := s.decode(c.body, &req); err != nil {
		return err
	}
	email, err := email.Normalize(req.Email)
	if err != nil {
		return errBadRequest("invalid email")
	}
	if !s.limiter.allow(c.route.pattern+"|email", email, s.rates.PreloginEmail) {
		return errRateLimited
	}
	resp := preloginResponse{KDFVersion: 1, Salt: s.synthetic(labelSyntheticSalt, email)}
	copy(resp.AccountID[:], s.synthetic(labelSyntheticAccountID, email))
	err = s.store.View(r.Context(), func(tx Tx) error {
		a, err := tx.AccountByEmail(email)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		resp = preloginResponse{AccountID: a.ID, KDFVersion: a.KDFVersion, Salt: a.Salt}
		return nil
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

type loginRequest struct {
	AccountID model.ID `json:"account_id"`
	AuthKey   []byte   `json:"auth_key"`
}

type recoverRequest struct {
	AccountID model.ID `json:"account_id"`
	RAuth     []byte   `json:"r_auth"`
}

type loginResponse struct {
	LoginToken string   `json:"login_token"`
	VaultID    model.ID `json:"vault_id"`
}

// login: POST /v1/login {account_id, auth_key} → {login_token, vault_id}.
func (s *Server) login(w http.ResponseWriter, r *http.Request, c *call) error {
	var req loginRequest
	if err := s.decode(c.body, &req); err != nil {
		return err
	}
	return s.issueLoginToken(w, r, c, TokenLogin, req.AccountID, req.AuthKey)
}

// recover: POST /v1/recover {account_id, r_auth} → {login_token, vault_id}.
func (s *Server) recover(w http.ResponseWriter, r *http.Request, c *call) error {
	var req recoverRequest
	if err := s.decode(c.body, &req); err != nil {
		return err
	}
	return s.issueLoginToken(w, r, c, TokenRecovery, req.AccountID, req.RAuth)
}

// issueLoginToken checks a derived secret against the latest creds and
// issues a login or recovery token bound to the account, its vault and the
// credential generation (R4, R6). An unknown account and a wrong secret do
// the same hashing and constant-time comparison (against a dummy verifier
// for the unknown account) and get the same response.
func (s *Server) issueLoginToken(w http.ResponseWriter, r *http.Request, c *call, kind TokenKind, accountID model.ID, secret []byte) error {
	if len(secret) != 32 || accountID.IsZero() {
		return errBadRequest("request does not match the schema")
	}
	if !s.limiter.allow(c.route.pattern+"|account", accountID.String(), s.rates.LoginAccount) {
		return errRateLimited
	}
	tok, tokHash, err := newSecret()
	if err != nil {
		return err
	}
	var resp loginResponse
	ok := false
	err = s.store.Update(r.Context(), func(tx Tx) error {
		verifier := s.dummy
		a, err := tx.Account(accountID)
		switch {
		case err == nil && kind == TokenLogin:
			verifier = a.AuthSHA256
		case err == nil:
			verifier = a.RAuthSHA256
		case !errors.Is(err, ErrNotFound):
			return err
		}
		match := crypto.CheckSecretHash(verifier, secret)
		if a == nil || !match {
			return nil
		}
		// Only after the secret matched: a disable is never shown to
		// whoever proved nothing.
		if err := adminRefusal(tx, a.ID, nil); err != nil {
			return err
		}
		ok = true
		resp = loginResponse{LoginToken: tok, VaultID: a.VaultID}
		return tx.InsertLoginToken(&LoginToken{
			TokenHash: tokHash, Kind: kind, AccountID: a.ID, VaultID: a.VaultID,
			CredGen: a.CredGen, ExpiresAt: s.now().Add(LoginTokenTTL),
		})
	})
	if err != nil {
		return err
	}
	if !ok {
		return errUnauthorized
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

type challengeRequest struct {
	AccountID model.ID `json:"account_id"`
	DeviceID  model.ID `json:"device_id"`
	Operation string   `json:"operation"`
}

type challengeResponse struct {
	Challenge []byte `json:"challenge"`
}

// newChallenge returns 256 random bits and the hash they are stored under.
func newChallenge() ([]byte, crypto.Hash, error) {
	b := make([]byte, crypto.ChallengeSize)
	if _, err := rand.Read(b); err != nil {
		return nil, crypto.Hash{}, err
	}
	return b, crypto.SHA256(b), nil
}

// authChallenge: POST /v1/auth/challenge {account_id, device_id, operation}
// → {challenge}. Session challenges need an active device; retire-status
// challenges are issued for any device the account has ever had (R5). The
// challenge is bound to the configured origin, the account, the device,
// the operation and a 60-second expiry. A device of an account the
// operator deleted gets 403 account_deleted instead of the 401 for an
// unknown device (errAccountDeleted).
func (s *Server) authChallenge(w http.ResponseWriter, r *http.Request, c *call) error {
	var req challengeRequest
	if err := s.decode(c.body, &req); err != nil {
		return err
	}
	if req.Operation != crypto.OperationSession && req.Operation != crypto.OperationRetireStatus {
		return errBadRequest("unknown operation")
	}
	if !s.limiter.allow(c.route.pattern+"|device", req.AccountID.String()+"/"+req.DeviceID.String(), s.rates.Device) {
		return errRateLimited
	}
	ch, chHash, err := newChallenge()
	if err != nil {
		return err
	}
	err = s.store.Update(r.Context(), func(tx Tx) error {
		d, err := tx.Device(req.AccountID, req.DeviceID)
		if errors.Is(err, ErrNotFound) {
			if gone, err := tx.DeviceDeleted(req.AccountID, req.DeviceID); err != nil {
				return err
			} else if gone {
				return errAccountDeleted
			}
			return errUnauthorized
		}
		if err != nil {
			return err
		}
		if req.Operation == crypto.OperationSession && !d.Active {
			return errUnauthorized
		}
		now := s.now()
		if err := s.checkChallengeRoom(tx, now, ChallengeScope{AccountID: &req.AccountID, DeviceID: &req.DeviceID}, s.lim.ChallengesPerDevice); err != nil {
			return err
		}
		return tx.InsertChallenge(&Challenge{
			Hash: chHash, Kind: ChallengeDevice, Origin: s.origin, AccountID: req.AccountID,
			DeviceID: req.DeviceID, Operation: req.Operation, ExpiresAt: now.Add(ChallengeTTL),
		})
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, challengeResponse{ch})
	return nil
}

// checkChallengeRoom enforces the outstanding-challenge limits: per scope
// and per process (R8, R14).
func (s *Server) checkChallengeRoom(tx Tx, now time.Time, scope ChallengeScope, perScope int) error {
	n, err := tx.CountChallenges(now, scope)
	if err != nil {
		return err
	}
	if n >= perScope {
		return errRateLimited
	}
	if n, err = tx.CountChallenges(now, ChallengeScope{}); err != nil {
		return err
	}
	if n >= s.lim.ChallengesPerProcess {
		return errBusy
	}
	return nil
}

type sessionRequest struct {
	AccountID model.ID `json:"account_id"`
	DeviceID  model.ID `json:"device_id"`
	Challenge []byte   `json:"challenge"`
	Sig       []byte   `json:"sig"`
}

type sessionResponse struct {
	AccessToken string          `json:"access_token"`
	ExpiresAt   model.Timestamp `json:"expires_at"`
	VaultID     model.ID        `json:"vault_id"`
}

// authSession: POST /v1/auth/session {account_id, device_id, challenge, sig}
// → {access_token, expires_at, vault_id}. vault_id is the vault the session
// is bound to, which a device that enrolled by approval has no other way to
// learn (R1). In one write transaction, serialized with
// every commit (R2): the challenge must be a device challenge for operation
// "session", bound to this account and device and to the configured
// origin, and unexpired; the device must be active; the signature must
// verify over the object rebuilt from the bound values (R5); the account
// must not be disabled, nor the device blocked, by the operator (403
// account_disabled or device_blocked); and the account's bucket must
// admit the request (R14). Only then is the
// challenge consumed and the session issued, so a refusal changes nothing.
func (s *Server) authSession(w http.ResponseWriter, r *http.Request, c *call) error {
	var req sessionRequest
	if err := s.decode(c.body, &req); err != nil {
		return err
	}
	if len(req.Challenge) != crypto.ChallengeSize {
		return errUnauthorized
	}
	tok, tokHash, err := newSecret()
	if err != nil {
		return err
	}
	var resp sessionResponse
	err = s.store.Update(r.Context(), func(tx Tx) error {
		now := s.now()
		ch, err := tx.Challenge(crypto.SHA256(req.Challenge))
		if errors.Is(err, ErrNotFound) {
			return errUnauthorized
		}
		if err != nil {
			return err
		}
		if ch.Kind != ChallengeDevice || ch.Operation != crypto.OperationSession ||
			ch.AccountID != req.AccountID || ch.DeviceID != req.DeviceID ||
			!now.Before(ch.ExpiresAt) || ch.Origin != s.origin {
			return errUnauthorized
		}
		d, err := tx.Device(ch.AccountID, ch.DeviceID)
		if errors.Is(err, ErrNotFound) {
			return errUnauthorized
		}
		if err != nil {
			return err
		}
		if !d.Active {
			return errUnauthorized
		}
		obj := &crypto.DeviceAuth{
			V: crypto.Version, Origin: ch.Origin, AccountID: ch.AccountID, DeviceID: ch.DeviceID,
			Operation: ch.Operation, Challenge: req.Challenge,
		}
		if crypto.VerifyDeviceAuth(ed25519.PublicKey(d.SigPK), obj, req.Sig) != nil {
			return errUnauthorized
		}
		// The signature proved the device's key, so the operator's
		// refusal may be shown. It comes before the account's bucket: a
		// 429 is "unreachable" to a client, which would let it load keys.
		if err := adminRefusal(tx, ch.AccountID, &ch.DeviceID); err != nil {
			return err
		}
		// The signature established the account; its bucket must admit the
		// request before anything is consumed or issued.
		if !s.limiter.allow(c.route.pattern+"|account", ch.AccountID.String(), s.rates.Account) {
			return errRateLimited
		}
		a, err := tx.Account(ch.AccountID)
		if err != nil {
			return err
		}
		if err := tx.DeleteChallenge(ch.Hash); err != nil {
			return err
		}
		exp := now.Add(SessionTTL)
		resp = sessionResponse{AccessToken: tok, ExpiresAt: model.TimestampOf(exp), VaultID: a.VaultID}
		return tx.InsertSession(&Session{
			TokenHash: tokHash, AccountID: a.ID, VaultID: a.VaultID, DeviceID: d.DeviceID,
			ExpiresAt: model.TimestampOf(exp).Time(),
		})
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// principal is the credential a vault request authenticated with.
type principal struct {
	kind      credKind
	tokenHash crypto.Hash
	accountID model.ID
	vaultID   model.ID
	deviceID  model.ID // sessions only
	expiresAt time.Time
	bootstrap *vaultlog.Head // login and recovery tokens: the bootstrap they committed
}

type credKind int

const (
	credSession credKind = iota + 1
	credLogin
	credRecovery
)

// authenticate resolves a bearer credential inside tx: a device session, or
// a login or recovery token whose credential generation is still the
// account's (R2, R6). Sessions are deleted when they are invalidated, so
// finding one unexpired is enough.
func (s *Server) authenticate(tx Tx, tokHash crypto.Hash) (*principal, error) {
	now := s.now()
	sess, err := tx.Session(tokHash)
	switch {
	case err == nil:
		if !now.Before(sess.ExpiresAt) {
			return nil, errUnauthorized
		}
		s.noteSeen(sess.AccountID, sess.DeviceID)
		return &principal{
			kind: credSession, tokenHash: tokHash, accountID: sess.AccountID, vaultID: sess.VaultID,
			deviceID: sess.DeviceID, expiresAt: sess.ExpiresAt,
		}, nil
	case !errors.Is(err, ErrNotFound):
		return nil, err
	}
	lt, err := tx.LoginToken(tokHash)
	if errors.Is(err, ErrNotFound) {
		return nil, errUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if !now.Before(lt.ExpiresAt) {
		return nil, errUnauthorized
	}
	a, err := tx.Account(lt.AccountID)
	if err != nil {
		return nil, err
	}
	if a.CredGen != lt.CredGen {
		return nil, errUnauthorized
	}
	// A disable deletes the account's tokens; this keeps one from outliving
	// it all the same.
	if err := adminRefusal(tx, a.ID, nil); err != nil {
		return nil, err
	}
	p := &principal{
		kind: credLogin, tokenHash: tokHash, accountID: lt.AccountID, vaultID: lt.VaultID,
		expiresAt: lt.ExpiresAt, bootstrap: lt.Bootstrap,
	}
	if lt.Kind == TokenRecovery {
		p.kind = credRecovery
	}
	return p, nil
}
