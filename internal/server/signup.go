package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// purposeSignup is the operation a signup challenge is bound to (R3).
const purposeSignup = "signup"

// CreateInvite issues a single-use registration capability bound to the
// normalized email (the admin invite of R3) and returns its code. Issuing
// one reveals nothing about existing accounts and reserves nothing.
func CreateInvite(ctx context.Context, st Store, email string, ttl time.Duration, now time.Time) (string, error) {
	norm, err := NormalizeEmail(email)
	if err != nil {
		return "", err
	}
	if ttl <= 0 {
		return "", errors.New("server: invite TTL must be positive")
	}
	code, h, err := newSecret()
	if err != nil {
		return "", err
	}
	err = st.Update(ctx, func(tx Tx) error {
		return tx.InsertRegistration(&Registration{CapHash: h, Email: norm, CreatedAt: now, ExpiresAt: now.Add(ttl)})
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

type signupChallengeRequest struct {
	Email            string `json:"email"`
	RegistrationCode string `json:"registration_code"`
}

// capability resolves a registration code for a normalized email. Every
// failure is the same 401, and nothing about accounts is read before the
// capability is valid (R3).
func (s *Server) capability(tx Tx, code, email string) (*Registration, error) {
	h, ok := secretHash(code)
	if !ok {
		return nil, errUnauthorized
	}
	reg, err := tx.Registration(h)
	if errors.Is(err, ErrNotFound) {
		return nil, errUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if reg.Email != email {
		return nil, errUnauthorized
	}
	return reg, nil
}

// signupChallenge: POST /v1/signup/challenge {email, registration_code} →
// {challenge}. The capability must be valid, unexpired and unused; at most
// 16 of its challenges are outstanding (R14). The challenge is bound to the
// configured origin, the normalized email, the capability and the purpose
// "signup", and is never accepted by device authentication (R3).
func (s *Server) signupChallenge(w http.ResponseWriter, r *http.Request, c *call) error {
	var req signupChallengeRequest
	if err := s.decode(c.body, &req); err != nil {
		return err
	}
	email, err := NormalizeEmail(req.Email)
	if err != nil {
		return errBadRequest("invalid email")
	}
	ch, chHash, err := newChallenge()
	if err != nil {
		return err
	}
	err = s.store.Update(r.Context(), func(tx Tx) error {
		reg, err := s.capability(tx, req.RegistrationCode, email)
		if err != nil {
			return err
		}
		now := s.now()
		if reg.Ack != nil || !now.Before(reg.ExpiresAt) {
			return errUnauthorized
		}
		if err := s.checkChallengeRoom(tx, now, ChallengeScope{CapHash: &reg.CapHash}, s.lim.ChallengesPerCapability); err != nil {
			return err
		}
		return tx.InsertChallenge(&Challenge{
			Hash: chHash, Kind: ChallengeSignup, Origin: s.origin, Operation: purposeSignup,
			Email: email, CapHash: reg.CapHash, ExpiresAt: now.Add(ChallengeTTL),
		})
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, challengeResponse{ch})
	return nil
}

type signupRequest struct {
	Email            string          `json:"email"`
	RegistrationCode string          `json:"registration_code"`
	Challenge        []byte          `json:"challenge"`
	PopSig           []byte          `json:"pop_sig"`
	Wires            []canonjson.Raw `json:"wires"`
}

// validChallenge checks a signup challenge against what it must be bound
// to (R3).
func (s *Server) validChallenge(tx Tx, value []byte, email string, capHash crypto.Hash) (*Challenge, error) {
	if len(value) != crypto.ChallengeSize {
		return nil, errUnauthorized
	}
	ch, err := tx.Challenge(crypto.SHA256(value))
	if errors.Is(err, ErrNotFound) {
		return nil, errUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if ch.Kind != ChallengeSignup || ch.Operation != purposeSignup || ch.Email != email ||
		ch.CapHash != capHash || ch.Origin != s.origin || !s.now().Before(ch.ExpiresAt) {
		return nil, errUnauthorized
	}
	return ch, nil
}

// publicationDigest identifies a canonical validated publication: the
// stored wires, in order.
func publicationDigest(pws []*prepared) crypto.Hash {
	d := sha256.New()
	for _, pw := range pws {
		d.Write(crypto.LP(pw.canon))
	}
	var h crypto.Hash
	d.Sum(h[:0])
	return h
}

// signup: POST /v1/signup {email, registration_code, challenge, pop_sig,
// wires} → {seq, h}: the §4.3 publication under R3.
//
//  1. A signup validation slot (2 running, 8 waiting; 429 when full), then
//     the body, at most 64 MiB.
//  2. The capability must exist and be bound to the normalized email.
//  3. A consumed capability only retrieves its acknowledgment, for the
//     same email and the same canonical publication, even after expiry and
//     later appends; any other publication is refused.
//  4. Otherwise: an unexpired capability, a valid signup challenge, every
//     wire validated with ApplyPublic from empty state (outside the writer
//     transaction), and pop_sig verified under the account key at the
//     upload head, over values taken from the validated publication.
//  5. One write transaction rechecks the capability and the challenge,
//     checks uniqueness (one generic registration_conflict), and commits
//     everything, consuming the capability and the challenge and storing
//     the acknowledgment. Nothing is written on any failure.
func (s *Server) signup(w http.ResponseWriter, r *http.Request, c *call) error {
	release, ok := s.signups.acquire(r.Context())
	if !ok {
		return errBusy
	}
	defer release()
	body, err := readBody(w, r, s.lim.MaxSignupBody)
	if err != nil {
		return err
	}
	if !s.collectionsWithin(body, "wires") {
		return errTooLarge
	}
	var req signupRequest
	if err := s.decode(body, &req); err != nil {
		return err
	}
	email, err := NormalizeEmail(req.Email)
	if err != nil {
		return errBadRequest("invalid email")
	}
	var reg *Registration
	err = s.store.View(r.Context(), func(tx Tx) (err error) {
		reg, err = s.capability(tx, req.RegistrationCode, email)
		return err
	})
	if err != nil {
		return err
	}

	if len(req.Wires) == 0 {
		return errBadRequest("no wires")
	}
	if len(req.Wires) > s.lim.MaxSignupWires {
		return errTooLarge
	}
	pws := make([]*prepared, len(req.Wires))
	for i, raw := range req.Wires {
		wire, err := vaultlog.ParseWire(raw)
		if err != nil {
			return errInvalidEntry(err)
		}
		if pws[i], err = s.prepare(wire); err != nil {
			return err
		}
	}
	digest := publicationDigest(pws)
	if reg.Ack != nil {
		return s.ackRetry(w, reg.Ack, digest)
	}
	if !s.now().Before(reg.ExpiresAt) {
		return errUnauthorized
	}
	err = s.store.View(r.Context(), func(tx Tx) error {
		_, err := s.validChallenge(tx, req.Challenge, email, reg.CapHash)
		return err
	})
	if err != nil {
		return err
	}

	// Validate the whole publication from empty state, keeping only what
	// the commit needs: each entry's departures, the final state and the
	// R13 charge, in which each object counts once.
	deps := make([][]vaultlog.Departure, len(pws))
	objs := vaultlog.ObjectMap{}
	have := pubStored{objs, map[model.ID]bool{}}
	var cost int64
	var final *vaultlog.PublicState
	for i, pw := range pws {
		post, err := vaultlog.ApplyPublic(final, pw.w, objs)
		if err != nil {
			return errInvalidEntry(err)
		}
		if i > 0 && (post.VaultID() != final.VaultID() || post.AccountID() != final.AccountID()) {
			return errBadRequest("the publication changes its account or vault")
		}
		deps[i], final = post.Departures(), post
		c, err := entryCost(pw, len(deps[i]), have)
		if err != nil {
			return err
		}
		cost += c
		for _, o := range pw.w.Objects {
			objs[o.SHA256] = o.Body
		}
		for _, op := range pw.w.Entry.Ops {
			if d, ok := op.(*vaultlog.DeviceAddOp); ok {
				have.devices[d.Cert.DeviceID] = true
			}
		}
	}
	ps, err := final.Marshal()
	if err != nil {
		return err
	}
	cost += int64(len(ps))
	head := final.Head()
	acct, _ := final.Account()
	pop := &crypto.SignupPoP{
		V: crypto.Version, Origin: s.origin, Email: email, AccountID: final.AccountID(),
		VaultID: final.VaultID(), UploadSeq: head.Seq, UploadH: head.H, Challenge: req.Challenge,
	}
	if crypto.VerifySignupPoP(acct.SigPK, pop, req.PopSig) != nil {
		return errUnauthorized
	}

	var ack *Ack
	err = s.store.Update(r.Context(), func(tx Tx) error {
		reg, err := s.capability(tx, req.RegistrationCode, email)
		if err != nil {
			return err
		}
		if reg.Ack != nil {
			ack = reg.Ack
			return nil
		}
		now := s.now()
		if !now.Before(reg.ExpiresAt) {
			return errUnauthorized
		}
		ch, err := s.validChallenge(tx, req.Challenge, email, reg.CapHash)
		if err != nil {
			return err
		}
		taken, err := tx.AccountTaken(final.AccountID(), email, final.VaultID())
		if err != nil {
			return err
		}
		if taken {
			return errRegConflict
		}
		a := &Account{ID: final.AccountID(), Email: email, VaultID: final.VaultID(), CreatedAt: now}
		v := &Vault{ID: final.VaultID(), AccountID: a.ID, LastBootstrap: -1}
		if _, ok := s.admit(a, nil, "", cost); !ok {
			return errQuota
		}
		// The rows exist first (the log references them) and are completed
		// from the final state below.
		a.Salt, v.PublicState = []byte{}, []byte{}
		if err := tx.InsertAccount(a); err != nil {
			return err
		}
		if err := tx.InsertVault(v); err != nil {
			return err
		}
		for i, pw := range pws {
			if err := s.applyEntry(tx, a, v, pw, deps[i]); err != nil {
				return err
			}
		}
		a.UsedBytes = cost
		if err := setState(a, v, final, ps); err != nil {
			return err
		}
		if err := tx.UpdateVault(v); err != nil {
			return err
		}
		if err := tx.UpdateAccount(a); err != nil {
			return err
		}
		if err := tx.DeleteChallenge(ch.Hash); err != nil {
			return err
		}
		ack = &Ack{AccountID: a.ID, VaultID: v.ID, Digest: digest, Head: head}
		return tx.ConsumeRegistration(reg.CapHash, ack, now)
	})
	if err != nil {
		return err
	}
	return s.ackRetry(w, ack, digest)
}

// ackRetry answers with an acknowledgment if the publication is the one it
// acknowledges, and refuses any other (R3).
func (s *Server) ackRetry(w http.ResponseWriter, ack *Ack, digest crypto.Hash) error {
	if !ack.Digest.Equal(digest) {
		return errRegConflict
	}
	writeJSON(w, http.StatusOK, ack.Head)
	return nil
}
