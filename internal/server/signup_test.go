package server

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// nothingStored checks that a vault left no trace: no account, vault,
// entries, objects or devices.
func (e *env) nothingStored(v *tvault) {
	e.t.Helper()
	e.view(func(tx Tx) error {
		if _, err := tx.Account(v.accountID()); !errors.Is(err, ErrNotFound) {
			e.t.Errorf("account stored: %v", err)
		}
		if _, err := tx.Vault(v.vaultID()); !errors.Is(err, ErrNotFound) {
			e.t.Errorf("vault stored: %v", err)
		}
		for _, w := range v.log {
			if _, err := tx.Entry(v.vaultID(), w.Entry.Seq); !errors.Is(err, ErrNotFound) {
				e.t.Errorf("entry %d stored: %v", w.Entry.Seq, err)
			}
			for _, d := range w.Entry.ObjectDigests() {
				if _, err := tx.Object(v.vaultID(), d); !errors.Is(err, ErrNotFound) {
					e.t.Errorf("object %v stored: %v", d, err)
				}
			}
		}
		for _, d := range v.order {
			if _, err := tx.Device(v.accountID(), d); !errors.Is(err, ErrNotFound) {
				e.t.Errorf("device %v stored: %v", d, err)
			}
		}
		return nil
	})
}

func (e *env) signupResp(req signupRequest) resp { return e.do("POST", "/v1/signup", "", req) }

// A registration capability bound to the normalized email is required, and
// every capability failure looks the same (R3).
func TestSignupRequiresCapability(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	code := e.invite("A@Example.COM ") // the domain is normalized; the local part is not
	if _, err := NormalizeEmail("A@Example.COM "); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.do("POST", "/v1/signup/challenge", "", signupChallengeRequest{v.email, code}), 401, "unauthorized",
		"a capability for another local part")
	code = e.invite(v.email)
	otherCode := e.invite("other@example.com")
	chal := e.signupChallenge(v.email, code)

	var first []byte
	for name, req := range map[string]signupRequest{
		"no code":            e.signupReq(v, "", chal, 0, nil, testOrigin),
		"unknown code":       e.signupReq(v, e.invite("x@example.com")[:42]+"A", chal, 0, nil, testOrigin),
		"another email code": e.signupReq(v, otherCode, chal, 0, nil, testOrigin),
	} {
		r := e.signupResp(req)
		wantCode(t, r, 401, "unauthorized", name)
		if first == nil {
			first = r.body
		} else if !bytes.Equal(first, r.body) {
			t.Errorf("%s: %s differs from %s", name, r.body, first)
		}
	}
	// Signup and signup challenges both refuse an unknown capability the same
	// way.
	wantCode(t, e.do("POST", "/v1/signup/challenge", "", signupChallengeRequest{v.email, "AAAA"}), 401, "unauthorized", "a malformed code")
	// The challenge must belong to this capability, and be fresh.
	otherChal := e.signupChallenge("other@example.com", otherCode)
	wantCode(t, e.signupResp(e.signupReq(v, code, otherChal, 0, nil, testOrigin)), 401, "unauthorized", "another capability's challenge")
	// Two capabilities for the same email: a challenge belongs to one.
	sameEmail := e.invite(v.email)
	wantCode(t, e.signupResp(e.signupReq(v, code, e.signupChallenge(v.email, sameEmail), 0, nil, testOrigin)), 401, "unauthorized",
		"a challenge of another capability for the same email")
	devChal := e.newChallengeForSignupTest(t)
	wantCode(t, e.signupResp(e.signupReq(v, code, devChal, 0, nil, testOrigin)), 401, "unauthorized", "a device challenge")
	wantCode(t, e.signupResp(e.signupReq(v, code, chal, 0, nil, "https://evil.example.com")), 401, "unauthorized", "pop_sig for another origin")
	e.nothingStored(v)

	// A capability that expires while its challenge is still fresh.
	short, err := CreateInvite(t.Context(), e.st, v.email, 2*time.Minute, e.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	e.clock.advance(110 * time.Second)
	shortChal := e.signupChallenge(v.email, short)
	e.clock.advance(20 * time.Second)
	wantCode(t, e.signupResp(e.signupReq(v, short, shortChal, 0, nil, testOrigin)), 401, "unauthorized",
		"an expired capability with a fresh challenge")
	e.nothingStored(v)

	// An expired capability that was never used registers nothing.
	e.clock.advance(7*24*time.Hour + time.Second)
	wantCode(t, e.do("POST", "/v1/signup/challenge", "", signupChallengeRequest{v.email, code}), 401, "unauthorized", "an expired capability")
	wantCode(t, e.signupResp(e.signupReq(v, code, chal, 0, nil, testOrigin)), 401, "unauthorized", "signup with an expired capability")
	e.nothingStored(v)
}

// newChallengeForSignupTest returns a device challenge of some other
// account.
func (e *env) newChallengeForSignupTest(t *testing.T) []byte {
	o := newVault(t, "dev-owner@example.com")
	e.publish(o)
	return e.newChallenge(o, o.dev(0), "session")
}

// pop_sig must be made with the account key at the upload head: on a vault
// with a checkpoint, the genesis key no longer proves possession (R3).
func TestSignupPopUsesHeadKey(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	v.normal(v.dev(0), 1, 10)
	v.checkpoint(v.dev(0))
	code := e.invite(v.email)
	chal := e.signupChallenge(v.email, code)
	wantCode(t, e.signupResp(e.signupReq(v, code, chal, 0, v.accts[1], testOrigin)), 401, "unauthorized", "a pop by the genesis key")
	e.nothingStored(v)
	var h vaultlog.Head
	e.must(e.signupResp(e.signupReq(v, code, chal, 0, v.accts[2], testOrigin)), 200, &h)
	if h != v.head() {
		t.Errorf("acknowledged %+v, want %+v", h, v.head())
	}
	// The derived creds come from the latest creds op, and both devices'
	// keys were recorded.
	e.view(func(tx Tx) error {
		a, err := tx.Account(v.accountID())
		if err != nil {
			return err
		}
		if a.CredGen != 2 || !bytes.Equal(a.Salt, v.st.Creds.Salt) || a.VaultID != v.vaultID() || a.Email != v.email {
			t.Errorf("account %+v", a)
		}
		return nil
	})
	wantStatus(t, e.do("POST", "/v1/login", "", loginRequest{v.accountID(), v.authKey}), 200, "login with the latest credentials")
}

// A lost response is recovered by reposting the same publication, even
// after the capability and the challenge expired and the log moved on; any
// other publication is refused (R3).
func TestSignupRetryAfterLostResponse(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	v.normal(v.dev(0), 1, 10)
	code := e.invite(v.email)
	chal := e.signupChallenge(v.email, code)
	req := e.signupReq(v, code, chal, 0, nil, testOrigin)
	upload := v.head()
	var h vaultlog.Head
	e.must(e.signupResp(req), 200, &h)
	if h != upload {
		t.Fatalf("ack %+v, want %+v", h, upload)
	}
	wantCode(t, e.do("POST", "/v1/signup/challenge", "", signupChallengeRequest{v.email, code}), 401, "unauthorized",
		"a challenge for a used capability")

	tok := e.session(v, v.dev(0))
	e.mustPost(v, tok, v.normal(v.dev(0), 1, 10))
	e.clock.advance(8 * 24 * time.Hour)

	// Identical, and identical but non-canonical (the canonical validated
	// publication is the same).
	e.must(e.signupResp(req), 200, &h)
	if h != upload {
		t.Errorf("retry ack %+v, want the original upload head %+v", h, upload)
	}
	loose := req
	loose.Wires = append([]canonjson.Raw{}, req.Wires...)
	loose.Wires[0] = append(canonjson.Raw(" "), req.Wires[0]...)
	e.must(e.signupResp(loose), 200, &h)

	// Different publications: a prefix, and the longer current log.
	prefix := req
	prefix.Wires = req.Wires[:1]
	wantCode(t, e.signupResp(prefix), 409, "registration_conflict", "a prefix of the publication")
	longer := e.signupReq(v, code, chal, 0, nil, testOrigin)
	wantCode(t, e.signupResp(longer), 409, "registration_conflict", "a longer publication")
	// The retry changed nothing: the head is still the appended entry.
	r, p := e.readLog(v, e.session(v, v.dev(0)), "")
	wantStatus(t, r, 200, "log")
	if p.Head != v.head() {
		t.Errorf("head %+v, want %+v", p.Head, v.head())
	}
}

// A failed signup leaves nothing behind and does not consume the
// capability or the challenge (R3).
func TestSignupFailureLeavesNothing(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	v.normal(v.dev(0), 2, 10)
	B, _ := v.bootstrap("dev-b")
	v.normal(B, 1, 10)
	code := e.invite(v.email)
	chal := e.signupChallenge(v.email, code)
	good := e.signupReq(v, code, chal, 0, nil, testOrigin)

	bad := good
	bad.Wires = append([]canonjson.Raw{}, good.Wires...)
	w := *v.log[2]
	w.Sigs = []vaultlog.Sig{{Role: vaultlog.RoleAccount, Sig: bytes.Repeat([]byte{2}, 64)}}
	bad.Wires[2] = wireJSON(t, &w)
	wantCode(t, e.signupResp(bad), 400, "invalid_entry", "a badly signed third wire")
	e.nothingStored(v)

	gap := good
	gap.Wires = append(append([]canonjson.Raw{}, good.Wires[:1]...), good.Wires[2:]...)
	wantCode(t, e.signupResp(gap), 400, "invalid_entry", "a publication with a gap")
	e.nothingStored(v)

	noGenesis := good
	noGenesis.Wires = good.Wires[1:]
	wantCode(t, e.signupResp(noGenesis), 400, "invalid_entry", "a publication without genesis")
	e.nothingStored(v)

	var h vaultlog.Head
	e.must(e.signupResp(good), 200, &h)
	if h != v.head() {
		t.Errorf("ack %+v", h)
	}
	e.view(func(tx Tx) error {
		for _, d := range []model.ID{v.dev(0), B} {
			dev, err := tx.Device(v.accountID(), d)
			if err != nil || !dev.Active {
				t.Errorf("device %v: %+v, %v", d, dev, err)
			}
		}
		return nil
	})
}

// Uniqueness conflicts return one generic error, only after the capability
// and the proof are valid (R3).
func TestSignupConflictIsGeneric(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)

	// The same vault under another email.
	twin := *v
	twin.email = "twin@example.com"
	code := e.invite(twin.email)
	r1 := e.signupResp(e.signupReq(&twin, code, e.signupChallenge(twin.email, code), 0, nil, testOrigin))
	wantCode(t, r1, 409, "registration_conflict", "the same vault under another email")
	// Another vault under the same email.
	w := newVault(t, v.email)
	code2 := e.invite(v.email)
	r2 := e.signupResp(e.signupReq(w, code2, e.signupChallenge(v.email, code2), 0, nil, testOrigin))
	wantCode(t, r2, 409, "registration_conflict", "another vault under the same email")
	if !bytes.Equal(r1.body, r2.body) {
		t.Errorf("conflicts differ: %s / %s", r1.body, r2.body)
	}
	e.nothingStored(w)
	// The failed attempt did not consume the capability.
	wantStatus(t, e.do("POST", "/v1/signup/challenge", "", signupChallengeRequest{v.email, code2}), 200, "the capability after a conflict")
	// A bad proof is refused before uniqueness is looked at.
	code3 := e.invite("third@example.com")
	third := *v
	third.email = "third@example.com"
	wantCode(t, e.signupResp(e.signupReq(&third, code3, e.signupChallenge(third.email, code3), 0, nil, "https://evil.example.com")),
		401, "unauthorized", "a conflicting upload with a bad proof")
}

func TestSignupLimits(t *testing.T) {
	e := newEnv(t, withLimits(func(l *Limits) { l.MaxWireResponse = 6000 }))
	v := newVault(t, "a@example.com")
	code := e.invite(v.email)
	for range 16 {
		e.signupChallenge(v.email, code)
	}
	wantCode(t, e.do("POST", "/v1/signup/challenge", "", signupChallengeRequest{v.email, code}), 429, "rate_limited",
		"a 17th outstanding challenge for one capability")
	e.clock.advance(ChallengeTTL)
	chal := e.signupChallenge(v.email, code)
	v.normal(v.dev(0), 1, 6000)
	wantCode(t, e.signupResp(e.signupReq(v, code, chal, 0, nil, testOrigin)), 413, "too_large", "a wire over the singleton cap")
	e.nothingStored(v)
}
