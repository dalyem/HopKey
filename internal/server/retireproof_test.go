package server

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

func (e *env) retireProofWith(v *tvault, dev model.ID, chal, sig []byte, after uint64) resp {
	e.t.Helper()
	return e.do("POST", "/v1/retire-status/proof", "", retireProofRequest{v.accountID(), after, chal, dev, sig})
}

func (e *env) retireProof(v *tvault, dev model.ID, after uint64) resp {
	e.t.Helper()
	chal := e.newChallenge(v, dev, crypto.OperationRetireStatus)
	return e.retireProofWith(v, dev, chal, e.signAuth(v, dev, crypto.OperationRetireStatus, testOrigin, chal), after)
}

type proofBody struct {
	Entries []struct {
		H    crypto.Hash   `json:"h"`
		Seq  uint64        `json:"seq,string"`
		Wire canonjson.Raw `json:"wire"`
	} `json:"entries"`
	Receipt struct {
		DeviceID model.ID    `json:"device_id"`
		H        crypto.Hash `json:"h"`
		How      string      `json:"how"`
		Seq      uint64      `json:"seq,string"`
	} `json:"receipt"`
}

// The proof endpoint serves a revoked device the signed entries from where
// it asks up to the one that removed it, without objects, and nothing past
// it. Only that device's own retire-status challenge, signed by its key,
// for this account, gets it; a device that never left gets nothing.
func TestRetireProof(t *testing.T) {
	e := newEnv(t)
	v, A, B := twoDevices(t, e)
	from := v.head().Seq
	e.mustPost(v, e.session(v, A), v.normal(A, 1, 10))
	cp := v.checkpoint(A, B)
	e.mustPost(v, e.session(v, A), cp)
	e.mustPost(v, e.session(v, A), v.normal(A, 1, 10)) // after the receipt: never served

	var p proofBody
	e.must(e.retireProof(v, B, from), 200, &p)
	if p.Receipt.DeviceID != B || p.Receipt.How != "revoked" || p.Receipt.Seq != cp.Entry.Seq || !p.Receipt.H.Equal(hashOf(t, cp)) {
		t.Errorf("receipt %+v", p.Receipt)
	}
	if len(p.Entries) != int(cp.Entry.Seq-from) {
		t.Fatalf("%d entries from seq %d to the checkpoint at %d", len(p.Entries), from, cp.Entry.Seq)
	}
	for i, en := range p.Entries {
		w, err := vaultlog.ParseWire(en.Wire)
		if err != nil {
			t.Fatal(err)
		}
		if en.Seq != from+1+uint64(i) || w.Entry.Seq != en.Seq || len(w.Objects) != 0 {
			t.Errorf("entry %d: seq %d, wire seq %d, %d objects", i, en.Seq, w.Entry.Seq, len(w.Objects))
		}
	}
	// From the receipt's own seq on, nothing.
	p = proofBody{}
	e.must(e.retireProof(v, B, cp.Entry.Seq), 200, &p)
	if len(p.Entries) != 0 {
		t.Errorf("%d entries past the receipt", len(p.Entries))
	}

	// A device that never left has no receipt, and no entries.
	wantCode(t, e.retireProof(v, A, from), 404, "not_found", "a device that never left")

	rs := crypto.OperationRetireStatus
	rc := e.newChallenge(v, B, rs)
	sig := e.signAuth(v, B, rs, testOrigin, rc)
	wantCode(t, e.retireProofWith(v, B, rc, e.signAuth(v, A, rs, testOrigin, rc), from), 401, "unauthorized", "B's challenge signed by A")
	wantCode(t, e.retireProofWith(v, A, rc, e.signAuth(v, A, rs, testOrigin, rc), from), 401, "unauthorized", "B's challenge used by A")
	wantCode(t, e.retireProofWith(v, B, rc, e.signAuth(v, B, crypto.OperationSession, testOrigin, rc), from), 401, "unauthorized", "signed as a session")
	wantCode(t, e.retireProofWith(v, B, rc, e.signAuth(v, B, rs, "https://evil.example.com", rc), from), 401, "unauthorized", "another origin")
	other := newVault(t, "b@example.com")
	e.publish(other)
	wantCode(t, e.do("POST", "/v1/retire-status/proof", "", retireProofRequest{other.accountID(), from, rc, B, sig}), 401, "unauthorized", "another account")
	// Correctly used once, and once only.
	wantStatus(t, e.retireProofWith(v, B, rc, sig, from), 200, "the challenge, correctly used")
	wantCode(t, e.retireProofWith(v, B, rc, sig, from), 401, "unauthorized", "the same challenge again")

	// A device the account never had. The challenge endpoint issues it
	// none, so the challenge is planted, with every binding the endpoint
	// checks right; the same planted challenge for B is the control.
	planted := e.plantChallenge(v, B, rs)
	wantStatus(t, e.retireProofWith(v, B, planted, e.signAuth(v, B, rs, testOrigin, planted), from), 200, "a planted challenge for B")
	stranger := randID(t)
	planted = e.plantChallenge(v, stranger, rs)
	strangerSig, err := crypto.SignDeviceAuth(v.devs[B].Sig, &crypto.DeviceAuth{
		V: 1, Origin: testOrigin, AccountID: v.accountID(), DeviceID: stranger, Operation: rs, Challenge: planted,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.retireProofWith(v, stranger, planted, strangerSig, from), 401, "unauthorized", "a device the account never had")
}

// plantChallenge stores a live retire-status or session challenge for dev
// as the challenge endpoint would, whether or not the account has dev.
func (e *env) plantChallenge(v *tvault, dev model.ID, op string) []byte {
	e.t.Helper()
	chal := make([]byte, crypto.ChallengeSize)
	if _, err := rand.Read(chal); err != nil {
		e.t.Fatal(err)
	}
	err := e.st.Update(context.Background(), func(tx Tx) error {
		return tx.InsertChallenge(&Challenge{
			Hash: crypto.SHA256(chal), Kind: ChallengeDevice, Origin: testOrigin, AccountID: v.accountID(),
			DeviceID: dev, Operation: op, ExpiresAt: e.clock.now().Add(ChallengeTTL),
		})
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return chal
}
