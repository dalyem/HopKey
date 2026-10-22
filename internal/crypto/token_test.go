package crypto

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

// Builds the token string bit by bit: raw as a 512-bit string, 3 zero bits
// appended, split into 103 five-bit symbols.
func tokenByHand(raw []byte) string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var bits strings.Builder
	for _, b := range raw {
		for i := 7; i >= 0; i-- {
			bits.WriteByte('0' + (b>>i)&1)
		}
	}
	bits.WriteString("000")
	s := bits.String()
	var out strings.Builder
	out.WriteString("hop1_")
	for i := 0; i < len(s); i += 5 {
		n := 0
		for _, c := range s[i : i+5] {
			n = n<<1 | int(c-'0')
		}
		out.WriteByte(alphabet[n])
	}
	return out.String()
}

func TestTokenBitByBit(t *testing.T) {
	acct := fixedSig("account-sig")
	pub := acct.Public().(ed25519.PublicKey)
	tok := &Token{GrantID: fixedID(0x70)}
	copy(tok.Seed[:], fixedBytes("seed", 32))
	fp := FpSig(pub)
	copy(tok.AcctFp[:], fp[:16])

	rawBytes := append(append(append([]byte{}, tok.GrantID[:]...), tok.Seed[:]...), fp[:16]...)
	want := tokenByHand(rawBytes)
	got := tok.String()
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if len(got) != 108 {
		t.Fatalf("token is %d characters", len(got))
	}
	back, err := ParseToken(got)
	if err != nil {
		t.Fatal(err)
	}
	if *back != *tok {
		t.Fatal("parse did not round-trip")
	}
	if !back.MatchesAccount(pub) || back.MatchesAccount(fixedSig("x").Public().(ed25519.PublicKey)) {
		t.Fatal("account fingerprint check is wrong")
	}
}

// Hand cases: all-zero raw is 103 zeros; all-ones raw ends with the two
// remaining data bits and the three padding bits, 11000 = 24 = 'R'.
func TestTokenHandCases(t *testing.T) {
	zero := "hop1_" + strings.Repeat("0", 103)
	tok, err := ParseToken(zero)
	if err != nil {
		t.Fatal(err)
	}
	if tok.String() != zero {
		t.Fatal("all-zero token does not round-trip")
	}
	ones := &Token{}
	for i := range ones.GrantID {
		ones.GrantID[i] = 0xff
	}
	for i := range ones.Seed {
		ones.Seed[i] = 0xff
	}
	for i := range ones.AcctFp {
		ones.AcctFp[i] = 0xff
	}
	if want := "hop1_" + strings.Repeat("Z", 102) + "R"; ones.String() != want {
		t.Fatalf("all-ones token = %s", ones.String())
	}
}

func TestParseTokenRules(t *testing.T) {
	tok := &Token{GrantID: fixedID(0x70)}
	copy(tok.Seed[:], fixedBytes("seed", 32))
	good := tok.String()
	body := good[5:]

	// Lowercase and the I/L/O substitutions are accepted.
	lower := "hop1_" + strings.ToLower(body)
	if back, err := ParseToken(lower); err != nil || *back != *tok {
		t.Errorf("lowercase rejected: %v", err)
	}
	sub := strings.NewReplacer("1", "I", "0", "O").Replace(body)
	if back, err := ParseToken("hop1_" + sub); err != nil || *back != *tok {
		t.Errorf("I/O substitution rejected: %v", err)
	}
	sub = strings.NewReplacer("1", "l", "0", "o").Replace(body)
	if back, err := ParseToken("hop1_" + sub); err != nil || *back != *tok {
		t.Errorf("l/o substitution rejected: %v", err)
	}
	sub = strings.ReplaceAll(body, "1", "L")
	if back, err := ParseToken("hop1_" + sub); err != nil || *back != *tok {
		t.Errorf("L substitution rejected: %v", err)
	}

	// The last symbol carries 2 data bits and 3 padding bits; any of
	// values 1..7 above its data bits sets padding.
	last := crockfordValue(body[102])
	padded := body[:102] + string(crockfordAlphabet[last|1])
	for name, in := range map[string]string{
		"nonzero padding (1)": padded,
		"nonzero padding (4)": body[:102] + string(crockfordAlphabet[last|4]),
		"102 symbols":         body[:102],
		"104 symbols":         body + "0",
		"hyphen":              body[:50] + "-" + body[51:],
		"hyphen inserted":     body[:50] + "-" + body[50:102],
		"U":                   body[:50] + "U" + body[51:],
		"symbol *":            body[:50] + "*" + body[51:],
		"space":               body[:50] + " " + body[51:],
		"non-ASCII":           body[:50] + "é" + body[52:],
	} {
		if _, err := ParseToken("hop1_" + in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, in := range map[string]string{
		"uppercase prefix": "HOP1_" + body,
		"no prefix":        body + "00000",
		"other prefix":     "hop2_" + body,
		"empty":            "",
		"prefix only":      "hop1_",
	} {
		if _, err := ParseToken(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTokenDerivations(t *testing.T) {
	tok := &Token{GrantID: fixedID(0x70)}
	copy(tok.Seed[:], fixedBytes("seed", 32))
	auth, err := tok.Auth()
	if err != nil {
		t.Fatal(err)
	}
	wantAuth, _ := hkdfKey(tok.Seed[:], tok.GrantID[:], LP([]byte("hopkey/v1/token-auth")), 32)
	if !bytes.Equal(auth, wantAuth) {
		t.Fatal("tAuth does not follow §8.1")
	}
	k1, err := tok.KEMKey()
	if err != nil {
		t.Fatal(err)
	}
	ikm, _ := hkdfKey(tok.Seed[:], tok.GrantID[:], LP([]byte("hopkey/v1/token-kem")), 32)
	k2, err := DeriveKEMKey(ikm)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1.PublicKey().Bytes(), k2.PublicKey().Bytes()) {
		t.Fatal("tKem does not follow §8.1")
	}
	other := *tok
	other.GrantID = fixedID(0x71)
	k3, _ := other.KEMKey()
	if bytes.Equal(k1.PublicKey().Bytes(), k3.PublicKey().Bytes()) {
		t.Fatal("grant_id does not salt tKem")
	}
	if !CheckSecretHash(SHA256(auth), auth) {
		t.Fatal("tAuth hash check failed")
	}

	n, err := NewToken(fixedID(0x72), fixedSig("a").Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if n.Seed == ([32]byte{}) {
		t.Fatal("NewToken left the seed empty")
	}
}
