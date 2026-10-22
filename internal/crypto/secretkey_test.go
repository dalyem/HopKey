package crypto

import (
	"math/big"
	"strings"
	"testing"
)

// Builds the text form bit by bit with big.Int, independently of the
// encoder: the 130-bit value is split into 26 five-bit symbols MSB first,
// and the check symbol is the value mod 37.
func TestSecretKeyBitByBit(t *testing.T) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U"
	var sk SecretKey
	sk.Hint = "A1B2C3"
	copy(sk.SK17[:], fixedBytes("bits", 17))
	sk.SK17[0] &= 0x03 // top 6 bits zero
	v := new(big.Int).SetBytes(sk.SK17[:])

	var bits strings.Builder
	for i := 129; i >= 0; i-- {
		bits.WriteByte('0' + byte(v.Bit(i)))
	}
	var secret strings.Builder
	for s := 0; s < 26; s++ {
		chunk := bits.String()[5*s : 5*s+5]
		n := 0
		for _, c := range chunk {
			n = n<<1 | int(c-'0')
		}
		secret.WriteByte(alphabet[n])
	}
	check := alphabet[new(big.Int).Mod(v, big.NewInt(37)).Int64()]
	got := sk.String()
	flat := strings.ReplaceAll(got, "-", "")
	if want := "H1" + "A1B2C3" + secret.String() + string(check); flat != want {
		t.Fatalf("got  %s\nwant %s", flat, want)
	}

	back, err := ParseSecretKey(got)
	if err != nil {
		t.Fatal(err)
	}
	if back != sk {
		t.Fatal("parse did not round-trip")
	}
}

// Hand-computed values, including check symbols from the extended range.
func TestSecretKeyHandCases(t *testing.T) {
	zeros := strings.Repeat("0", 25)
	for _, tc := range []struct {
		value int64
		text  string // 26 secret symbols + check
	}{
		{0, zeros + "0" + "0"},
		{1, zeros + "1" + "1"},
		{31, zeros + "Z" + "Z"},
		{32, strings.Repeat("0", 24) + "10" + "*"},
		{33, strings.Repeat("0", 24) + "11" + "~"},
		{34, strings.Repeat("0", 24) + "12" + "$"},
		{35, strings.Repeat("0", 24) + "13" + "="},
		{36, strings.Repeat("0", 24) + "14" + "U"},
		{37, strings.Repeat("0", 24) + "15" + "0"},
	} {
		var sk SecretKey
		sk.Hint = "000000"
		big.NewInt(tc.value).FillBytes(sk.SK17[:])
		if flat := strings.ReplaceAll(sk.String(), "-", ""); flat != "H1000000"+tc.text {
			t.Errorf("value %d: %s", tc.value, flat)
		}
		back, err := ParseSecretKey("H1000000" + tc.text)
		if err != nil || back != sk {
			t.Errorf("value %d: parse: %v", tc.value, err)
		}
	}
	// All 130 bits set.
	var sk SecretKey
	sk.Hint = "ZZZZZZ"
	sk.SK17[0] = 0x03
	for i := 1; i < 17; i++ {
		sk.SK17[i] = 0xff
	}
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(1))
	check := "0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U"[new(big.Int).Mod(max, big.NewInt(37)).Int64()]
	if flat := strings.ReplaceAll(sk.String(), "-", ""); flat != "H1ZZZZZZ"+strings.Repeat("Z", 26)+string(check) {
		t.Errorf("max value: %s", flat)
	}
}

func TestParseSecretKeyLenient(t *testing.T) {
	sk, err := GenerateSecretKey("ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	if sk.SK17[0]>>2 != 0 {
		t.Fatal("generated SK17 has nonzero top bits")
	}
	text := sk.String()
	if len(strings.ReplaceAll(text, "-", "")) != 2+6+26+1 {
		t.Fatalf("text form %q has the wrong length", text)
	}
	variants := []string{
		text,
		strings.ToLower(text),
		strings.ReplaceAll(text, "-", ""),
		"-" + strings.ReplaceAll(text, "-", "--") + "-",
		strings.ReplaceAll(strings.ReplaceAll(text, "1", "l"), "0", "o"),
		strings.ReplaceAll(text, "1", "I"),
	}
	for _, v := range variants {
		back, err := ParseSecretKey(v)
		if err != nil || back.SK17 != sk.SK17 || back.Hint != sk.Hint {
			t.Errorf("%q: %v", v, err)
		}
	}
}

func TestParseSecretKeyRejects(t *testing.T) {
	var sk SecretKey
	sk.Hint = "ABCDEF"
	copy(sk.SK17[:], fixedBytes("reject", 17))
	sk.SK17[0] &= 0x03
	flat := strings.ReplaceAll(sk.String(), "-", "")
	flip := func(i int) string {
		b := []byte(flat)
		if b[i] == '0' {
			b[i] = '1'
		} else {
			b[i] = '0'
		}
		return string(b)
	}
	for name, in := range map[string]string{
		"one secret symbol changed": flip(10),
		"check symbol changed":      flip(len(flat) - 1),
		"too short":                 flat[:len(flat)-1],
		"too long":                  flat + "0",
		"bad prefix":                "H2" + flat[2:],
		"no prefix":                 flat[2:] + "00",
		"bad character":             flat[:12] + "#" + flat[13:],
		"U in the secret":           flat[:12] + "U" + flat[13:],
		"check-only symbol in hint": "H1*BCDEF" + flat[8:],
		"empty":                     "",
		"spaces":                    strings.ReplaceAll(sk.String(), "-", " "),
	} {
		if _, err := ParseSecretKey(in); err == nil {
			t.Errorf("%s: accepted %q", name, in)
		}
	}
	if _, err := GenerateSecretKey("ABCDE"); err == nil {
		t.Error("5-symbol hint accepted")
	}
}
