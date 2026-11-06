package crypto

import (
	"errors"
	"math/big"
	"regexp"
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

// §12 layout: H1-HHHHHH-SSSSSS-SSSSS-SSSSS-SSSSS-SSSSSC. The final group
// (what §4.3 has the user type back) includes the check symbol.
func TestSecretKeyLayout(t *testing.T) {
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^H1-[0-9A-HJKMNP-TV-Z]{6}-[0-9A-HJKMNP-TV-Z]{6}(-[0-9A-HJKMNP-TV-Z]{5}){3}-[0-9A-HJKMNP-TV-Z]{5}[0-9A-HJKMNP-TV-Z*~$=U]$`)
	if text := sk.String(); !re.MatchString(text) {
		t.Fatalf("layout: %q", text)
	}
}

// The hint is drawn at random at signup (§12): 6 Crockford symbols that
// differ between keys.
func TestNewSecretKeyRandomHint(t *testing.T) {
	seen := map[string]bool{}
	for range 64 {
		sk, err := NewSecretKey()
		if err != nil {
			t.Fatal(err)
		}
		if h, ok := normalizeHint(sk.Hint); !ok || h != sk.Hint {
			t.Fatalf("hint %q is not 6 canonical Crockford symbols", sk.Hint)
		}
		if sk.SK17[0]>>2 != 0 {
			t.Fatal("generated SK17 has nonzero top bits")
		}
		seen[sk.Hint] = true
	}
	// 64 draws from 2^30 hints: a repeat is a broken generator.
	if len(seen) != 64 {
		t.Fatalf("%d distinct hints in 64 draws", len(seen))
	}
}

// Recovery Key text form built with big.Int, independently of the
// encoder: RK is 256 bits, padded on the right with 4 zero bits to 260,
// split into 52 five-bit symbols, and the check symbol is the value of
// those 52 symbols mod 37.
func TestRecoveryKeyBitByBit(t *testing.T) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U"
	var rk RecoveryKey
	copy(rk[:], fixedBytes("rk bits", 32))
	v := new(big.Int).Lsh(new(big.Int).SetBytes(rk[:]), 4)
	var sym strings.Builder
	for s := 51; s >= 0; s-- {
		sym.WriteByte(alphabet[new(big.Int).And(new(big.Int).Rsh(v, uint(5*s)), big.NewInt(31)).Int64()])
	}
	check := alphabet[new(big.Int).Mod(v, big.NewInt(37)).Int64()]
	want := "R1"
	for i := 0; i < 52; i += 4 {
		want += "-" + sym.String()[i:i+4]
	}
	want += string(check)
	if got := rk.String(); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	re := regexp.MustCompile(`^R1(-[0-9A-HJKMNP-TV-Z]{4}){12}-[0-9A-HJKMNP-TV-Z]{4}[0-9A-HJKMNP-TV-Z*~$=U]$`)
	if !re.MatchString(want) {
		t.Fatalf("layout: %q", want)
	}
	back, err := ParseRecoveryKey(want)
	if err != nil || back != rk {
		t.Fatalf("parse: %v", err)
	}

	// All ones and all zeros.
	var ones RecoveryKey
	for i := range ones {
		ones[i] = 0xff
	}
	if flat := strings.ReplaceAll(ones.String(), "-", ""); !strings.HasPrefix(flat, "R1"+strings.Repeat("Z", 51)+"G") {
		t.Errorf("all ones: %s", flat) // the last symbol is one data bit and four zero padding bits
	}
	if flat := strings.ReplaceAll(RecoveryKey{}.String(), "-", ""); flat != "R1"+strings.Repeat("0", 53) {
		t.Errorf("all zeros: %s", flat)
	}
}

func TestParseRecoveryKeyLenient(t *testing.T) {
	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	text := rk.String()
	for _, v := range []string{
		text,
		strings.ToLower(text),
		strings.ReplaceAll(text, "-", ""),
		"-" + strings.ReplaceAll(text, "-", "--") + "-",
		strings.ReplaceAll(strings.ReplaceAll(text, "1", "l"), "0", "o"),
		strings.ReplaceAll(text, "1", "I"),
	} {
		back, err := ParseRecoveryKey(v)
		if err != nil || back != rk {
			t.Errorf("%q: %v", v, err)
		}
	}
}

func TestParseRecoveryKeyRejects(t *testing.T) {
	var rk RecoveryKey
	copy(rk[:], fixedBytes("rk reject", 32))
	flat := strings.ReplaceAll(rk.String(), "-", "")
	flip := func(i int) string {
		b := []byte(flat)
		if b[i] == '0' {
			b[i] = '1'
		} else {
			b[i] = '0'
		}
		return string(b)
	}
	// Nonzero padding: the last data symbol gets a low bit set, and the
	// check symbol is recomputed so that only the padding is wrong.
	vals := make([]int, 52)
	for i := range 52 {
		vals[i] = crockfordValue(flat[2+i])
	}
	vals[51] |= 1
	padded := "R1"
	for _, v := range vals {
		padded += string(crockfordAlphabet[v])
	}
	padded += string(checkSymbol(vals))
	for name, in := range map[string]string{
		"one symbol changed":   flip(10),
		"check symbol changed": flip(len(flat) - 1),
		"nonzero padding bits": padded,
		"too short":            flat[:len(flat)-1],
		"too long":             flat + "0",
		"Secret Key prefix":    "H1" + flat[2:],
		"bad prefix digit":     "R2" + flat[2:],
		"bad character":        flat[:12] + "#" + flat[13:],
		"U in the data":        flat[:12] + "U" + flat[13:],
		"empty":                "",
		"spaces":               strings.ReplaceAll(rk.String(), "-", " "),
	} {
		if _, err := ParseRecoveryKey(in); !errors.Is(err, ErrBadRecoveryKey) {
			t.Errorf("%s: %q: %v", name, in, err)
		}
	}
	// A Secret Key is not a Recovery Key and vice versa.
	sk, _ := NewSecretKey()
	if _, err := ParseRecoveryKey(sk.String()); err == nil {
		t.Error("Secret Key parsed as a Recovery Key")
	}
	if _, err := ParseSecretKey(rk.String()); err == nil {
		t.Error("Recovery Key parsed as a Secret Key")
	}
}
