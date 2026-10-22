package canonjson

import (
	"strings"
	"testing"
)

// RFC 8785 §3.2.2 example with the "numbers" member removed: the floats in
// it are outside the subset this package supports.
func TestRFC8785StringsAndLiterals(t *testing.T) {
	in := `{
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`
	want := `{"literals":[null,true,false],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// The full RFC 8785 §3.2.2 example carries floats, which we reject.
func TestRFC8785NumbersExampleRejected(t *testing.T) {
	in := `{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001]}`
	if _, err := Canonicalize([]byte(in)); err == nil {
		t.Fatal("floats accepted")
	}
}

// RFC 8785 §3.2.3 sorting example: keys order by UTF-16 code units, so the
// emoji (a surrogate pair, 0xd83d...) sorts before U+FB33.
func TestRFC8785Sorting(t *testing.T) {
	in := `{
  "\u20ac": "Euro Sign",
  "\r": "Carriage Return",
  "\ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "\ud83d\ude00": "Emoji: Grinning Face",
  "\u0080": "Control",
  "\u00f6": "Latin Small Letter O With Diaeresis"
}`
	want := "{" +
		"\"\\r\":\"Carriage Return\"," +
		"\"1\":\"One\"," +
		"\"\u0080\":\"Control\"," +
		"\"\u00f6\":\"Latin Small Letter O With Diaeresis\"," +
		"\"\u20ac\":\"Euro Sign\"," +
		"\"\U0001F600\":\"Emoji: Grinning Face\"," +
		"\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"" +
		"}"
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

// RFC 8785 Appendix B rows that are safe integers.
func TestRFC8785IntegerSerialization(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"0", "0"},
		{"1", "1"},
		{"-1", "-1"},
		{"9007199254740991", "9007199254740991"},
		{"-9007199254740991", "-9007199254740991"},
		{"295147905179352830", ""}, // beyond 2^53: rejected
		{"9007199254740992", ""},   // 2^53 is exact in a double but not safe
		{"1e3", ""},
		{"1.0", ""},
		{"-0", ""},
		{"01", ""},
	} {
		got, err := Canonicalize([]byte(tc.in))
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s: accepted as %s", tc.in, got)
			}
			continue
		}
		if err != nil || string(got) != tc.want {
			t.Errorf("%s: got %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestStringEscaping(t *testing.T) {
	// Every C0 control, plus DEL and U+2028, which JCS leaves raw.
	var b strings.Builder
	for c := 0; c < 0x20; c++ {
		b.WriteByte(byte(c))
	}
	b.WriteString("\x7f\u2028\"\\/")
	got, err := Marshal(b.String())
	if err != nil {
		t.Fatal(err)
	}
	want := `"\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\b\t\n\u000b\f\r\u000e\u000f` +
		`\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f` +
		"\x7f\u2028" + `\"\\/"`
	if string(got) != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	if _, err := Marshal("\xff"); err == nil {
		t.Fatal("invalid UTF-8 encoded")
	}
}

type inner struct {
	A string `json:"a"`
}

type embedded struct {
	V int `json:"v"`
}

type sample struct {
	embedded
	Name    string            `json:"name"`
	Count   uint32            `json:"count"`
	Big     uint64            `json:"big,string"`
	Data    []byte            `json:"data"`
	List    []string          `json:"list"`
	Map     map[string]string `json:"map"`
	Opt     *inner            `json:"opt"`
	Flag    bool              `json:"flag"`
	Nested  inner             `json:"nested"`
	Payload Raw               `json:"payload"`
	skipped int
}

func TestRoundTrip(t *testing.T) {
	s := sample{
		embedded: embedded{V: 1},
		Name:     "x",
		Count:    4294967295,
		Big:      18446744073709551615,
		Data:     []byte{0xfb, 0xff},
		Nested:   inner{A: "é"},
		Payload:  Raw(`{ "b" : 1, "a" : [true] }`),
	}
	got, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"big":"18446744073709551615","count":4294967295,"data":"-_8","flag":false,"list":[],"map":{},"name":"x","nested":{"a":"é"},"opt":null,"payload":{"a":[true],"b":1},"v":1}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	var back sample
	if err := Unmarshal(got, &back); err != nil {
		t.Fatal(err)
	}
	again, err := Marshal(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != want {
		t.Fatalf("round trip changed: %s", again)
	}
}

const validSample = `{"big":"1","count":1,"data":"","flag":false,"list":[],"map":{},"name":"x","nested":{"a":""},"opt":null,"payload":null,"v":1}`

func TestStrictDecoding(t *testing.T) {
	var ok sample
	if err := Unmarshal([]byte(validSample), &ok); err != nil {
		t.Fatalf("valid sample rejected: %v", err)
	}
	cases := map[string]string{
		"unknown member":          strings.Replace(validSample, `"v":1`, `"v":1,"extra":1`, 1),
		"duplicate member":        strings.Replace(validSample, `"v":1`, `"v":1,"v":1`, 1),
		"nested duplicate":        strings.Replace(validSample, `{"a":""}`, `{"a":"","a":""}`, 1),
		"duplicate in map":        strings.Replace(validSample, `"map":{}`, `"map":{"k":"1","k":"2"}`, 1),
		"duplicate in Raw":        strings.Replace(validSample, `"payload":null`, `"payload":{"k":1,"k":1}`, 1),
		"missing member":          strings.Replace(validSample, `"flag":false,`, ``, 1),
		"missing nested":          strings.Replace(validSample, `{"a":""}`, `{}`, 1),
		"case-folded name":        strings.Replace(validSample, `"name"`, `"Name"`, 1),
		"trailing data":           validSample + `{}`,
		"trailing garbage":        validSample + ` x`,
		"null for string":         strings.Replace(validSample, `"name":"x"`, `"name":null`, 1),
		"null for slice":          strings.Replace(validSample, `"list":[]`, `"list":null`, 1),
		"null for map":            strings.Replace(validSample, `"map":{}`, `"map":null`, 1),
		"number as u64s":          strings.Replace(validSample, `"big":"1"`, `"big":1`, 1),
		"leading zero u64s":       strings.Replace(validSample, `"big":"1"`, `"big":"01"`, 1),
		"signed u64s":             strings.Replace(validSample, `"big":"1"`, `"big":"+1"`, 1),
		"u64s overflow":           strings.Replace(validSample, `"big":"1"`, `"big":"18446744073709551616"`, 1),
		"u32 overflow":            strings.Replace(validSample, `"count":1`, `"count":4294967296`, 1),
		"negative u32":            strings.Replace(validSample, `"count":1`, `"count":-1`, 1),
		"float":                   strings.Replace(validSample, `"count":1`, `"count":1.0`, 1),
		"exponent":                strings.Replace(validSample, `"count":1`, `"count":1e0`, 1),
		"string for number":       strings.Replace(validSample, `"count":1`, `"count":"1"`, 1),
		"bool for string":         strings.Replace(validSample, `"name":"x"`, `"name":true`, 1),
		"padded base64":           strings.Replace(validSample, `"data":""`, `"data":"-_8="`, 1),
		"std base64":              strings.Replace(validSample, `"data":""`, `"data":"+/8"`, 1),
		"non-zero trailing bits":  strings.Replace(validSample, `"data":""`, `"data":"-_9"`, 1),
		"lone high surrogate":     strings.Replace(validSample, `"name":"x"`, `"name":"\ud800"`, 1),
		"lone low surrogate":      strings.Replace(validSample, `"name":"x"`, `"name":"\udc00"`, 1),
		"raw control in string":   strings.Replace(validSample, `"name":"x"`, "\"name\":\"\x01\"", 1),
		"invalid UTF-8":           strings.Replace(validSample, `"name":"x"`, "\"name\":\"\xff\"", 1),
		"bad escape":              strings.Replace(validSample, `"name":"x"`, `"name":"\x"`, 1),
		"single quotes":           strings.Replace(validSample, `"name":"x"`, `"name":'x'`, 1),
		"trailing comma":          strings.Replace(validSample, `"v":1}`, `"v":1,}`, 1),
		"array for object":        strings.Replace(validSample, `"nested":{"a":""}`, `"nested":[]`, 1),
		"empty input":             ``,
		"top-level not an object": `[]`,
	}
	for name, in := range cases {
		var s sample
		if err := Unmarshal([]byte(in), &s); err == nil {
			t.Errorf("%s: accepted %s", name, in)
		}
	}
}

// encoding/base64 skips CR and LF even in strict mode. A b64 value must
// hold only base64url characters, so escaped line breaks and other
// whitespace inside the string are rejected.
func TestBase64RejectsLineBreaks(t *testing.T) {
	var ok sample
	if err := Unmarshal([]byte(strings.Replace(validSample, `"data":""`, `"data":"-_8"`, 1)), &ok); err != nil || string(ok.Data) != "\xfb\xff" {
		t.Fatalf("clean value: %x, %v", ok.Data, err)
	}
	for name, val := range map[string]string{
		"LF":       `-_\n8`,
		"CR":       `-_\r8`,
		"CRLF":     `-_\r\n8`,
		"trailing": `-_8\n`,
		"leading":  `\r-_8`,
		"tab":      `-_\t8`,
		"space":    `-_ 8`,
	} {
		in := strings.Replace(validSample, `"data":""`, `"data":"`+val+`"`, 1)
		var s sample
		if err := Unmarshal([]byte(in), &s); err == nil {
			t.Errorf("%s: accepted %s as %x", name, in, s.Data)
		}
	}
}

func TestDepthLimit(t *testing.T) {
	deep := strings.Repeat("[", maxDepth+2) + strings.Repeat("]", maxDepth+2)
	if _, err := Canonicalize([]byte(deep)); err == nil {
		t.Fatal("excessive nesting accepted")
	}
}

func TestMarshalRefusals(t *testing.T) {
	if _, err := Marshal(1.5); err == nil {
		t.Error("float encoded")
	}
	if _, err := Marshal(uint64(1 << 53)); err == nil {
		t.Error("unsafe integer encoded without ,string")
	}
	type omit struct {
		A string `json:"a,omitempty"`
	}
	if _, err := Marshal(omit{}); err == nil {
		t.Error("omitempty accepted")
	}
	type clash struct {
		A string
		B string `json:"A"`
	}
	if _, err := Marshal(clash{}); err == nil {
		t.Error("two members with one name accepted")
	}
}

func TestUnmarshalNeedsPointer(t *testing.T) {
	var s sample
	if err := Unmarshal([]byte(validSample), s); err == nil {
		t.Fatal("non-pointer accepted")
	}
}
