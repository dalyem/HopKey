// Package canonjson implements the JSON rules of crypto spec §3
// (https://plan.23d.dev/p/xuu5z9q2): RFC 8785 (JCS) output and a strict
// decoder for closed schemas.
//
// Only the value kinds HopKey's schemas use are supported: objects, arrays,
// strings, booleans, null and integers in the IEEE-double safe range
// (|n| ≤ 2^53-1). Floats are rejected in both directions. u64 values are
// decimal strings, written with the `,string` tag option on an integer
// field.
//
// Go values map to JSON as follows:
//
//   - struct: an object with one member per exported field, named by its
//     json tag. Anonymous struct fields without a name are flattened. Every
//     member is required; omitempty and omitzero are refused. The one
//     exception is a string field tagged ",optional": it is written only
//     when it is not "", and an absent member decodes as "". A member that
//     is present must not be "", so that a value has one encoding.
//   - pointer: null when nil (a "|null" field in the spec); null is accepted
//     only for pointer fields.
//   - slice and array: an array; a nil slice encodes as []. []byte is the
//     exception: it is a b64 string (base64url without padding, §3).
//   - map: an object; keys are strings or implement encoding.TextMarshaler.
//     A nil map encodes as {}.
//   - encoding.TextMarshaler / TextUnmarshaler: a string.
//   - Raw: an already-encoded JSON value, re-canonicalized on output.
//
// The decoder rejects unknown members, duplicate members at any depth,
// missing members, wrong types and trailing data.
package canonjson

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
)

// b64 is the spec's binary encoding: base64url without padding, with the
// unused trailing bits required to be zero.
var b64 = base64.RawURLEncoding.Strict()

// decodeB64 decodes a b64 value. encoding/base64 skips CR and LF even in
// strict mode, so every character is first checked against the base64url
// alphabet; anything else, including line breaks, is rejected.
func decodeB64(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return nil, fmt.Errorf("character %q at offset %d is not in the base64url alphabet", c, i)
		}
	}
	return b64.DecodeString(s)
}

// Raw holds one JSON value in canonical form. Marshal re-canonicalizes it;
// Unmarshal stores the canonical form of whatever value it finds there. It
// is for members whose schema depends on context, such as an item plaintext
// inside a grant bundle.
type Raw []byte

// Marshal returns the RFC 8785 encoding of v.
func Marshal(v any) ([]byte, error) {
	var e encoder
	if err := e.value(reflect.ValueOf(v), false); err != nil {
		return nil, err
	}
	return e.buf.Bytes(), nil
}

// Canonicalize parses data strictly and returns its RFC 8785 encoding.
func Canonicalize(data []byte) ([]byte, error) {
	n, err := parse(data)
	if err != nil {
		return nil, err
	}
	var e encoder
	e.node(n)
	return e.buf.Bytes(), nil
}

// Unmarshal decodes data into v, which must be a non-nil pointer, under the
// closed-schema rules described in the package comment.
func Unmarshal(data []byte, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("canonjson: Unmarshal needs a non-nil pointer, got %T", v)
	}
	n, err := parse(data)
	if err != nil {
		return err
	}
	return decode(n, rv.Elem(), "$", false)
}

var (
	rawType             = reflect.TypeFor[Raw]()
	textMarshalerType   = reflect.TypeFor[encoding.TextMarshaler]()
	textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()
)

// field is one JSON member of a struct type.
type field struct {
	name     string
	index    []int
	asString bool // the ",string" option: an integer written as a decimal string
	optional bool // the ",optional" option: a string member absent when ""
}

var fieldCache sync.Map // reflect.Type -> fieldsResult

type fieldsResult struct {
	fields []field
	err    error
}

func fieldsOf(t reflect.Type) ([]field, error) {
	if c, ok := fieldCache.Load(t); ok {
		r := c.(fieldsResult)
		return r.fields, r.err
	}
	var fields []field
	err := collectFields(t, nil, &fields)
	if err == nil {
		seen := map[string]bool{}
		for _, f := range fields {
			if seen[f.name] {
				err = fmt.Errorf("canonjson: %v has two members named %q", t, f.name)
				break
			}
			seen[f.name] = true
		}
	}
	fieldCache.Store(t, fieldsResult{fields, err})
	return fields, err
}

func collectFields(t reflect.Type, prefix []int, out *[]field) error {
	for i := range t.NumField() {
		sf := t.Field(i)
		tag, hasTag := sf.Tag.Lookup("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		index := append(slices.Clone(prefix), i)
		if sf.Anonymous && name == "" {
			ft := sf.Type
			if ft.Kind() != reflect.Struct {
				return fmt.Errorf("canonjson: embedded field %s in %v must be a struct", sf.Name, t)
			}
			if err := collectFields(ft, index, out); err != nil {
				return err
			}
			continue
		}
		if !sf.IsExported() {
			continue
		}
		if !hasTag || name == "" {
			name = sf.Name
		}
		f := field{name: name, index: index}
		for opt := range strings.SplitSeq(opts, ",") {
			switch opt {
			case "":
			case "string":
				switch sf.Type.Kind() {
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
					reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
					f.asString = true
				default:
					return fmt.Errorf("canonjson: ,string on non-integer field %s in %v", sf.Name, t)
				}
			case "optional":
				if sf.Type.Kind() != reflect.String {
					return fmt.Errorf("canonjson: ,optional on non-string field %s in %v", sf.Name, t)
				}
				f.optional = true
			default:
				return fmt.Errorf("canonjson: unsupported tag option %q on %s in %v (every member is required)", opt, sf.Name, t)
			}
		}
		*out = append(*out, f)
	}
	return nil
}

// --- encoding ---

type encoder struct {
	buf bytes.Buffer
}

func (e *encoder) value(v reflect.Value, asString bool) error {
	if !v.IsValid() {
		e.buf.WriteString("null")
		return nil
	}
	t := v.Type()
	if t == rawType {
		c, err := Canonicalize(v.Bytes())
		if err != nil {
			return err
		}
		e.buf.Write(c)
		return nil
	}
	if t.Kind() != reflect.Pointer && t.Kind() != reflect.Interface && t.Implements(textMarshalerType) {
		text, err := v.Interface().(encoding.TextMarshaler).MarshalText()
		if err != nil {
			return fmt.Errorf("canonjson: %v: %w", t, err)
		}
		return e.string(string(text))
	}
	switch t.Kind() {
	case reflect.Bool:
		if v.Bool() {
			e.buf.WriteString("true")
		} else {
			e.buf.WriteString("false")
		}
	case reflect.String:
		return e.string(v.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		if asString {
			return e.string(strconv.FormatInt(n, 10))
		}
		if n > maxSafeInteger || n < -maxSafeInteger {
			return fmt.Errorf("canonjson: integer %d outside the safe range", n)
		}
		e.buf.WriteString(strconv.FormatInt(n, 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n := v.Uint()
		if asString {
			return e.string(strconv.FormatUint(n, 10))
		}
		if n > maxSafeInteger {
			return fmt.Errorf("canonjson: integer %d outside the safe range", n)
		}
		e.buf.WriteString(strconv.FormatUint(n, 10))
	case reflect.Float32, reflect.Float64:
		return fmt.Errorf("canonjson: floating-point values are not allowed")
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			e.buf.WriteString("null")
			return nil
		}
		return e.value(v.Elem(), asString)
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 && !t.Elem().Implements(textMarshalerType) {
			return e.string(b64.EncodeToString(v.Bytes()))
		}
		return e.array(v)
	case reflect.Array:
		return e.array(v)
	case reflect.Map:
		return e.mapValue(v)
	case reflect.Struct:
		return e.structValue(v)
	default:
		return fmt.Errorf("canonjson: unsupported type %v", t)
	}
	return nil
}

func (e *encoder) array(v reflect.Value) error {
	e.buf.WriteByte('[')
	for i := range v.Len() {
		if i > 0 {
			e.buf.WriteByte(',')
		}
		if err := e.value(v.Index(i), false); err != nil {
			return err
		}
	}
	e.buf.WriteByte(']')
	return nil
}

type encMember struct {
	key   string
	utf16 []uint16
	value reflect.Value
	asStr bool
}

func (e *encoder) members(ms []encMember) error {
	slices.SortFunc(ms, func(a, b encMember) int { return slices.Compare(a.utf16, b.utf16) })
	e.buf.WriteByte('{')
	for i, m := range ms {
		if i > 0 {
			if slices.Equal(ms[i-1].utf16, m.utf16) {
				return fmt.Errorf("canonjson: duplicate member %q", m.key)
			}
			e.buf.WriteByte(',')
		}
		if err := e.string(m.key); err != nil {
			return err
		}
		e.buf.WriteByte(':')
		if err := e.value(m.value, m.asStr); err != nil {
			return err
		}
	}
	e.buf.WriteByte('}')
	return nil
}

func (e *encoder) mapValue(v reflect.Value) error {
	ms := make([]encMember, 0, v.Len())
	iter := v.MapRange()
	for iter.Next() {
		k, err := mapKeyString(iter.Key())
		if err != nil {
			return err
		}
		if !utf8.ValidString(k) {
			return fmt.Errorf("canonjson: invalid UTF-8 in member name")
		}
		ms = append(ms, encMember{key: k, utf16: utf16.Encode([]rune(k)), value: iter.Value()})
	}
	return e.members(ms)
}

func mapKeyString(k reflect.Value) (string, error) {
	if k.Type().Implements(textMarshalerType) {
		text, err := k.Interface().(encoding.TextMarshaler).MarshalText()
		return string(text), err
	}
	if k.Kind() == reflect.String {
		return k.String(), nil
	}
	return "", fmt.Errorf("canonjson: unsupported map key type %v", k.Type())
}

func (e *encoder) structValue(v reflect.Value) error {
	fields, err := fieldsOf(v.Type())
	if err != nil {
		return err
	}
	ms := make([]encMember, 0, len(fields))
	for _, f := range fields {
		fv := v.FieldByIndex(f.index)
		if f.optional && fv.String() == "" {
			continue
		}
		ms = append(ms, encMember{key: f.name, utf16: utf16.Encode([]rune(f.name)), value: fv, asStr: f.asString})
	}
	return e.members(ms)
}

// string writes s with exactly the escaping RFC 8785 §3.2.2.2 requires:
// '"' and '\\' escaped, the five short control escapes, \u00xx (lowercase)
// for the other C0 controls, and everything else as raw UTF-8.
func (e *encoder) string(s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("canonjson: invalid UTF-8 in string")
	}
	e.writeString(s)
	return nil
}

const hexDigits = "0123456789abcdef"

func (e *encoder) writeString(s string) {
	e.buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			e.buf.WriteString(`\"`)
		case '\\':
			e.buf.WriteString(`\\`)
		case '\b':
			e.buf.WriteString(`\b`)
		case '\f':
			e.buf.WriteString(`\f`)
		case '\n':
			e.buf.WriteString(`\n`)
		case '\r':
			e.buf.WriteString(`\r`)
		case '\t':
			e.buf.WriteString(`\t`)
		default:
			if c < 0x20 {
				e.buf.WriteString(`\u00`)
				e.buf.WriteByte(hexDigits[c>>4])
				e.buf.WriteByte(hexDigits[c&0xf])
			} else {
				e.buf.WriteByte(c)
			}
		}
	}
	e.buf.WriteByte('"')
}

// node writes a parsed tree canonically. Parsed strings are already valid
// UTF-8 and numbers already in range.
func (e *encoder) node(n *node) {
	switch n.kind {
	case kindNull:
		e.buf.WriteString("null")
	case kindBool:
		if n.b {
			e.buf.WriteString("true")
		} else {
			e.buf.WriteString("false")
		}
	case kindNumber:
		e.buf.WriteString(strconv.FormatInt(n.num, 10))
	case kindString:
		e.writeString(n.str)
	case kindArray:
		e.buf.WriteByte('[')
		for i, c := range n.elems {
			if i > 0 {
				e.buf.WriteByte(',')
			}
			e.node(c)
		}
		e.buf.WriteByte(']')
	case kindObject:
		ms := slices.Clone(n.members)
		keys := make(map[string][]uint16, len(ms))
		for _, m := range ms {
			keys[m.name] = utf16.Encode([]rune(m.name))
		}
		slices.SortFunc(ms, func(a, b member) int { return slices.Compare(keys[a.name], keys[b.name]) })
		e.buf.WriteByte('{')
		for i, m := range ms {
			if i > 0 {
				e.buf.WriteByte(',')
			}
			e.writeString(m.name)
			e.buf.WriteByte(':')
			e.node(m.value)
		}
		e.buf.WriteByte('}')
	}
}

// --- decoding ---

func typeErr(path string, want string, n *node) error {
	return fmt.Errorf("canonjson: %s: want %s, got %v", path, want, n.kind)
}

func decode(n *node, v reflect.Value, path string, asString bool) error {
	t := v.Type()
	if t == rawType {
		var e encoder
		e.node(n)
		v.SetBytes(e.buf.Bytes())
		return nil
	}
	if t.Kind() == reflect.Pointer {
		if n.kind == kindNull {
			v.SetZero()
			return nil
		}
		p := reflect.New(t.Elem())
		if err := decode(n, p.Elem(), path, asString); err != nil {
			return err
		}
		v.Set(p)
		return nil
	}
	if n.kind == kindNull {
		return fmt.Errorf("canonjson: %s: null is not allowed here", path)
	}
	if reflect.PointerTo(t).Implements(textUnmarshalerType) {
		if n.kind != kindString {
			return typeErr(path, "string", n)
		}
		if err := v.Addr().Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte(n.str)); err != nil {
			return fmt.Errorf("canonjson: %s: %w", path, err)
		}
		return nil
	}
	switch t.Kind() {
	case reflect.Bool:
		if n.kind != kindBool {
			return typeErr(path, "boolean", n)
		}
		v.SetBool(n.b)
	case reflect.String:
		if n.kind != kindString {
			return typeErr(path, "string", n)
		}
		v.SetString(n.str)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		x, err := intValue(n, path, asString)
		if err != nil {
			return err
		}
		if v.OverflowInt(x) {
			return fmt.Errorf("canonjson: %s: %d overflows %v", path, x, t)
		}
		v.SetInt(x)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		x, err := uintValue(n, path, asString)
		if err != nil {
			return err
		}
		if v.OverflowUint(x) {
			return fmt.Errorf("canonjson: %s: %d overflows %v", path, x, t)
		}
		v.SetUint(x)
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 && !reflect.PointerTo(t.Elem()).Implements(textUnmarshalerType) {
			if n.kind != kindString {
				return typeErr(path, "b64 string", n)
			}
			b, err := decodeB64(n.str)
			if err != nil {
				return fmt.Errorf("canonjson: %s: invalid base64url: %w", path, err)
			}
			v.SetBytes(b)
			return nil
		}
		if n.kind != kindArray {
			return typeErr(path, "array", n)
		}
		s := reflect.MakeSlice(t, len(n.elems), len(n.elems))
		for i, c := range n.elems {
			if err := decode(c, s.Index(i), fmt.Sprintf("%s[%d]", path, i), false); err != nil {
				return err
			}
		}
		v.Set(s)
	case reflect.Array:
		if n.kind != kindArray {
			return typeErr(path, "array", n)
		}
		if len(n.elems) != t.Len() {
			return fmt.Errorf("canonjson: %s: want %d elements, got %d", path, t.Len(), len(n.elems))
		}
		for i, c := range n.elems {
			if err := decode(c, v.Index(i), fmt.Sprintf("%s[%d]", path, i), false); err != nil {
				return err
			}
		}
	case reflect.Map:
		if n.kind != kindObject {
			return typeErr(path, "object", n)
		}
		m := reflect.MakeMapWithSize(t, len(n.members))
		for _, mem := range n.members {
			k := reflect.New(t.Key()).Elem()
			switch {
			case reflect.PointerTo(t.Key()).Implements(textUnmarshalerType):
				if err := k.Addr().Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte(mem.name)); err != nil {
					return fmt.Errorf("canonjson: %s: key %q: %w", path, mem.name, err)
				}
			case t.Key().Kind() == reflect.String:
				k.SetString(mem.name)
			default:
				return fmt.Errorf("canonjson: unsupported map key type %v", t.Key())
			}
			if m.MapIndex(k).IsValid() {
				return fmt.Errorf("canonjson: %s: key %q decodes to a duplicate", path, mem.name)
			}
			ev := reflect.New(t.Elem()).Elem()
			if err := decode(mem.value, ev, path+"."+mem.name, false); err != nil {
				return err
			}
			m.SetMapIndex(k, ev)
		}
		v.Set(m)
	case reflect.Struct:
		if n.kind != kindObject {
			return typeErr(path, "object", n)
		}
		fields, err := fieldsOf(t)
		if err != nil {
			return err
		}
		byName := make(map[string]*node, len(n.members))
		for _, mem := range n.members {
			byName[mem.name] = mem.value
		}
		for _, f := range fields {
			c, ok := byName[f.name]
			if !ok && f.optional {
				v.FieldByIndex(f.index).SetString("")
				continue
			}
			if !ok {
				return fmt.Errorf("canonjson: %s: missing member %q", path, f.name)
			}
			delete(byName, f.name)
			if err := decode(c, v.FieldByIndex(f.index), path+"."+f.name, f.asString); err != nil {
				return err
			}
			if f.optional && v.FieldByIndex(f.index).String() == "" {
				return fmt.Errorf("canonjson: %s: optional member %q is present but empty", path, f.name)
			}
		}
		for _, mem := range n.members {
			if _, unknown := byName[mem.name]; unknown {
				return fmt.Errorf("canonjson: %s: unknown member %q", path, mem.name)
			}
		}
	default:
		return fmt.Errorf("canonjson: %s: unsupported type %v", path, t)
	}
	return nil
}

// decimalString checks the u64s grammar: no sign, no leading zeros except
// "0" itself.
func decimalString(n *node, path string) (string, error) {
	if n.kind != kindString {
		return "", typeErr(path, "decimal string", n)
	}
	s := n.str
	if s == "" || len(s) > 20 || (len(s) > 1 && s[0] == '0') {
		return "", fmt.Errorf("canonjson: %s: %q is not a canonical decimal", path, s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return "", fmt.Errorf("canonjson: %s: %q is not a canonical decimal", path, s)
		}
	}
	return s, nil
}

func uintValue(n *node, path string, asString bool) (uint64, error) {
	if asString {
		s, err := decimalString(n, path)
		if err != nil {
			return 0, err
		}
		x, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("canonjson: %s: %q out of range", path, s)
		}
		return x, nil
	}
	if n.kind != kindNumber {
		return 0, typeErr(path, "integer", n)
	}
	if n.num < 0 {
		return 0, fmt.Errorf("canonjson: %s: negative value %d", path, n.num)
	}
	return uint64(n.num), nil
}

func intValue(n *node, path string, asString bool) (int64, error) {
	if asString {
		s, err := decimalString(n, path)
		if err != nil {
			return 0, err
		}
		x, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("canonjson: %s: %q out of range", path, s)
		}
		return x, nil
	}
	if n.kind != kindNumber {
		return 0, typeErr(path, "integer", n)
	}
	return n.num, nil
}
