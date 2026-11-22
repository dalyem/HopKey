package canonjson

import (
	"errors"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// maxDepth bounds nesting so hostile input cannot exhaust the stack.
const maxDepth = 64

// maxSafeInteger is 2^53-1, the largest integer every IEEE double
// represents exactly along with all smaller ones.
const maxSafeInteger = 1<<53 - 1

type kind uint8

const (
	kindNull kind = iota
	kindBool
	kindNumber
	kindString
	kindArray
	kindObject
)

func (k kind) String() string {
	switch k {
	case kindNull:
		return "null"
	case kindBool:
		return "boolean"
	case kindNumber:
		return "number"
	case kindString:
		return "string"
	case kindArray:
		return "array"
	default:
		return "object"
	}
}

// node is one parsed JSON value. Objects keep their members in input order;
// duplicates are rejected while parsing.
type node struct {
	kind    kind
	b       bool
	num     int64
	str     string
	elems   []*node
	members []member
}

type member struct {
	name  string
	value *node
}

// parse reads exactly one JSON value from data. It rejects duplicate
// members at any depth, numbers that are not safe integers, invalid UTF-8,
// lone surrogates and trailing data.
func parse(data []byte) (*node, error) {
	p := &parser{data: data}
	p.skipSpace()
	n, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos != len(p.data) {
		return nil, p.errorf("trailing data")
	}
	return n, nil
}

type parser struct {
	data []byte
	pos  int
}

func (p *parser) errorf(format string, args ...any) error {
	return fmt.Errorf("canonjson: offset %d: %s", p.pos, fmt.Sprintf(format, args...))
}

func (p *parser) skipSpace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (*node, error) {
	if depth > maxDepth {
		return nil, p.errorf("nesting deeper than %d", maxDepth)
	}
	if p.pos >= len(p.data) {
		return nil, p.errorf("unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		s, err := p.string()
		if err != nil {
			return nil, err
		}
		return &node{kind: kindString, str: s}, nil
	case c == '-' || '0' <= c && c <= '9':
		return p.number()
	case p.literal("true"):
		return &node{kind: kindBool, b: true}, nil
	case p.literal("false"):
		return &node{kind: kindBool}, nil
	case p.literal("null"):
		return &node{kind: kindNull}, nil
	default:
		return nil, p.errorf("unexpected character %q", c)
	}
}

func (p *parser) literal(lit string) bool {
	if len(p.data)-p.pos >= len(lit) && string(p.data[p.pos:p.pos+len(lit)]) == lit {
		p.pos += len(lit)
		return true
	}
	return false
}

func (p *parser) object(depth int) (*node, error) {
	p.pos++ // '{'
	n := &node{kind: kindObject}
	seen := map[string]bool{}
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return n, nil
	}
	for {
		p.skipSpace()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, p.errorf("expected member name")
		}
		name, err := p.string()
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, p.errorf("duplicate member %q", name)
		}
		seen[name] = true
		p.skipSpace()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, p.errorf("expected ':'")
		}
		p.pos++
		p.skipSpace()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		n.members = append(n.members, member{name: name, value: v})
		p.skipSpace()
		if p.pos >= len(p.data) {
			return nil, p.errorf("unexpected end of object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return n, nil
		default:
			return nil, p.errorf("expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (*node, error) {
	p.pos++ // '['
	n := &node{kind: kindArray}
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return n, nil
	}
	for {
		p.skipSpace()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		n.elems = append(n.elems, v)
		p.skipSpace()
		if p.pos >= len(p.data) {
			return nil, p.errorf("unexpected end of array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return n, nil
		default:
			return nil, p.errorf("expected ',' or ']'")
		}
	}
}

// number accepts only the integer grammar -?(0|[1-9][0-9]*) with a value in
// the safe range. Fractions, exponents and -0 are floats for our purposes.
func (p *parser) number() (*node, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	digits := p.pos
	for p.pos < len(p.data) && '0' <= p.data[p.pos] && p.data[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == digits {
		return nil, p.errorf("invalid number")
	}
	if p.pos < len(p.data) {
		switch p.data[p.pos] {
		case '.', 'e', 'E':
			return nil, p.errorf("floating-point numbers are not allowed")
		}
	}
	text := string(p.data[start:p.pos])
	if p.pos-digits > 1 && p.data[digits] == '0' {
		return nil, p.errorf("number %s has a leading zero", text)
	}
	if text == "-0" {
		return nil, p.errorf("-0 is not allowed")
	}
	v, err := strconv.ParseInt(text, 10, 64)
	if err != nil || v > maxSafeInteger || v < -maxSafeInteger {
		return nil, p.errorf("number %s is outside the safe integer range", text)
	}
	return &node{kind: kindNumber, num: v}, nil
}

var errLoneSurrogate = errors.New("lone surrogate")

// string reads a JSON string starting at the opening quote.
func (p *parser) string() (string, error) {
	p.pos++ // '"'
	var out []byte
	for {
		if p.pos >= len(p.data) {
			return "", p.errorf("unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return string(out), nil
		case c == '\\':
			r, err := p.escape()
			if err != nil {
				return "", err
			}
			out = utf8.AppendRune(out, r)
		case c < 0x20:
			return "", p.errorf("unescaped control character in string")
		case c < utf8.RuneSelf:
			out = append(out, c)
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", p.errorf("invalid UTF-8 in string")
			}
			out = append(out, p.data[p.pos:p.pos+size]...)
			p.pos += size
		}
	}
}

func (p *parser) escape() (rune, error) {
	p.pos++ // '\\'
	if p.pos >= len(p.data) {
		return 0, p.errorf("unterminated escape")
	}
	c := p.data[p.pos]
	p.pos++
	switch c {
	case '"', '\\', '/':
		return rune(c), nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
		r, err := p.hex4()
		if err != nil {
			return 0, err
		}
		if utf16.IsSurrogate(r) {
			if r >= 0xdc00 || len(p.data)-p.pos < 2 || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
				return 0, p.errorf("%v", errLoneSurrogate)
			}
			p.pos += 2
			lo, err := p.hex4()
			if err != nil {
				return 0, err
			}
			combined := utf16.DecodeRune(r, lo)
			if combined == utf8.RuneError {
				return 0, p.errorf("%v", errLoneSurrogate)
			}
			return combined, nil
		}
		return r, nil
	default:
		return 0, p.errorf("invalid escape \\%c", c)
	}
}

func (p *parser) hex4() (rune, error) {
	if len(p.data)-p.pos < 4 {
		return 0, p.errorf("short \\u escape")
	}
	var r rune
	for _, c := range p.data[p.pos : p.pos+4] {
		r <<= 4
		switch {
		case '0' <= c && c <= '9':
			r |= rune(c - '0')
		case 'a' <= c && c <= 'f':
			r |= rune(c-'a') + 10
		case 'A' <= c && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, p.errorf("invalid \\u escape")
		}
	}
	p.pos += 4
	return r, nil
}
