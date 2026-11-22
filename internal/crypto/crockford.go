package crypto

// Crockford base32 symbols, value order (§8.1, §12).
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// crockfordCheckSymbols extends the alphabet with the five check-only
// symbols for values 32 to 36 (Crockford's mod-37 check symbol).
const crockfordCheckSymbols = crockfordAlphabet + "*~$=U"

// crockfordValue maps one input character to its value, applying the
// decoding rules: lowercase accepted, I and L read as 1, O as 0. It returns
// -1 for anything else, including U (a check symbol only) and hyphens.
func crockfordValue(c byte) int {
	if 'a' <= c && c <= 'z' {
		c -= 'a' - 'A'
	}
	switch c {
	case 'I', 'L':
		return 1
	case 'O':
		return 0
	}
	for i := 0; i < len(crockfordAlphabet); i++ {
		if crockfordAlphabet[i] == c {
			return i
		}
	}
	return -1
}

// bitAt returns bit i of the big-endian bit string b, or 0 past its end.
func bitAt(b []byte, i int) int {
	if i/8 >= len(b) {
		return 0
	}
	return int(b[i/8]>>(7-i%8)) & 1
}

// crockfordEncode emits n symbols for the bit string b starting at bit
// offset skip, padding with zero bits on the right.
func crockfordEncode(b []byte, skip, n int) string {
	out := make([]byte, n)
	for s := range n {
		v := 0
		for j := range 5 {
			v = v<<1 | bitAt(b, skip+5*s+j)
		}
		out[s] = crockfordAlphabet[v]
	}
	return string(out)
}

// crockfordDecode turns symbol values back into a bit string of nbytes
// bytes, writing the first symbol's bits starting at bit offset skip. Bits
// that fall outside the buffer are returned as the overflow count of set
// bits, so callers can require zero padding.
func crockfordDecode(vals []int, skip, nbytes int) (out []byte, overflowSet int) {
	out = make([]byte, nbytes)
	for s, v := range vals {
		for j := range 5 {
			bit := v >> (4 - j) & 1
			i := skip + 5*s + j
			if i/8 >= nbytes {
				overflowSet += bit
				continue
			}
			out[i/8] |= byte(bit << (7 - i%8))
		}
	}
	return out, overflowSet
}
