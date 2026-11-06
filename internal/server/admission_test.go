package server

import (
	"strconv"
	"testing"
)

// The client's admission preflight (crypto spec rev 17 amendment, §3.1)
// measures a candidate as this server does: singleton length = 212 +
// digits(seq) + len(JCS(wire)), against 1 MiB per object and 4 MiB per
// wire. internal/store's admission tests pin the client to the same
// numbers; this pins the server's own accounting to them.
func TestSingletonLenIsTheSpecFormula(t *testing.T) {
	for _, seq := range []uint64{1, 9, 10, 99, 100, 12345, 1<<63 - 1, 1<<64 - 1} {
		for _, n := range []int{0, 1, 1000, 4 * MiB} {
			if got, want := singletonLen(seq, n), 212+len(strconv.FormatUint(seq, 10))+n; got != want {
				t.Errorf("singletonLen(%d, %d) = %d, want %d", seq, n, got, want)
			}
		}
	}
	lim := DefaultLimits()
	if lim.MaxObject != 1<<20 || lim.MaxWireResponse != 4<<20 || lim.MaxOps != 8192 || lim.MaxObjects != 16384 {
		t.Errorf("limits %+v are not the ones clients check against", lim)
	}
}
