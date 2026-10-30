package server

import (
	"net/http"
	"net/netip"
	"testing"
)

func TestClientIP(t *testing.T) {
	s := &Server{proxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	for _, c := range []struct {
		remote, xff, want string
	}{
		{"192.0.2.1:1234", "", "192.0.2.1"},
		{"192.0.2.1:1234", "203.0.113.5", "192.0.2.1"},           // untrusted peer
		{"10.1.1.1:1234", "203.0.113.5", "203.0.113.5"},          // trusted proxy
		{"10.1.1.1:1234", "1.1.1.1, 203.0.113.5", "203.0.113.5"}, // rightmost untrusted
		{"10.1.1.1:1234", "203.0.113.5, 10.2.2.2", "203.0.113.5"},
		{"10.1.1.1:1234", "", "10.1.1.1"},
		{"10.1.1.1:1234", "garbage", "10.1.1.1"},
		{"[::ffff:192.0.2.1]:1", "", "192.0.2.1"},
	} {
		r := &http.Request{RemoteAddr: c.remote, Header: http.Header{}}
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := s.clientIP(r).String(); got != c.want {
			t.Errorf("clientIP(%s, %q) = %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
	if k := ipKey(netip.MustParseAddr("2001:db8:1:2:3:4:5:6")); k != "2001:db8:1:2::/64" {
		t.Errorf("IPv6 key %s", k)
	}
}

func TestDepthWithin(t *testing.T) {
	if !depthWithin([]byte(`{"a":"[[[[[[["}`), 1) {
		t.Error("brackets inside a string counted")
	}
	if !depthWithin([]byte(`{"a":"\"[[["}`), 1) {
		t.Error("an escaped quote ended the string")
	}
	if depthWithin([]byte(`[[1]]`), 1) || !depthWithin([]byte(`[[1]]`), 2) {
		t.Error("depth of [[1]]")
	}
}
