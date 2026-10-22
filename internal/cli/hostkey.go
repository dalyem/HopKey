package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

var errCaptured = errors.New("hop: host key captured")

// fetchHostKey connects to addr:port, runs the SSH key exchange far enough to
// learn the server's host key, and hangs up before authenticating. algs, if
// set, limits which host key algorithms the client offers, so the server
// presents a key of a type that is pinned.
func fetchHostKey(ctx context.Context, host string, port int, algs []string, timeout time.Duration) (ssh.PublicKey, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	// Stop a blocked handshake when the context ends.
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User:              "hop-check",
		HostKeyAlgorithms: algs,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errCaptured
		},
	}
	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
	if got != nil {
		return got, nil
	}
	if err == nil {
		err = errors.New("no host key was presented")
	}
	return nil, fmt.Errorf("ssh handshake with %s: %w", addr, err)
}

// algorithmsFor lists the host key algorithms that can present any of the
// pinned keys. Without pins it returns nil and the client's defaults apply.
func algorithmsFor(pins []ssh.PublicKey) []string {
	var out []string
	seen := map[string]bool{}
	add := func(a ...string) {
		for _, x := range a {
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	for _, p := range pins {
		switch p.Type() {
		case ssh.KeyAlgoRSA:
			add(ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA)
		default:
			add(p.Type())
		}
	}
	return out
}

// tcpReachable reports whether a TCP connection to host:port opens.
func tcpReachable(ctx context.Context, host string, port int, timeout time.Duration) error {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return conn.Close()
}
