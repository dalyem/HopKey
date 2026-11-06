//go:build !linux && !darwin && !freebsd

package sshagent

import (
	"errors"
	"net"
)

// peerUID has no implementation here, so every connection is refused. Linux
// (SO_PEERCRED), macOS and FreeBSD (LOCAL_PEERCRED) have their own files.
// OpenBSD and NetBSD have a peer credential option too, but x/sys offers no
// accessor for it; add a build-tagged file for them rather than loosening
// this one.
func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("sshagent: peer credentials are not implemented on this platform")
}
