//go:build !linux

package sshagent

import (
	"errors"
	"net"
)

// peerUID has no implementation here yet, so every connection is refused.
// macOS and the BSDs need getpeereid (or LOCAL_PEERCRED); add a build-tagged
// file for them rather than loosening this one.
func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("sshagent: peer credentials are not implemented on this platform")
}
