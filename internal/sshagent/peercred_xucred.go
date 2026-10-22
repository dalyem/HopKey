//go:build darwin || freebsd

package sshagent

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the uid of the process that connected c, from the socket's
// LOCAL_PEERCRED option (struct xucred: the effective uid at connect time).
// macOS and FreeBSD both have it. A credential structure of a version this
// code does not know is refused rather than read.
func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Xucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, sockErr
	}
	if cred == nil {
		return 0, errors.New("sshagent: no peer credentials")
	}
	if cred.Version != 0 { // XUCRED_VERSION
		return 0, fmt.Errorf("sshagent: unknown xucred version %d", cred.Version)
	}
	return cred.Uid, nil
}
