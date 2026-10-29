//go:build !linux && !darwin

package procs

import (
	"net"
	"syscall"
)

// Lookup is not supported here.
func Lookup(pid int) (Proc, error) { return Proc{}, ErrUnsupported }

// Open is not supported here.
func Open(pid int) (*Pin, error) { return nil, ErrUnsupported }

// Signal is not supported here.
func (p *Pin) Signal(sig syscall.Signal) error { return ErrUnsupported }

// Exited is always true here: nothing is signalled.
func (p *Pin) Exited() bool { return true }

// Close does nothing here.
func (p *Pin) Close() {}

// PeerPID is not supported here.
func PeerPID(c *net.UnixConn) (int, error) { return 0, ErrUnsupported }
