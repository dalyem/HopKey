//go:build linux

package cli

import (
	"context"

	"golang.org/x/sys/unix"
)

// watchStdinHangup calls hangup once poll reports f hung up. It asks for no
// events: POLLHUP and POLLERR are always reported, and stdin is never read,
// so what the user types is left for a later prompt.
func watchStdinHangup(ctx context.Context, f interface{ Fd() uintptr }, hangup func()) {
	fd := int32(f.Fd())
	go func() {
		for ctx.Err() == nil {
			fds := []unix.PollFd{{Fd: fd}}
			n, err := unix.Poll(fds, 500)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return
			}
			if n > 0 && fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
				hangup()
				return
			}
		}
	}()
}
