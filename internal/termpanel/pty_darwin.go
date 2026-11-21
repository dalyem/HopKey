package termpanel

import (
	"bytes"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	ioctlGetTermios = unix.TIOCGETA
	ioctlSetTermios = unix.TIOCSETA
)

// openPTY opens a pty: its master, non-blocking, and its slave.
func openPTY() (ptm int, pts *os.File, err error) {
	ptm, err = unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, nil, err
	}
	fail := func(err error) (int, *os.File, error) {
		unix.Close(ptm)
		return -1, nil, err
	}
	if err := unix.IoctlSetInt(ptm, unix.TIOCPTYGRANT, 0); err != nil {
		return fail(err)
	}
	if err := unix.IoctlSetInt(ptm, unix.TIOCPTYUNLK, 0); err != nil {
		return fail(err)
	}
	var buf [128]byte // TIOCPTYGNAME's size
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(ptm), uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&buf[0]))); e != 0 {
		return fail(e)
	}
	if err := unix.SetNonblock(ptm, true); err != nil {
		return fail(err)
	}
	name := string(buf[:bytes.IndexByte(buf[:], 0)])
	fd, err := unix.Open(name, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	return ptm, os.NewFile(uintptr(fd), name), nil
}

func newWakePipe() (wakePipe, error) {
	// As os.Pipe does without pipe2: a fork in between must not inherit
	// the descriptors.
	var p [2]int
	syscall.ForkLock.RLock()
	err := unix.Pipe(p[:])
	if err == nil {
		unix.CloseOnExec(p[0])
		unix.CloseOnExec(p[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return wakePipe{}, err
	}
	unix.SetNonblock(p[0], true)
	unix.SetNonblock(p[1], true)
	return wakePipe{p[0], p[1]}, nil
}
