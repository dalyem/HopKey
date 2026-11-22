package termpanel

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const (
	ioctlGetTermios = unix.TCGETS
	ioctlSetTermios = unix.TCSETS
)

// openPTY opens a pty: its master, non-blocking, and its slave.
func openPTY() (ptm int, pts *os.File, err error) {
	ptm, err = unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, nil, err
	}
	n, err := unix.IoctlGetUint32(ptm, unix.TIOCGPTN)
	if err == nil {
		err = unix.IoctlSetPointerInt(ptm, unix.TIOCSPTLCK, 0)
	}
	if err != nil {
		unix.Close(ptm)
		return -1, nil, err
	}
	name := "/dev/pts/" + strconv.FormatUint(uint64(n), 10)
	fd, err := unix.Open(name, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Close(ptm)
		return -1, nil, err
	}
	return ptm, os.NewFile(uintptr(fd), name), nil
}

func newWakePipe() (wakePipe, error) {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return wakePipe{}, err
	}
	return wakePipe{p[0], p[1]}, nil
}
