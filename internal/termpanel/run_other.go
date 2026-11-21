//go:build !linux && !darwin

package termpanel

import (
	"context"
	"os"
	"syscall"
)

// Run is not supported here: it returns ErrUnsupported, and the caller
// runs the child on its streams directly.
func Run(ctx context.Context, opts Options, start func(tty *os.File, sys *syscall.SysProcAttr) (wait func() error, err error)) error {
	return ErrUnsupported
}
