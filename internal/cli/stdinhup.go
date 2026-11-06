package cli

import (
	"context"
	"errors"
	"os"
)

// errStdinClosed is the cause hangupContext gives the context it cancels when
// stdin is gone.
var errStdinClosed = errors.New("stdin closed")

// hangupContext returns ctx, cancelled with errStdinClosed once the other
// end of stdin goes away (the terminal's master closed, or the pipe's writer
// exited). A hop auth command that waits for another device reads nothing
// from stdin meanwhile, so without this a login whose terminal was killed
// would keep the vault until its own deadline. stop ends the watch.
func hangupContext(ctx context.Context, e *Env) (context.Context, func()) {
	// Only a terminal: a pipe's writer exits as soon as it has written, which
	// is no reason to stop (--password-stdin).
	f, ok := e.Stdin.(*os.File)
	if !ok || f == nil || !e.StdinTTY {
		return ctx, func() {}
	}
	ctx, cancel := context.WithCancelCause(ctx)
	watchStdinHangup(ctx, f, func() { cancel(errStdinClosed) })
	return ctx, func() { cancel(nil) }
}
