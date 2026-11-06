//go:build linux

package cli

import (
	"context"
	"os"
	"testing"
	"time"
)

// A login whose terminal went away stops, and releases the vault. The watch
// only looks at stdin's hangup state: it never reads, and a pipe whose
// writer is still there is not a hangup.
func TestHangupContextCancelsWhenStdinGoesAway(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ctx, stop := hangupContext(context.Background(), &Env{Stdin: r, StdinTTY: true})
	defer stop()
	w.Write([]byte("typed ahead\n"))
	select {
	case <-ctx.Done():
		t.Fatal("cancelled while the writer is still there")
	case <-time.After(700 * time.Millisecond):
	}
	w.Close()
	select {
	case <-ctx.Done():
		if got := context.Cause(ctx); got != errStdinClosed {
			t.Errorf("cause = %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not cancelled after stdin was closed")
	}
	buf := make([]byte, 64)
	if n, _ := r.Read(buf); string(buf[:n]) != "typed ahead\n" {
		t.Errorf("the watch consumed input: %q", buf[:n])
	}
}

// Off a terminal (--password-stdin) a closed pipe is the normal case.
func TestHangupContextIgnoresPipes(t *testing.T) {
	r, w, _ := os.Pipe()
	defer r.Close()
	w.Close()
	ctx, stop := hangupContext(context.Background(), &Env{Stdin: r, StdinTTY: false})
	defer stop()
	select {
	case <-ctx.Done():
		t.Fatal("cancelled for a pipe")
	case <-time.After(700 * time.Millisecond):
	}
}
