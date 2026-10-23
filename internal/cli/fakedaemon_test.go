package cli_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
)

// fakeDaemon answers the control protocol on a real Unix socket with
// whatever each test sets, so the CLI can be driven through states and
// error codes a real daemon reaches only with a server: sync states, held
// changes, config_stale, config_not_written warnings. It records every
// request.
type fakeDaemon struct {
	base  string
	home  string
	paths daemon.Paths
	now   time.Time

	mu    sync.Mutex
	ops   map[string]func(params json.RawMessage) (any, error)
	calls []daemon.Request

	// Per-invocation settings for hop.
	stdin string
	tty   bool
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	// Unix socket paths are length-limited, so avoid t.TempDir here.
	base, err := os.MkdirTemp("", "hkf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	f := &fakeDaemon{
		base: base,
		home: filepath.Join(base, "home"),
		paths: daemon.Paths{
			RunDir:    filepath.Join(base, "run"),
			ConfigDir: filepath.Join(base, "home", ".ssh", "hop"),
			StateDir:  filepath.Join(base, "state"),
		},
		now: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC),
		ops: map[string]func(json.RawMessage) (any, error){},
	}
	if err := os.MkdirAll(f.paths.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.home, 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", f.paths.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeDaemon) serve(c net.Conn) {
	defer c.Close()
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	enc := json.NewEncoder(c)
	for sc.Scan() {
		var req daemon.Request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			return
		}
		f.mu.Lock()
		f.calls = append(f.calls, req)
		fn := f.ops[req.Op]
		f.mu.Unlock()
		var resp daemon.Response
		if fn == nil {
			resp.Error = &daemon.Error{Code: daemon.CodeInvalid, Message: "fake daemon: unhandled op " + req.Op}
		} else if res, err := fn(req.Params); err != nil {
			var de *daemon.Error
			if !errors.As(err, &de) {
				de = &daemon.Error{Code: daemon.CodeInternal, Message: err.Error()}
			}
			resp.Error = de
		} else {
			resp.OK = true
			if w, ok := res.(warned); ok {
				res, resp.Warning = w.result, &daemon.Error{Code: daemon.CodeConfigNotWritten, Message: w.warning}
			}
			if res != nil {
				b, err := json.Marshal(res)
				if err != nil {
					panic(err)
				}
				resp.Result = b
			}
		}
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

// warned is a handler's answer for a change that took effect while the ssh
// config could not be written: a success that carries result and a
// config_not_written warning, as the daemon answers.
type warned struct {
	result  any
	warning string
}

// on sets the handler for op.
func (f *fakeDaemon) on(op string, fn func(params json.RawMessage) (any, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops[op] = fn
}

// reply makes op answer with result.
func (f *fakeDaemon) reply(op string, result any) {
	f.on(op, func(json.RawMessage) (any, error) { return result, nil })
}

// fail makes op answer with a daemon error.
func (f *fakeDaemon) fail(op, code, msg string) {
	f.on(op, func(json.RawMessage) (any, error) { return nil, &daemon.Error{Code: code, Message: msg} })
}

// called returns the params of every request for op so far.
func (f *fakeDaemon) called(op string) []json.RawMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []json.RawMessage
	for _, c := range f.calls {
		if c.Op == op {
			out = append(out, c.Params)
		}
	}
	return out
}

func (f *fakeDaemon) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

// hop runs the CLI against the fake daemon.
func (f *fakeDaemon) hop(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	return f.hopWith(t, nil, args...)
}

func (f *fakeDaemon) hopWith(t *testing.T, adjust func(*cli.Env), args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var so, se bytes.Buffer
	env := &cli.Env{
		Stdin: strings.NewReader(f.stdin), Stdout: &so, Stderr: &se,
		Getenv: func(string) string { return "" },
		Home:   f.home, Paths: f.paths,
		StdoutTTY: f.tty, StdinTTY: f.tty,
		StartDaemon: func() error {
			t.Error("the CLI tried to start a daemon, but one is running")
			return errors.New("unexpected daemon start")
		},
		ExecSSH: func(string, []string, []string) error {
			t.Error("the CLI ran ssh")
			return errors.New("unexpected ssh")
		},
		RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
			t.Errorf("the CLI ran %s %q", name, args)
			return nil, errors.New("unexpected command")
		},
		Now:         func() time.Time { return f.now },
		DialTimeout: 2 * time.Second,
	}
	if adjust != nil {
		adjust(env)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	code = cli.Run(ctx, args, env)
	f.stdin = ""
	return code, so.String(), se.String()
}

// hostile is vault, server or filesystem text that tries to break a line,
// redraw the terminal and forge a diagnostic.
const hostile = "x\nhop: forged\x1b[2J‮\u009b"

// assertOneLineEach checks that out is display-safe and that no line in it
// was forged.
func assertNoForgery(t *testing.T, what, out string) {
	t.Helper()
	assertDisplaySafe(t, what, out)
	for _, l := range lines(out) {
		if strings.HasPrefix(l, "hop: forged") {
			t.Errorf("%s: forged line in %q", what, out)
		}
	}
}

func decodeJSON(t *testing.T, s string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(s), v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, s)
	}
}
