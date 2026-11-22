package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

func pid() int { return os.Getpid() }

// Client talks to a daemon's control socket.
type Client struct {
	mu   sync.Mutex
	conn net.Conn
	sc   *bufio.Scanner
}

// Dial connects to the control socket at path.
func Dial(ctx context.Context, path string) (*Client, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64<<10), maxRequest)
	return &Client{conn: conn, sc: sc}, nil
}

// Close hangs up.
func (c *Client) Close() error { return c.conn.Close() }

// Call sends one request and decodes the result into result, if non-nil. A
// refusal by the daemon is returned as *Error. So is a warning on a
// success, with result decoded all the same: a caller that only checks
// the error never takes a partial success for a whole one. A caller that
// handles warnings uses CallWarn.
func (c *Client) Call(ctx context.Context, op string, params, result any) error {
	w, err := c.CallWarn(ctx, op, params, result)
	if err == nil && w != nil {
		return w
	}
	return err
}

// CallWarn is Call that also returns the warning a successful response
// carries (CodeConfigNotWritten: the change took effect, the ssh config is
// behind). The result is decoded either way.
func (c *Client) CallWarn(ctx context.Context, op string, params, result any) (warning *Error, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	req := Request{Op: op}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		req.Params = b
	}
	line, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(requestTimeout + 5*time.Second)
	}
	c.conn.SetDeadline(deadline)
	defer c.conn.SetDeadline(time.Time{})
	// Stop a blocked read when the context is cancelled.
	stop := context.AfterFunc(ctx, func() { c.conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if _, err := c.conn.Write(append(line, '\n')); err != nil {
		return nil, connError(ctx, err)
	}
	if !c.sc.Scan() {
		err := c.sc.Err()
		if err == nil {
			err = errors.New("the daemon closed the connection")
		}
		return nil, connError(ctx, err)
	}
	var resp Response
	if err := json.Unmarshal(c.sc.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("daemon: malformed response: %w", err)
	}
	if !resp.OK {
		if resp.Error == nil {
			return nil, errors.New("daemon: request failed")
		}
		return nil, resp.Error
	}
	if result != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, result); err != nil {
			return nil, fmt.Errorf("daemon: malformed result: %w", err)
		}
	}
	return resp.Warning, nil
}

func connError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
