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
// refusal by the daemon is returned as *Error.
func (c *Client) Call(ctx context.Context, op string, params, result any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	req := Request{Op: op}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		req.Params = b
	}
	line, err := json.Marshal(req)
	if err != nil {
		return err
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
		return connError(ctx, err)
	}
	if !c.sc.Scan() {
		err := c.sc.Err()
		if err == nil {
			err = errors.New("the daemon closed the connection")
		}
		return connError(ctx, err)
	}
	var resp Response
	if err := json.Unmarshal(c.sc.Bytes(), &resp); err != nil {
		return fmt.Errorf("daemon: malformed response: %w", err)
	}
	if !resp.OK {
		if resp.Error == nil {
			return errors.New("daemon: request failed")
		}
		return resp.Error
	}
	if result != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, result); err != nil {
			return fmt.Errorf("daemon: malformed result: %w", err)
		}
	}
	return nil
}

func connError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
