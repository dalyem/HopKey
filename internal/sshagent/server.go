package sshagent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

// maxSocketPath is the longest socket path that fits sockaddr_un on macOS
// (104 bytes including the NUL). Linux allows 108.
const maxSocketPath = 103

// ErrInUse means another process is already serving the socket path.
var ErrInUse = errors.New("sshagent: socket is in use")

// Server serves an agent on a Unix socket.
type Server struct {
	// Logf, if set, receives connections that were turned away.
	Logf func(format string, args ...any)

	path  string
	ln    *net.UnixListener
	agent agent.ExtendedAgent

	// authorize decides whether a peer may talk to the agent. Tests replace
	// it; the default accepts only the process's own uid.
	authorize func(*net.UnixConn) error

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// Listen creates the socket at path and starts listening. The parent
// directory is created and forced to 0700 and the socket is 0600. A stale
// socket file left by a dead process is replaced; a live one yields ErrInUse.
func Listen(path string, ag agent.ExtendedAgent) (*Server, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("sshagent: socket path %q is not absolute", path)
	}
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("sshagent: socket path is %d bytes, the limit is %d", len(path), maxSocketPath)
	}
	if err := preparePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	// The socket is created with the umask's permissions. The 0700 parent
	// keeps other users out until this chmod lands.
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return &Server{
		path:      path,
		ln:        ln,
		agent:     ag,
		authorize: requireSameUID,
		conns:     make(map[net.Conn]struct{}),
	}, nil
}

// Path returns the socket path.
func (s *Server) Path() string { return s.path }

// Serve accepts connections until Close is called, then returns nil.
func (s *Server) Serve() error {
	for {
		c, err := s.ln.AcceptUnix()
		if err != nil {
			if s.isClosed() {
				return nil
			}
			return err
		}
		if err := s.authorize(c); err != nil {
			if s.Logf != nil {
				s.Logf("sshagent: rejected connection: %v", err)
			}
			c.Close()
			continue
		}
		if !s.track(c) {
			c.Close()
			return nil
		}
		go s.serveConn(c)
	}
}

// Close stops accepting, drops open connections, waits for their handlers
// and removes the socket file.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	err := s.ln.Close() // also unlinks the socket
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()

	s.wg.Wait()
	return err
}

func (s *Server) serveConn(c net.Conn) {
	defer s.wg.Done()
	defer s.untrack(c)
	// ServeAgent returns when the client hangs up; the error is io.EOF then.
	_ = agent.ServeAgent(s.agent, c)
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// track registers c, reporting false if the server is already closed.
// wg.Add happens under the lock so it cannot race with the Wait in Close.
func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c] = struct{}{}
	s.wg.Add(1)
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	c.Close()
}

func requireSameUID(c *net.UnixConn) error {
	uid, err := peerUID(c)
	if err != nil {
		return err
	}
	if want := uint32(os.Getuid()); uid != want {
		return fmt.Errorf("peer uid %d, want %d", uid, want)
	}
	return nil
}

// preparePrivateDir makes sure dir exists, is a real directory we own, and
// has mode 0700.
func preparePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("sshagent: %s is not a directory", dir)
	}
	if !ownedByCurrentUser(fi) {
		return fmt.Errorf("sshagent: %s is not owned by the current user", dir)
	}
	if fi.Mode().Perm() != 0o700 {
		return os.Chmod(dir, 0o700)
	}
	return nil
}

// removeStaleSocket deletes path if it is a socket nobody is listening on.
func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("sshagent: %s exists and is not a socket", path)
	}
	if c, err := net.DialTimeout("unix", path, 250*time.Millisecond); err == nil {
		c.Close()
		return ErrInUse
	}
	return os.Remove(path)
}
