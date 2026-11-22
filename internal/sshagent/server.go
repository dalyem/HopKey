package sshagent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/dalyem/hopkey/internal/filelock"
	"github.com/dalyem/hopkey/internal/safepath"
)

// maxSocketPath is the longest socket path that fits sockaddr_un on macOS
// (104 bytes including the NUL). Linux allows 108.
const maxSocketPath = 103

// lockName is the file next to the socket whose flock says "a server owns
// this directory". It is never deleted: removing a lock file while another
// process opens it is a race.
const lockName = "agent.lock"

// ErrInUse means another server holds the socket directory's lock, or a live
// listener that does not use the lock is already on the socket path.
var ErrInUse = errors.New("sshagent: socket is in use")

// Server serves an agent on a Unix socket.
type Server struct {
	// Logf, if set, receives connections that were turned away.
	Logf func(format string, args ...any)

	path  string
	ln    *net.UnixListener
	agent agent.ExtendedAgent

	// lock holds the flock for the server's lifetime; sockInfo identifies
	// the socket file this server created so Close never unlinks another.
	lock     *os.File
	sockInfo os.FileInfo

	// authorize decides whether a peer may talk to the agent. Tests replace
	// it; the default accepts only the process's own uid.
	authorize func(*net.UnixConn) error

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	closed   bool
	wg       sync.WaitGroup
	done     chan struct{} // closed once Close has finished draining
	closeErr error         // valid after done is closed
}

// Listen creates the socket at path and starts listening.
//
// The parent directory is created if needed and must pass
// safepath.EnsurePrivateDir: no unsafe ancestors, owned by the current user,
// mode 0700. The server holds an exclusive flock on agent.lock in that
// directory until Close; a second Listen on the same directory returns
// ErrInUse and touches nothing. Once the lock is held, a socket file at path
// is probed by dialing it: a live listener (one that does not use the lock)
// yields ErrInUse and is left alone, a refused connection marks the file as
// stale and it is replaced, and any other dial error is returned without
// touching the file. The socket is 0600.
//
// Path reports the socket's path with symlinks in the directory resolved.
func Listen(path string, ag agent.ExtendedAgent) (*Server, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("sshagent: socket path %q is not absolute", path)
	}
	dir, err := safepath.EnsurePrivateDir(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("sshagent: socket directory: %w", err)
	}
	path = filepath.Join(dir, filepath.Base(path))
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("sshagent: socket path is %d bytes, the limit is %d", len(path), maxSocketPath)
	}

	lock, err := filelock.TryLock(filepath.Join(dir, lockName))
	if errors.Is(err, filelock.ErrLocked) {
		return nil, ErrInUse
	}
	if err != nil {
		return nil, fmt.Errorf("sshagent: %w", err)
	}
	srv, err := listenLocked(path, ag, lock)
	if err != nil {
		lock.Close()
		return nil, err
	}
	return srv, nil
}

// listenLocked does the work of Listen while the caller holds the lock.
func listenLocked(path string, ag agent.ExtendedAgent, lock *os.File) (*Server, error) {
	// With the lock held no cooperating server is running here, but a
	// process that ignores the lock may still be listening on the path.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("sshagent: %s exists and is not a socket", path)
		}
		if err := removeStaleSocket(path, fi); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	// Go would unlink by name on Close, even if the path now names someone
	// else's socket. Close does the unlink itself, after checking the inode.
	ln.SetUnlinkOnClose(false)

	fail := func(err error) (*Server, error) {
		ln.Close()
		os.Remove(path) // ours: we hold the lock and just created it
		return nil, err
	}
	// The socket is created with the umask's permissions. The 0700 parent
	// keeps other users out until this chmod lands.
	if err := os.Chmod(path, 0o600); err != nil {
		return fail(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fail(err)
	}
	return &Server{
		path:      path,
		ln:        ln,
		agent:     ag,
		lock:      lock,
		sockInfo:  info,
		authorize: requireSameUID,
		conns:     make(map[net.Conn]struct{}),
		done:      make(chan struct{}),
	}, nil
}

// dialExisting probes a socket file left at the path. Tests replace it.
var dialExisting = func(path string) (net.Conn, error) {
	return net.DialTimeout("unix", path, 2*time.Second)
}

// removeStaleSocket unlinks the socket file fi at path if nothing listens on
// it. A successful dial means a live listener: ErrInUse. Only a refused
// connection proves the file is stale; any other error (a timeout, a full
// backlog, a permission problem) leaves the file alone and is returned.
// The file is removed only if it is still the inode fi describes. There is a
// small window between that check and the unlink that the filesystem API
// cannot close; the private directory keeps other users out of it.
func removeStaleSocket(path string, fi os.FileInfo) error {
	conn, err := dialExisting(path)
	if err == nil {
		conn.Close()
		return ErrInUse
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("sshagent: cannot tell whether the socket at %s is live: %w", path, err)
	}
	cur, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(fi, cur) {
		return fmt.Errorf("sshagent: %s changed while it was being checked", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
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

// Close stops accepting, drops open connections, waits for their handlers,
// removes the socket file if it is still the one this server created, and
// releases the directory lock. Every call returns only after that work has
// finished; later calls return the first call's error.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		<-s.done
		return s.closeErr
	}
	s.closed = true
	err := s.ln.Close()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()

	s.wg.Wait()

	// Unlink before unlocking, so a server that starts next finds no socket
	// of ours to trip over. Only our own inode: if the path was replaced,
	// the replacement is not ours to delete.
	if cur, statErr := os.Lstat(s.path); statErr == nil && os.SameFile(cur, s.sockInfo) {
		if rmErr := os.Remove(s.path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) && err == nil {
			err = rmErr
		}
	}
	if lockErr := s.lock.Close(); lockErr != nil && err == nil {
		err = lockErr
	}
	s.closeErr = err
	close(s.done)
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

// RequireSameUID is the check Listen applies to every connection: the peer
// must run as this process's uid. It is exported so the daemon's control
// socket applies the same rule.
func RequireSameUID(c *net.UnixConn) error { return requireSameUID(c) }

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
