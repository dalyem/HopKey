package daemon

import (
	"errors"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/sshagent"
)

var (
	errReadOnly = errors.New("daemon: the agent is read-only")
	errFenced   = errors.New("daemon: the vault was locked or this device revoked; the agent signs nothing")
)

// fence is the lock-free view of a store's lock state (store.Store): a
// generation that moves on every unlock, lock, self-lock and revocation,
// before the store does anything slow, and whether the device is revoked.
type fence interface {
	Generation() uint64
	IsRevoked() bool
}

func fenceOf(s model.Store) fence {
	f, _ := s.(fence)
	return f
}

// loaded is a keyring and the store generation it was loaded in.
type loaded struct {
	kr  *sshagent.Keyring
	gen uint64
}

// liveAgent is the agent served on the socket. It forwards to the current
// keyring, which reload replaces whole, so a reload never exposes a half-
// filled keyring to an ssh that is mid-handshake. It only lists and signs.
//
// With a fenced store it serves the keyring only while the store is in the
// generation the keyring was loaded in and the device is not revoked (§5.5).
// That check reads two atomics when each list or signature call is
// admitted: it is an admission cutoff. Once a lock or a revocation moves
// the fence, every call admitted after is refused, even while the store is
// still writing and the daemon's teardown is waiting for it. A call that
// passed the check before the fence moved may still complete, whether or
// not its signature was already being computed.
type liveAgent struct {
	fence fence // nil: the store has no generation, and nothing is fenced
	cur   atomic.Pointer[loaded]
}

var _ agent.ExtendedAgent = (*liveAgent)(nil)

func newLiveAgent(f fence) *liveAgent {
	a := &liveAgent{fence: f}
	a.cur.Store(&loaded{kr: sshagent.NewKeyring()})
	return a
}

// generation is the store's generation now, or 0 for a store without one.
func (a *liveAgent) generation() uint64 {
	if a.fence == nil {
		return 0
	}
	return a.fence.Generation()
}

// swap installs kr, loaded in store generation gen, and returns the keyring
// it replaced.
func (a *liveAgent) swap(kr *sshagent.Keyring, gen uint64) *sshagent.Keyring {
	return a.cur.Swap(&loaded{kr: kr, gen: gen}).kr
}

// valid reports whether l may be served.
func (a *liveAgent) valid(l *loaded) bool {
	return a.fence == nil || (a.fence.Generation() == l.gen && !a.fence.IsRevoked())
}

// stale reports whether the store has left the generation of the keyring
// in place, or the device was revoked.
func (a *liveAgent) stale() bool { return !a.valid(a.cur.Load()) }

// view returns the current keyring's agent, or nil when it is fenced off.
func (a *liveAgent) view() agent.ExtendedAgent {
	l := a.cur.Load()
	if !a.valid(l) {
		return nil
	}
	return l.kr.Agent()
}

func (a *liveAgent) List() ([]*agent.Key, error) {
	v := a.view()
	if v == nil {
		return nil, nil
	}
	return v.List()
}

func (a *liveAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	v := a.view()
	if v == nil {
		return nil, errFenced
	}
	return v.Sign(key, data)
}

func (a *liveAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	v := a.view()
	if v == nil {
		return nil, errFenced
	}
	return v.SignWithFlags(key, data, flags)
}

func (a *liveAgent) Signers() ([]ssh.Signer, error) {
	v := a.view()
	if v == nil {
		return nil, nil
	}
	return v.Signers()
}

func (*liveAgent) Add(agent.AddedKey) error   { return errReadOnly }
func (*liveAgent) Remove(ssh.PublicKey) error { return errReadOnly }
func (*liveAgent) RemoveAll() error           { return errReadOnly }
func (*liveAgent) Lock([]byte) error          { return errReadOnly }
func (*liveAgent) Unlock([]byte) error        { return errReadOnly }
func (*liveAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
