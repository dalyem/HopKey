package daemon

import (
	"errors"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/dalyem/hopkey/internal/sshagent"
)

var errReadOnly = errors.New("daemon: the agent is read-only")

// liveAgent is the agent served on the socket. It forwards to the current
// keyring, which reload replaces whole, so a reload never exposes a half-
// filled keyring to an ssh that is mid-handshake. It only lists and signs.
type liveAgent struct {
	cur atomic.Pointer[sshagent.Keyring]
}

var _ agent.ExtendedAgent = (*liveAgent)(nil)

func newLiveAgent() *liveAgent {
	a := &liveAgent{}
	a.cur.Store(sshagent.NewKeyring())
	return a
}

// swap installs kr and returns the keyring it replaced.
func (a *liveAgent) swap(kr *sshagent.Keyring) *sshagent.Keyring { return a.cur.Swap(kr) }

func (a *liveAgent) view() agent.ExtendedAgent { return a.cur.Load().Agent() }

func (a *liveAgent) List() ([]*agent.Key, error) { return a.view().List() }

func (a *liveAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.view().Sign(key, data)
}

func (a *liveAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	return a.view().SignWithFlags(key, data, flags)
}

func (a *liveAgent) Signers() ([]ssh.Signer, error) { return a.view().Signers() }

func (*liveAgent) Add(agent.AddedKey) error   { return errReadOnly }
func (*liveAgent) Remove(ssh.PublicKey) error { return errReadOnly }
func (*liveAgent) RemoveAll() error           { return errReadOnly }
func (*liveAgent) Lock([]byte) error          { return errReadOnly }
func (*liveAgent) Unlock([]byte) error        { return errReadOnly }
func (*liveAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
