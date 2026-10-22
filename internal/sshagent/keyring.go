// Package sshagent serves an in-memory keyring over an ssh-agent socket.
package sshagent

import (
	"errors"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var errReadOnly = errors.New("sshagent: keyring is read-only")

// Keyring holds decrypted private keys in memory. The daemon fills it with
// Add and RemoveAll; clients of the agent socket only see the read-only
// view returned by Agent.
type Keyring struct {
	kr agent.ExtendedAgent
}

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring {
	return &Keyring{kr: agent.NewKeyring().(agent.ExtendedAgent)}
}

// Add loads a private key (*rsa.PrivateKey, *ecdsa.PrivateKey or
// ed25519.PrivateKey) under the given comment.
func (k *Keyring) Add(key any, comment string) error {
	return k.kr.Add(agent.AddedKey{PrivateKey: key, Comment: comment})
}

// RemoveAll drops every key.
func (k *Keyring) RemoveAll() error {
	return k.kr.RemoveAll()
}

// Agent returns the view that is safe to serve to other processes: it lists
// keys and signs, and refuses every request that changes the keyring.
// Without this, any process running as the user could add keys, remove keys,
// or lock the keyring with ssh-add.
//
// The view implements agent.ExtendedAgent. OpenSSH asks for rsa-sha2-256 and
// rsa-sha2-512 signatures through SignWithFlags; an agent without it only
// signs RSA with SHA-1, which current servers reject.
func (k *Keyring) Agent() agent.ExtendedAgent {
	return readOnly{k.kr}
}

type readOnly struct {
	agent.ExtendedAgent
}

func (readOnly) Add(agent.AddedKey) error   { return errReadOnly }
func (readOnly) Remove(ssh.PublicKey) error { return errReadOnly }
func (readOnly) RemoveAll() error           { return errReadOnly }
func (readOnly) Lock([]byte) error          { return errReadOnly }
func (readOnly) Unlock([]byte) error        { return errReadOnly }
