package daemon

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/redact"
)

// OpRedact finds the vault's secrets in text hop mcp is about to hand an
// agent: the passwords of its credentials, its keys' private halves, and
// what the store holds of the account (AccountSecrets). It answers where
// they stand and of what kind, never what they are: the caller, which has
// the text, replaces them, in the same pass as what it finds itself. It
// needs the vault unlocked, and refuses with CodeLocked otherwise.
const OpRedact = "redact"

// RedactParams is the request for OpRedact. Each text is bytes, so that
// what is not UTF-8 keeps its offsets.
type RedactParams struct {
	Texts [][]byte `json:"texts"`
}

// RedactResult answers OpRedact: for each text, in order, the stretches to
// replace, by byte offset into it. Hits may overlap.
type RedactResult struct {
	Hits [][]redact.Hit `json:"hits"`
}

// AccountSecrets is implemented by a store that holds secrets beyond what
// its snapshot shows while it is unlocked (store.Store: the secrets of
// verified items a queued change replaces or deletes, the Secret Key, a
// pending kit, the account's and the device's own keys), each in every
// form it may be printed in. It fails with model.ErrLocked while locked.
type AccountSecrets interface {
	AccountSecrets() ([]redact.Secret, error)
}

// dispatchRedact handles OpRedact. handled is false for any other op.
func (d *Daemon) dispatchRedact(ctx context.Context, req Request, decode func(any) error) (result any, handled bool, err error) {
	if req.Op != OpRedact {
		return nil, false, nil
	}
	var p RedactParams
	if err := decode(&p); err != nil {
		return nil, true, err
	}
	r, err := d.opRedact(ctx, p)
	return r, true, err
}

// OpRedact is rationed (redactBudget): each request holds at most
// redactMaxRequest bytes, the daemon takes redactRate bytes a second after
// a burst of redactBurst, and runs at most redactSlots requests at once.
// It is a lookup in the vault's secrets, so a process that can call it can
// test guesses against them; the ration bounds how fast, so that it costs
// what reading the output of commands would. It is a throughput limit, not
// a boundary: a process of the user's own can read far more than this.
const (
	redactMaxRequest = 256 << 10
	redactBurst      = 1 << 20
	redactRate       = (8 << 20) / 60.0
	redactSlots      = 4
)

// CodeRedactBudget refuses OpRedact while the daemon's redaction budget is
// spent. It refills within seconds.
const CodeRedactBudget = "redact_budget"

// redactBudget is a token bucket of bytes, shared by every OpRedact
// caller. The zero value is full.
type redactBudget struct {
	mu     sync.Mutex
	now    func() time.Time // time.Now when nil
	tokens float64
	last   time.Time
}

// take spends n bytes of the budget, and reports whether there were n to
// spend. A refused request spends nothing.
func (b *redactBudget) take(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now
	if b.now != nil {
		now = b.now
	}
	t := now()
	if b.last.IsZero() {
		b.tokens = redactBurst
	} else if dt := t.Sub(b.last).Seconds(); dt > 0 {
		b.tokens = min(redactBurst, b.tokens+dt*redactRate)
	}
	b.last = t
	if float64(n) > b.tokens {
		return false
	}
	b.tokens -= float64(n)
	return true
}

func (d *Daemon) opRedact(ctx context.Context, p RedactParams) (*RedactResult, error) {
	n := 0
	for _, t := range p.Texts {
		n += len(t)
	}
	if n > redactMaxRequest {
		return nil, invalidf("redact takes at most %d bytes a request, not %d", redactMaxRequest, n)
	}
	if !d.redactBudget.take(n) {
		return nil, &Error{Code: CodeRedactBudget, Message: "the hop daemon's redaction budget is exhausted; try again shortly"}
	}
	select {
	case d.redactSlots <- struct{}{}:
		defer func() { <-d.redactSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	snap, _, err := d.fresh(ctx)
	if err != nil {
		return nil, err
	}
	secrets := vaultSecrets(snap)
	if a, ok := d.store.(AccountSecrets); ok {
		more, err := a.AccountSecrets()
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, more...)
	}
	// The store's secrets repeat most of the snapshot's.
	slices.SortFunc(secrets, func(a, b redact.Secret) int {
		return cmp.Or(strings.Compare(a.Value, b.Value), strings.Compare(a.Kind, b.Kind))
	})
	secrets = slices.Compact(secrets)
	out := &RedactResult{Hits: make([][]redact.Hit, len(p.Texts))}
	for i, t := range p.Texts {
		out.Hits[i] = redact.Literals(string(t), secrets)
		if out.Hits[i] == nil {
			out.Hits[i] = []redact.Hit{}
		}
	}
	return out, nil
}

// vaultSecrets is every secret field of the snapshot's items: each
// credential's password, and each key's private half in the forms
// redact.PrivateKeyForms lists.
func vaultSecrets(snap model.Snapshot) []redact.Secret {
	var out []redact.Secret
	for _, c := range snap.Credentials {
		if c.Password != "" {
			out = append(out, redact.Secret{Kind: redact.KindVaultPassword, Value: c.Password})
		}
	}
	for _, k := range snap.Keys {
		out = append(out, redact.PrivateKeyForms(k.PrivateKey)...)
	}
	return out
}
