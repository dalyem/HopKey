package daemon

import (
	"context"
	"slices"
	"strings"

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

// AccountSecrets is implemented by a store that holds secrets beyond its
// items while it is unlocked (store.Store: the Secret Key, a pending kit,
// the device's own keys), each in every form it may be printed in. It
// fails with model.ErrLocked while locked.
type AccountSecrets interface {
	AccountSecrets() ([]redact.Secret, error)
}

// minKeyLine is the shortest line of a private key's body looked for on
// its own: the last line of a block can be a few characters, which would
// match ordinary text.
const minKeyLine = 16

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

func (d *Daemon) opRedact(ctx context.Context, p RedactParams) (*RedactResult, error) {
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
	out := &RedactResult{Hits: make([][]redact.Hit, len(p.Texts))}
	for i, t := range p.Texts {
		out.Hits[i] = redact.Literals(string(t), secrets)
		if out.Hits[i] == nil {
			out.Hits[i] = []redact.Hit{}
		}
	}
	return out, nil
}

// vaultSecrets is every secret field of the vault's items: each
// credential's password, and each key's private half whole, its body
// without line breaks, and each body line long enough to stand alone.
func vaultSecrets(snap model.Snapshot) []redact.Secret {
	var out []redact.Secret
	for _, c := range snap.Credentials {
		if c.Password != "" {
			out = append(out, redact.Secret{Kind: redact.KindVaultPassword, Value: c.Password})
		}
	}
	for _, k := range snap.Keys {
		if k.PrivateKey == "" {
			continue
		}
		out = append(out, redact.Secret{Kind: redact.KindVaultPrivateKey, Value: k.PrivateKey})
		var body []string
		for _, l := range strings.Split(strings.ReplaceAll(k.PrivateKey, "\r\n", "\n"), "\n") {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "-----") {
				continue
			}
			body = append(body, l)
			if len(l) >= minKeyLine {
				out = append(out, redact.Secret{Kind: redact.KindVaultPrivateKey, Value: l})
			}
		}
		if joined := strings.Join(body, ""); len(joined) >= minKeyLine {
			out = append(out, redact.Secret{Kind: redact.KindVaultPrivateKey, Value: joined})
		}
	}
	return slices.CompactFunc(out, func(a, b redact.Secret) bool { return a == b })
}
