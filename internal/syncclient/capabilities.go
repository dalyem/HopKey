package syncclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/dalyem/hopkey/internal/model"
)

// The capabilities preflight (crypto spec rev 17, §5.3).
var (
	// ErrCapabilitiesNewer: the server describes itself in a format newer
	// than v1.
	ErrCapabilitiesNewer = errors.New("the server describes itself in a newer format; upgrade hop")
	// ErrCapabilitiesUnknown: anything but a usable v1 answer or a 404.
	ErrCapabilitiesUnknown = errors.New("hop could not check whether the server accepts access records; try again")
)

// rev16Types are the item types of a server that predates GET
// /v1/capabilities: rev 16's, plus policy.
var rev16Types = []model.Type{model.TypeCredential, model.TypeGrant, model.TypeHost, model.TypeKey, model.TypePolicy, model.TypeSnippet}

// ItemTypes is GET /v1/capabilities: the item types the server accepts.
// A 404 means a server from before the endpoint, with rev 16's types and
// policy. A v greater than 1 is ErrCapabilitiesNewer; any other status,
// body or transport error is ErrCapabilitiesUnknown. Members other than v
// and item_types, and type names this build doesn't know, are ignored.
// The answer is never cached.
func (c *Client) ItemTypes(ctx context.Context) ([]model.Type, error) {
	r, err := c.exchange(ctx, &call{method: http.MethodGet, path: "/v1/capabilities"})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCapabilitiesUnknown, err)
	}
	switch r.status {
	case http.StatusOK:
	case http.StatusNotFound:
		return slices.Clone(rev16Types), nil
	default:
		return nil, fmt.Errorf("%w: status %d", ErrCapabilitiesUnknown, r.status)
	}
	return parseCapabilities(r.body)
}

func parseCapabilities(body []byte) ([]model.Type, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("%w: the answer is not a JSON object", ErrCapabilitiesUnknown)
	}
	var v json.Number
	if raw, ok := obj["v"]; !ok || json.Unmarshal(raw, &v) != nil {
		return nil, fmt.Errorf("%w: no version", ErrCapabilitiesUnknown)
	}
	n, err := v.Int64()
	switch {
	case err != nil || n < 1:
		return nil, fmt.Errorf("%w: version %s", ErrCapabilitiesUnknown, v)
	case n > 1:
		return nil, ErrCapabilitiesNewer
	}
	var names []string
	if raw, ok := obj["item_types"]; !ok || json.Unmarshal(raw, &names) != nil || names == nil {
		return nil, fmt.Errorf("%w: no item_types list", ErrCapabilitiesUnknown)
	}
	known := map[model.Type]bool{}
	for _, t := range append(slices.Clone(rev16Types), model.TypeAccess) {
		known[t] = true
	}
	var out []model.Type
	for _, s := range names {
		if t := model.Type(s); known[t] && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return out, nil
}

// ItemTypes is the publication preflight's capabilities check: the server
// the vault is being published to.
func (p *Publisher) ItemTypes(ctx context.Context) ([]model.Type, error) { return p.c.ItemTypes(ctx) }
