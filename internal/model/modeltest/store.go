// Package modeltest is an in-memory model.Store for tests and for the
// development store behind the hopdev build tag. It keeps the rules the real
// store enforces that callers depend on: IDs and versions, type checks on
// replace, and reference integrity on Put and Delete. It does not encrypt
// anything.
package modeltest

import (
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/dalyem/hopkey/internal/access"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// Store is an in-memory model.Store. The zero value is ready to use.
type Store struct {
	// Persist, if set, is called with the new contents after every change
	// while the store is locked. If it fails the change is rolled back and
	// the error is returned to the caller.
	Persist func(model.Snapshot) error

	// DeviceID is the device the store stamps on access records (by).
	// Zero means DefaultDeviceID.
	DeviceID model.ID

	// PutAccessHook, if set, sees each PutAccess first; an error it
	// returns fails the put, as a vault that refuses a write does.
	PutAccessHook atomic.Pointer[func(model.Access) error]

	mu     sync.Mutex
	snap   model.Snapshot
	writes int
}

// DefaultDeviceID is the device a Store stamps by default.
var DefaultDeviceID = model.ID{0xde, 0x71, 0xce}

var _ model.Store = (*Store)(nil)

// New returns an empty store.
func New() *Store { return &Store{} }

// NewFrom returns a store holding a copy of snap. Items must already carry IDs.
func NewFrom(snap model.Snapshot) *Store { return &Store{snap: cloneSnapshot(snap)} }

// Writes reports how many successful changes (Put or Delete) the store has
// seen. Tests use it to check that a read-only operation wrote nothing.
func (s *Store) Writes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

func (s *Store) Snapshot(context.Context) (model.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneSnapshot(s.snap), nil
}

func (s *Store) PutHost(_ context.Context, h model.Host) (model.Host, error) {
	h = normalizeHost(h)
	if err := validateHost(h); err != nil {
		return model.Host{}, err
	}
	return put(s, h, model.TypeHost, func(sn *model.Snapshot) *[]model.Host { return &sn.Hosts }, func(h *model.Host) *model.Header { return &h.Header })
}

func (s *Store) PutKey(_ context.Context, k model.Key) (model.Key, error) {
	if k.Name == "" || k.PrivateKey == "" || k.PublicKey == "" {
		return model.Key{}, fmt.Errorf("modeltest: key needs a name, private_key and public_key")
	}
	switch k.KeyType {
	case "ed25519", "ecdsa-p256", "rsa":
	default:
		return model.Key{}, fmt.Errorf("modeltest: unknown key_type %q", k.KeyType)
	}
	return put(s, k, model.TypeKey, func(sn *model.Snapshot) *[]model.Key { return &sn.Keys }, func(k *model.Key) *model.Header { return &k.Header })
}

func (s *Store) PutCredential(_ context.Context, c model.Credential) (model.Credential, error) {
	return put(s, c, model.TypeCredential, func(sn *model.Snapshot) *[]model.Credential { return &sn.Credentials }, func(c *model.Credential) *model.Header { return &c.Header })
}

func (s *Store) PutSnippet(_ context.Context, sn model.Snippet) (model.Snippet, error) {
	if sn.Params == nil {
		sn.Params = []string{}
	}
	return put(s, sn, model.TypeSnippet, func(x *model.Snapshot) *[]model.Snippet { return &x.Snippets }, func(sn *model.Snippet) *model.Header { return &sn.Header })
}

func (s *Store) Delete(_ context.Context, id model.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneSnapshot(s.snap)
	found := false
	next.Hosts = without(next.Hosts, id, &found, func(h *model.Host) *model.Header { return &h.Header })
	next.Keys = without(next.Keys, id, &found, func(k *model.Key) *model.Header { return &k.Header })
	next.Credentials = without(next.Credentials, id, &found, func(c *model.Credential) *model.Header { return &c.Header })
	next.Snippets = without(next.Snippets, id, &found, func(sn *model.Snippet) *model.Header { return &sn.Header })
	next.Access = without(next.Access, id, &found, func(a *model.Access) *model.Header { return &a.Header })
	if !found {
		return model.ErrNotFound
	}
	if err := checkRefs(next); err != nil {
		return err
	}
	return s.commit(next)
}

// without drops the item with the given id from list, setting *found if it
// was there.
func without[T any](list []T, id model.ID, found *bool, header func(*T) *model.Header) []T {
	return slices.DeleteFunc(list, func(x T) bool {
		if header(&x).ItemID != id {
			return false
		}
		*found = true
		return true
	})
}

// put creates or replaces one item of type T in the list that list selects.
func put[T any](s *Store, v T, typ model.Type, list func(*model.Snapshot) *[]T, header func(*T) *model.Header) (T, error) {
	var zero T
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneSnapshot(s.snap)
	items := list(&next)
	h := header(&v)

	idx := -1
	if h.ItemID.IsZero() {
		var id model.ID
		if _, err := rand.Read(id[:]); err != nil {
			return zero, err
		}
		h.ItemID, h.ItemVersion = id, 1
	} else {
		idx = slices.IndexFunc(*items, func(x T) bool { return header(&x).ItemID == h.ItemID })
		switch {
		case idx < 0 && holdsID(next, h.ItemID):
			return zero, fmt.Errorf("modeltest: item %s is not a %s", h.ItemID, typ)
		case idx < 0:
			return zero, model.ErrNotFound
		}
		if cur := header(&(*items)[idx]).ItemVersion; h.ItemVersion != cur {
			return zero, fmt.Errorf("modeltest: item %s is at version %d, not %d", h.ItemID, cur, h.ItemVersion)
		}
		h.ItemVersion++
	}
	h.V, h.Type = 1, typ

	if idx >= 0 {
		(*items)[idx] = v
	} else {
		*items = append(*items, v)
	}
	if err := checkRefs(next); err != nil {
		return zero, err
	}
	if err := s.commit(next); err != nil {
		return zero, err
	}
	// Hand back a copy, so a caller cannot reach into the store.
	out := cloneSnapshot(next)
	for _, x := range *list(&out) {
		if header(&x).ItemID == h.ItemID {
			return x, nil
		}
	}
	return v, nil
}

func (s *Store) commit(next model.Snapshot) error {
	if s.Persist != nil {
		if err := s.Persist(cloneSnapshot(next)); err != nil {
			return err
		}
	}
	s.snap = next
	s.writes++
	return nil
}

func holdsID(snap model.Snapshot, id model.ID) bool {
	return slices.ContainsFunc(snap.Hosts, func(x model.Host) bool { return x.ItemID == id }) ||
		slices.ContainsFunc(snap.Keys, func(x model.Key) bool { return x.ItemID == id }) ||
		slices.ContainsFunc(snap.Credentials, func(x model.Credential) bool { return x.ItemID == id }) ||
		slices.ContainsFunc(snap.Snippets, func(x model.Snippet) bool { return x.ItemID == id }) ||
		slices.ContainsFunc(snap.Access, func(x model.Access) bool { return x.ItemID == id })
}

func normalizeHost(h model.Host) model.Host {
	h = cloneHost(h)
	if h.Aliases == nil {
		h.Aliases = []string{}
	}
	if h.Addresses == nil {
		h.Addresses = []string{}
	}
	if h.Tags == nil {
		h.Tags = []string{}
	}
	if h.HostKeys == nil {
		h.HostKeys = []string{}
	}
	return h
}

func validateHost(h model.Host) error {
	switch {
	case h.Name == "":
		return fmt.Errorf("modeltest: host needs a name")
	case h.Port > 65535:
		return fmt.Errorf("modeltest: host %q: invalid port %d", h.Name, h.Port)
	case h.Route != "auto" && h.Route != "tailnet" && h.Route != "direct":
		return fmt.Errorf("modeltest: host %q: invalid route %q", h.Name, h.Route)
	case h.AgentAccess != "allow" && h.AgentAccess != "deny":
		return fmt.Errorf("modeltest: host %q: invalid agent_access %q", h.Name, h.AgentAccess)
	case h.AgentOutput != "" && h.AgentOutput != model.AgentOutputFull && h.AgentOutput != model.AgentOutputNone:
		return fmt.Errorf("modeltest: host %q: invalid agent_output %q", h.Name, h.AgentOutput)
	}
	if t := h.Tailscale; t != nil && t.SSH != "yes" && t.SSH != "no" && t.SSH != "unknown" {
		return fmt.Errorf("modeltest: host %q: invalid tailscale.ssh %q", h.Name, t.SSH)
	}
	return nil
}

// checkRefs enforces reference integrity: every key_id, credential_id and
// jump_host_id names a live item of the right type, and jump hosts form no
// loop.
func checkRefs(snap model.Snapshot) error {
	hosts := map[model.ID]model.Host{}
	for _, h := range snap.Hosts {
		hosts[h.ItemID] = h
	}
	for _, h := range snap.Hosts {
		if !h.KeyID.IsZero() && !slices.ContainsFunc(snap.Keys, func(k model.Key) bool { return k.ItemID == h.KeyID }) {
			return fmt.Errorf("modeltest: host %q refers to missing key %s", h.Name, h.KeyID)
		}
		if !h.CredentialID.IsZero() && !slices.ContainsFunc(snap.Credentials, func(c model.Credential) bool { return c.ItemID == h.CredentialID }) {
			return fmt.Errorf("modeltest: host %q refers to missing credential %s", h.Name, h.CredentialID)
		}
		seen := map[model.ID]bool{h.ItemID: true}
		for cur := h; !cur.JumpHostID.IsZero(); {
			next, ok := hosts[cur.JumpHostID]
			if !ok {
				return fmt.Errorf("modeltest: host %q refers to missing jump host %s", cur.Name, cur.JumpHostID)
			}
			if seen[next.ItemID] {
				return fmt.Errorf("modeltest: host %q has a jump host loop", h.Name)
			}
			seen[next.ItemID] = true
			cur = next
		}
	}
	return nil
}

func cloneSnapshot(s model.Snapshot) model.Snapshot {
	out := model.Snapshot{}
	for _, h := range s.Hosts {
		out.Hosts = append(out.Hosts, cloneHost(h))
	}
	out.Keys = slices.Clone(s.Keys)
	out.Credentials = slices.Clone(s.Credentials)
	for _, sn := range s.Snippets {
		sn.Params = slices.Clone(sn.Params)
		out.Snippets = append(out.Snippets, sn)
	}
	for _, a := range s.Access {
		out.Access = append(out.Access, *access.Clone(&a))
	}
	return out
}

// PutAccess creates or replaces an access record, stamped with DeviceID,
// after the schema and V_access (crypto spec rev 17, §5.1).
func (s *Store) PutAccess(_ context.Context, a model.Access) (model.Access, error) {
	if f := s.PutAccessHook.Load(); f != nil {
		if err := (*f)(a); err != nil {
			return model.Access{}, err
		}
	}
	a = *access.Clone(&a)
	a.By = s.DeviceID
	if a.By.IsZero() {
		a.By = DefaultDeviceID
	}
	check := a
	if check.ItemID.IsZero() {
		check.ItemID = model.ID{1}
	}
	check.V, check.Type = 1, model.TypeAccess
	if err := crypto.ValidateAccess(&check); err != nil {
		return model.Access{}, err
	}
	var cur *model.Access
	s.mu.Lock()
	for i := range s.snap.Access {
		o := &s.snap.Access[i]
		switch {
		case !a.ItemID.IsZero() && o.ItemID == a.ItemID:
			cur = access.Clone(o)
		case model.NameKey(o.Label) == model.NameKey(a.Label):
			// Labels are unique among live records under K_alias (§5.1).
			s.mu.Unlock()
			return model.Access{}, fmt.Errorf("modeltest: another hop access record has the label %q", o.Label)
		}
	}
	s.mu.Unlock()
	if err := access.Check(cur, &a, access.PathWrite); err != nil {
		return model.Access{}, err
	}
	return put(s, a, model.TypeAccess, func(sn *model.Snapshot) *[]model.Access { return &sn.Access }, func(a *model.Access) *model.Header { return &a.Header })
}

// InjectAccess stores a as it is, with a new item ID and none of
// PutAccess's checks: a record an older or foreign writer put, which the
// log took, since only writers keep labels unique (§5.1). It returns the
// record as stored.
func (s *Store) InjectAccess(a model.Access) model.Access {
	a = *access.Clone(&a)
	rand.Read(a.ItemID[:])
	a.V, a.Type, a.ItemVersion = 1, model.TypeAccess, 1
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snap.Access = append(s.snap.Access, a)
	s.writes++
	return a
}

// DeleteAccess deletes an access record whose targets are all terminal,
// and removed unless forget.
func (s *Store) DeleteAccess(ctx context.Context, id model.ID, forget bool) error {
	s.mu.Lock()
	var cur *model.Access
	for i := range s.snap.Access {
		if s.snap.Access[i].ItemID == id {
			cur = access.Clone(&s.snap.Access[i])
		}
	}
	s.mu.Unlock()
	if cur == nil {
		return model.ErrNotFound
	}
	if err := access.CheckDelete(cur, forget); err != nil {
		return err
	}
	return s.Delete(ctx, id)
}

func cloneHost(h model.Host) model.Host {
	h.Aliases = slices.Clone(h.Aliases)
	h.Addresses = slices.Clone(h.Addresses)
	h.Tags = slices.Clone(h.Tags)
	h.HostKeys = slices.Clone(h.HostKeys)
	if h.Tailscale != nil {
		t := *h.Tailscale
		h.Tailscale = &t
	}
	return h
}
