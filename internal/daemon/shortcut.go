package daemon

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/shellcmd"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// Shortcut ops: hop shortcut writes with put_shortcut and deletes with
// delete; the session panel of hop connect reads its host's panel with
// shortcuts.
const (
	OpPutShortcut = "put_shortcut"
	OpShortcuts   = "shortcuts"
)

// CodeShortcutsUnsupported: the server doesn't list shortcut among its
// item types, or hop could not ask it.
const CodeShortcutsUnsupported = "shortcuts_unsupported"

// PutShortcutParams is the request for OpPutShortcut. A zero ItemID
// creates the shortcut.
type PutShortcutParams struct {
	Shortcut model.Shortcut `json:"shortcut"`
}

// PutShortcutResult answers OpPutShortcut. Hides names the shortcuts of
// the other scope that the saved one keeps out of a panel: global ones in
// its host's panel, for a host shortcut; for a global one, the hosts whose
// own shortcuts keep it out of theirs.
type PutShortcutResult struct {
	Shortcut model.Shortcut  `json:"shortcut"`
	Hides    []ShortcutClash `json:"hides,omitempty"`
	HiddenIn []ShortcutClash `json:"hidden_in,omitempty"`
}

// ShortcutClash is one shortcut of the other scope that clashes with a
// saved one, and the host whose panel it is about.
type ShortcutClash struct {
	Shortcut model.Shortcut `json:"shortcut"`
	HostID   string         `json:"host_id"`
}

// ShortcutsParams is the request for OpShortcuts. An empty HostID asks
// for the panel of a session to no vault host: the global shortcuts.
type ShortcutsParams struct {
	HostID string `json:"host_id,omitempty"`
}

// ShortcutsResult answers OpShortcuts: the host's panel, its own
// shortcuts first (model.EffectiveShortcuts).
type ShortcutsResult struct {
	Panel []PanelShortcut `json:"panel"`
}

// PanelShortcut is one entry of a panel and the shortcuts it hides.
type PanelShortcut struct {
	Shortcut model.Shortcut   `json:"shortcut"`
	Hides    []model.Shortcut `json:"hides,omitempty"`
}

// shortcutStore is the store's shortcut writer.
type shortcutStore interface {
	PutShortcut(ctx context.Context, sc model.Shortcut) (model.Shortcut, error)
}

func (d *Daemon) dispatchShortcut(ctx context.Context, req Request, decode func(any) error) (any, bool, error) {
	switch req.Op {
	case OpPutShortcut:
		var p PutShortcutParams
		if err := decode(&p); err != nil {
			return nil, true, err
		}
		r, err := d.opPutShortcut(ctx, p)
		return r, true, err
	case OpShortcuts:
		var p ShortcutsParams
		if len(req.Params) > 0 && string(req.Params) != "null" {
			if err := decode(&p); err != nil {
				return nil, true, err
			}
		}
		r, err := d.opShortcuts(ctx, p)
		return r, true, err
	}
	return nil, false, nil
}

func (d *Daemon) opShortcuts(ctx context.Context, p ShortcutsParams) (*ShortcutsResult, error) {
	var host model.ID
	if p.HostID != "" {
		id, err := model.ParseID(p.HostID)
		if err != nil {
			return nil, invalidf("host_id: %v", err)
		}
		host = id
	}
	snap, _, err := d.fresh(ctx)
	if err != nil {
		return nil, err
	}
	out := &ShortcutsResult{Panel: []PanelShortcut{}}
	for _, e := range model.EffectiveShortcuts(snap.Shortcuts, host) {
		out.Panel = append(out.Panel, PanelShortcut{Shortcut: e.Shortcut, Hides: e.Hides})
	}
	return out, nil
}

func (d *Daemon) opPutShortcut(ctx context.Context, p PutShortcutParams) (*PutShortcutResult, error) {
	ss, ok := d.store.(shortcutStore)
	if !ok {
		return nil, invalidf("this vault can't hold shortcuts")
	}
	snap, err := d.store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	// A server that took a shortcut once lists the type: a shortcut with
	// no mark is in verified state. Otherwise ask, before taking the lock.
	if !slices.ContainsFunc(snap.Shortcuts, func(s model.Shortcut) bool { return snap.Marks[s.ItemID] == "" }) {
		if err := d.shortcutCapabilities(ctx); err != nil {
			return nil, err
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if snap, err = d.store.Snapshot(ctx); err != nil {
		return nil, err
	}
	sc, err := checkShortcutInput(p.Shortcut, snap)
	if err != nil {
		return nil, err
	}
	saved, err := ss.PutShortcut(ctx, sc)
	if err != nil {
		return nil, storeError(err)
	}
	d.localWrite()
	return shortcutClashes(saved, snap), d.reloadAfter(ctx, "saved")
}

// shortcutCapabilities is the §5.3 check for shortcuts: a local-only vault
// needs none; a server-backed one asks its server.
func (d *Daemon) shortcutCapabilities(ctx context.Context) error {
	if d.sync == nil {
		return nil
	}
	info, err := d.sync.st.ServerInfo()
	if errors.Is(err, store.ErrNotServerBacked) {
		return nil
	}
	if err != nil {
		return err
	}
	unknown := &Error{Code: CodeShortcutsUnsupported, Message: "hop could not check whether the server accepts shortcuts; try again when it can be reached"}
	c, err := d.sync.client(info.Server)
	if err != nil {
		return unknown
	}
	types, err := c.ItemTypes(ctx)
	switch {
	case errors.Is(err, syncclient.ErrCapabilitiesNewer):
		return &Error{Code: CodeShortcutsUnsupported, Message: err.Error()}
	case err != nil:
		return unknown
	case !slices.Contains(types, model.TypeShortcut):
		return &Error{Code: CodeShortcutsUnsupported, Message: "the server doesn't accept shortcuts yet; upgrade hop-server, then every device's hop"}
	}
	return nil
}

// checkShortcutInput refuses a shortcut the panel could not use, or whose
// keys clash with another shortcut of its scope. A clash with the other
// scope is allowed: the host shortcut wins in that host's panel
// (model.EffectiveShortcuts), and the result says so.
func checkShortcutInput(sc model.Shortcut, snap model.Snapshot) (model.Shortcut, error) {
	sc.Name = strings.TrimSpace(sc.Name)
	sc.Description = crypto.CRLFToLF(sc.Description)
	if err := model.CheckShortcutKeys(sc.Keys); err != nil {
		return sc, invalidf("%v", err)
	}
	if strings.ContainsAny(sc.Keys, model.ShortcutReservedKeys) {
		return sc, invalidf("%q is a key of the panel itself; pick another", model.ShortcutReservedKeys)
	}
	if strings.TrimSpace(sc.Command) == "" {
		return sc, invalidf("a shortcut needs a command")
	}
	if strings.ContainsAny(sc.Command, "\r\n") {
		return sc, invalidf("a shortcut's command is one line; for several commands, join them with ; or &&")
	}
	if strings.Contains(sc.Command, "\t") {
		return sc, invalidf("a shortcut's command can't have a tab: typed into the shell, a tab is the completion key; use spaces")
	}
	if len(sc.Command) > model.MaxShortcutCommand {
		return sc, invalidf("the command is longer than %d bytes", model.MaxShortcutCommand)
	}
	if shellcmd.HasPlaceholder(sc.Command) {
		return sc, invalidf("a shortcut can't have {{parameters}}: the panel types the command as it is; use a snippet for that")
	}
	check := sc
	check.V, check.Type, check.ItemID = crypto.Version, model.TypeShortcut, model.ID{1}
	if err := crypto.ValidateShortcut(&check); err != nil {
		return sc, invalidf("%v", err)
	}
	if !sc.HostID.IsZero() && !slices.ContainsFunc(snap.Hosts, func(h model.Host) bool { return h.ItemID == sc.HostID }) {
		return sc, &Error{Code: CodeNotFound, Message: "the shortcut's host is not in the vault"}
	}
	for _, o := range snap.Shortcuts {
		if o.ItemID == sc.ItemID || o.HostID != sc.HostID || !model.ShortcutKeysClash(o.Keys, sc.Keys) {
			continue
		}
		if o.Keys == sc.Keys {
			return sc, invalidf("%s already has a shortcut on %q (%s); remove it first", scopeName(sc, snap), o.Keys, o.Command)
		}
		return sc, invalidf("%q and %q can't both be shortcuts of %s: the panel would run %q before the second key",
			o.Keys, sc.Keys, scopeName(sc, snap), shorter(o.Keys, sc.Keys))
	}
	return sc, nil
}

func shorter(a, b string) string {
	if len(a) < len(b) {
		return a
	}
	return b
}

// scopeName names a shortcut's scope for a message.
func scopeName(sc model.Shortcut, snap model.Snapshot) string {
	if sc.HostID.IsZero() {
		return "the global panel"
	}
	for _, h := range snap.Hosts {
		if h.ItemID == sc.HostID {
			return "host " + h.Name
		}
	}
	return "host " + sc.HostID.String()
}

// shortcutClashes is saved's result with what it hides and what hides it
// in the panels it is in.
func shortcutClashes(saved model.Shortcut, snap model.Snapshot) *PutShortcutResult {
	out := &PutShortcutResult{Shortcut: saved}
	for _, o := range snap.Shortcuts {
		if o.ItemID == saved.ItemID || !model.ShortcutKeysClash(o.Keys, saved.Keys) {
			continue
		}
		switch {
		case !saved.HostID.IsZero() && o.HostID.IsZero():
			out.Hides = append(out.Hides, ShortcutClash{Shortcut: o, HostID: saved.HostID.String()})
		case saved.HostID.IsZero() && !o.HostID.IsZero():
			out.HiddenIn = append(out.HiddenIn, ShortcutClash{Shortcut: o, HostID: o.HostID.String()})
		}
	}
	return out
}

// deleteHostShortcuts deletes the shortcuts of host id before the host
// goes, when with says to, and otherwise refuses while it has any. It is
// a no-op for an item that is not a host. The host's other references are
// checked first, so its shortcuts don't go when the host would then stay.
// The caller holds d.mu.
func (d *Daemon) deleteHostShortcuts(ctx context.Context, snap model.Snapshot, id model.ID, with bool) error {
	if !slices.ContainsFunc(snap.Hosts, func(h model.Host) bool { return h.ItemID == id }) {
		return nil
	}
	var keys []string
	var ids []model.ID
	for _, sc := range snap.Shortcuts {
		if sc.HostID == id {
			keys, ids = append(keys, sc.Keys), append(ids, sc.ItemID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	if !with {
		return invalidf("the host has shortcuts (%s); remove them first with hop shortcut rm KEYS --host HOST, or remove the host with hop rm, which asks to remove them too",
			strings.Join(keys, ", "))
	}
	for _, h := range snap.Hosts {
		if h.ItemID != id && h.JumpHostID == id {
			return invalidf("host %s still uses this host as its jump host; nothing was removed", h.Name)
		}
	}
	for _, sid := range ids {
		if err := d.store.Delete(ctx, sid); err != nil && !errors.Is(err, model.ErrNotFound) {
			d.localWrite()
			return storeError(err)
		}
	}
	d.localWrite()
	return nil
}
