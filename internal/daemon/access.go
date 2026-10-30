package daemon

import (
	"context"
	"errors"
	"slices"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// The vault side of hop access (crypto spec rev 17, Part 2). hop mcp never
// calls these, and no other op returns an access record.
const (
	OpAccessList   = "access.list"
	OpAccessPut    = "access.put"
	OpAccessDelete = "access.delete"
	// OpAccessCapabilities checks that the server takes access records
	// (GET /v1/capabilities, §5.3). The answer is never cached.
	OpAccessCapabilities = "access.capabilities"
	// OpAccessReviewAck acknowledges access-review notes hop access ls
	// has shown (§7.5).
	OpAccessReviewAck = "access.review_ack"
)

// CodeAccessUnsupported: the server doesn't list access among its item
// types, or hop couldn't find out.
const CodeAccessUnsupported = "access_unsupported"

// AccessListResult answers OpAccessList: every live access record, as the
// vault shows it (verified state with this device's queued changes), and
// the records with a queued change (Marks, by item ID).
type AccessListResult struct {
	Access []model.Access        `json:"access"`
	Marks  map[string]model.Mark `json:"marks,omitempty"`
	// Retired lists the devices revoked or retired from the account, for
	// attributing records (by) to them.
	Retired []string `json:"retired,omitempty"`
	// Local is true for a vault with no server.
	Local bool `json:"local"`
	// Reviews are the access-review notes not yet acknowledged: a
	// checkpoint revoked the devices that last changed these records.
	// ReviewsEvicted counts older ones dropped undelivered.
	Reviews        []AccessReview `json:"reviews,omitempty"`
	ReviewsEvicted uint64         `json:"reviews_evicted,omitempty"`
}

// AccessReview is one access-review note.
type AccessReview struct {
	ID            uint64             `json:"id"`
	CheckpointSeq uint64             `json:"checkpoint_seq"`
	Devices       []string           `json:"devices"`
	Items         []AccessReviewItem `json:"items"`
	// Text is the note as hop status shows it.
	Text string `json:"text"`
}

// AccessReviewItem is a record an AccessReview names.
type AccessReviewItem struct {
	ItemID string `json:"item_id"`
	Label  string `json:"label"`
}

// AccessReviewAckParams acknowledges the notes of one AccessListResult:
// exactly those IDs, and the evicted count it reported.
type AccessReviewAckParams struct {
	IDs     []uint64 `json:"ids"`
	Evicted uint64   `json:"evicted,omitempty"`
}

// AccessPutParams is the request of OpAccessPut.
type AccessPutParams struct {
	Access model.Access `json:"access"`
}

// AccessDeleteParams is the request of OpAccessDelete. Forget deletes a
// record with abandoned targets. RecordID, when set, must be the record
// ID of item ID: a run deletes only the record it acted for.
type AccessDeleteParams struct {
	ID       string `json:"id"`
	RecordID string `json:"record_id,omitempty"`
	Forget   bool   `json:"forget"`
}

// AccessCapabilitiesResult answers OpAccessCapabilities when access
// records may be written.
type AccessCapabilitiesResult struct {
	Local bool `json:"local"`
}

// accessStore is the store's access writer.
type accessStore interface {
	PutAccess(ctx context.Context, a model.Access) (model.Access, error)
	DeleteAccess(ctx context.Context, id model.ID, forget bool) error
}

// retiredLister is a store that knows the account's retired devices.
type retiredLister interface {
	RetiredDevices() []model.ID
}

func (d *Daemon) dispatchAccess(ctx context.Context, req Request, decode func(any) error) (any, bool, error) {
	switch req.Op {
	case OpAccessList:
		res, err := d.opAccessList(ctx)
		return res, true, err
	case OpAccessPut:
		var p AccessPutParams
		if err := decode(&p); err != nil {
			return nil, true, err
		}
		res, err := d.opAccessPut(ctx, p)
		return res, true, err
	case OpAccessDelete:
		var p AccessDeleteParams
		if err := decode(&p); err != nil {
			return nil, true, err
		}
		return nil, true, d.opAccessDelete(ctx, p)
	case OpAccessCapabilities:
		res, err := d.accessCapabilities(ctx)
		return res, true, err
	case OpAccessReviewAck:
		var p AccessReviewAckParams
		if err := decode(&p); err != nil {
			return nil, true, err
		}
		return nil, true, d.opAccessReviewAck(p)
	}
	return nil, false, nil
}

func (d *Daemon) accessWriter() (accessStore, error) {
	as, ok := d.store.(accessStore)
	if !ok {
		return nil, invalidf("this vault store does not hold hop access records")
	}
	return as, nil
}

func (d *Daemon) opAccessList(ctx context.Context) (*AccessListResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	snap, err := d.store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	out := &AccessListResult{Access: snap.Access, Local: d.sync == nil}
	if out.Access == nil {
		out.Access = []model.Access{}
	}
	for _, a := range snap.Access {
		if m, ok := snap.Marks[a.ItemID]; ok {
			if out.Marks == nil {
				out.Marks = map[string]model.Mark{}
			}
			out.Marks[a.ItemID.String()] = m
		}
	}
	if rl, ok := d.store.(retiredLister); ok {
		for _, id := range rl.RetiredDevices() {
			out.Retired = append(out.Retired, id.String())
		}
	}
	if d.sync != nil {
		if ns, err := d.sync.st.SyncNotes(); err == nil {
			out.ReviewsEvicted = ns.Evicted[store.NoteAccessReview]
			for _, r := range ns.AccessReviews {
				v := AccessReview{ID: r.ID, CheckpointSeq: r.CheckpointSeq, Devices: []string{}, Items: []AccessReviewItem{}, Text: AccessReviewText(r)}
				for _, id := range r.Devices {
					v.Devices = append(v.Devices, id.String())
				}
				for _, it := range r.Items {
					v.Items = append(v.Items, AccessReviewItem{ItemID: it.ItemID.String(), Label: it.Label})
				}
				out.Reviews = append(out.Reviews, v)
			}
		}
	}
	return out, nil
}

func (d *Daemon) opAccessReviewAck(p AccessReviewAckParams) error {
	if d.sync == nil || (len(p.IDs) == 0 && p.Evicted == 0) {
		return nil
	}
	n := store.SyncNotes{}
	for _, id := range p.IDs {
		n.AccessReviews = append(n.AccessReviews, store.AccessReviewNote{ID: id})
	}
	if p.Evicted > 0 {
		n.Evicted = map[string]uint64{store.NoteAccessReview: p.Evicted}
	}
	if err := d.sync.st.AckSyncNotes(n); err != nil {
		return storeError(err)
	}
	return nil
}

func (d *Daemon) opAccessPut(ctx context.Context, p AccessPutParams) (*model.Access, error) {
	as, err := d.accessWriter()
	if err != nil {
		return nil, err
	}
	// A create is journaled only once the server says it takes access
	// records (§5.3).
	if p.Access.ItemID.IsZero() {
		if _, err := d.accessCapabilities(ctx); err != nil {
			return nil, err
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	saved, err := as.PutAccess(ctx, p.Access)
	if err != nil {
		return nil, storeError(err)
	}
	d.localWrite()
	return &saved, nil
}

func (d *Daemon) opAccessDelete(ctx context.Context, p AccessDeleteParams) error {
	id, err := model.ParseID(p.ID)
	if err != nil {
		return invalidf("%v", err)
	}
	as, err := d.accessWriter()
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if p.RecordID != "" {
		rid, err := model.ParseID(p.RecordID)
		if err != nil {
			return invalidf("%v", err)
		}
		snap, err := d.store.Snapshot(ctx)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(snap.Access, func(a model.Access) bool { return a.ItemID == id })
		if i < 0 || snap.Access[i].RecordID != rid {
			return storeError(model.ErrNotFound)
		}
	}
	if err := as.DeleteAccess(ctx, id, p.Forget); err != nil {
		return storeError(err)
	}
	d.localWrite()
	return nil
}

// accessCapabilities is the §5.3 check: a local-only vault needs none; a
// server-backed one asks its server, every time.
func (d *Daemon) accessCapabilities(ctx context.Context) (*AccessCapabilitiesResult, error) {
	if d.sync == nil {
		return &AccessCapabilitiesResult{Local: true}, nil
	}
	info, err := d.sync.st.ServerInfo()
	if errors.Is(err, store.ErrNotServerBacked) {
		return &AccessCapabilitiesResult{Local: true}, nil
	}
	if err != nil {
		return nil, err
	}
	c, err := d.sync.client(info.Server)
	if err != nil {
		return nil, &Error{Code: CodeAccessUnsupported, Message: syncclient.ErrCapabilitiesUnknown.Error()}
	}
	types, err := c.ItemTypes(ctx)
	switch {
	case errors.Is(err, syncclient.ErrCapabilitiesNewer):
		return nil, &Error{Code: CodeAccessUnsupported, Message: err.Error()}
	case err != nil:
		return nil, &Error{Code: CodeAccessUnsupported, Message: syncclient.ErrCapabilitiesUnknown.Error()}
	case !slices.Contains(types, model.TypeAccess):
		return nil, &Error{Code: CodeAccessUnsupported, Message: "the server doesn't accept hop access records; upgrade hop-server"}
	}
	return &AccessCapabilitiesResult{}, nil
}
