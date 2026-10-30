package server

import (
	"bytes"
	"context"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/dalyem/hopkey/internal/model"
)

// Last seen (hop auth devices): every request a device authenticates with
// its session records the time, at most once a minute per device. The
// write happens in the background, so no request waits on it and none
// takes the write lock for it while it holds a read transaction or an
// account's admission lock.

// seenEvery is how often a device's last seen time is written at most.
const seenEvery = time.Minute

type deviceKey struct{ account, device model.ID }

// seenTracker holds the last seen times not written yet.
type seenTracker struct {
	mu      sync.Mutex
	queued  map[deviceKey]time.Time // the last time queued, per device, within seenEvery
	pending map[deviceKey]time.Time // not written yet
	wake    chan struct{}
}

func newSeenTracker() *seenTracker {
	return &seenTracker{queued: map[deviceKey]time.Time{}, pending: map[deviceKey]time.Time{}, wake: make(chan struct{}, 1)}
}

// noteSeen records that a device authenticated now, unless it did less
// than seenEvery ago.
func (s *Server) noteSeen(accountID, deviceID model.ID) {
	now := s.now()
	k := deviceKey{accountID, deviceID}
	t := s.seen
	t.mu.Lock()
	if last, ok := t.queued[k]; ok && !now.Before(last) && now.Sub(last) < seenEvery {
		t.mu.Unlock()
		return
	}
	t.queued[k], t.pending[k] = now, now
	t.mu.Unlock()
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

// seenWriter writes the pending last seen times until the server stops,
// and once more then.
func (s *Server) seenWriter() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stop:
			s.flushSeen()
			return
		case <-s.seen.wake:
			s.flushSeen()
		}
	}
}

func (s *Server) flushSeen() {
	t := s.seen
	t.mu.Lock()
	batch := t.pending
	t.pending = map[deviceKey]time.Time{}
	now := s.now()
	for k, last := range t.queued {
		if now.Sub(last) >= seenEvery {
			delete(t.queued, k)
		}
	}
	t.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	err := s.store.Update(context.Background(), func(tx Tx) error {
		for k, at := range batch {
			if err := tx.SetDeviceSeen(k.account, k.device, at); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.log.Error("recording when devices were last seen", "err", err)
	}
}

// devicesSeenResponse answers getDevicesSeen.
type devicesSeenResponse struct {
	Devices []deviceSeen `json:"devices"`
}

type deviceSeen struct {
	DeviceID model.ID        `json:"device_id"`
	SeenAt   model.Timestamp `json:"seen_at"`
}

// getDevicesSeen: GET /v1/vaults/{id}/devices/seen →
// {devices:[{device_id, seen_at}]}: when each device of the account last
// made a request with its session, to within seenEvery. A device that
// never did is not listed.
func (s *Server) getDevicesSeen(w http.ResponseWriter, r *http.Request, c *call) error {
	tok, ok := bearer(r)
	if !ok {
		return errUnauthorized
	}
	vaultID, okV := parseID(r.PathValue("vault"))
	var seen map[model.ID]time.Time
	err := s.store.View(r.Context(), func(tx Tx) error {
		p, err := s.vaultAuth(tx, tok, vaultID, okV)
		if err != nil {
			return err
		}
		if err := s.accountBucket(c, p); err != nil {
			return err
		}
		seen, err = tx.DevicesSeen(p.accountID)
		return err
	})
	if err != nil {
		return err
	}
	resp := devicesSeenResponse{Devices: []deviceSeen{}}
	for id, at := range seen {
		resp.Devices = append(resp.Devices, deviceSeen{DeviceID: id, SeenAt: model.TimestampOf(at)})
	}
	slices.SortFunc(resp.Devices, func(a, b deviceSeen) int { return bytes.Compare(a.DeviceID[:], b.DeviceID[:]) })
	writeJSON(w, http.StatusOK, resp)
	return nil
}
