package daemon

import (
	"context"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

// Tests for the second review of the revocation work (d8b3f24): only the
// lock the server left unconfirmed unlocks by itself once the server
// accepts the device, and a refused session stays a refusal when the
// server can't be asked again.

// A hop lock that comes while the sync loop retries an unconfirmed vault
// stays locked, whether it comes once the loop has read that the vault is
// unconfirmed, or before the store's check registers its request. Under a
// server that refuses the device, the store does not label the newer lock
// unconfirmed either, so a later retry does not unlock it.
func TestUnconfirmedRetryNeverUnlocksAManualLock(t *testing.T) {
	for _, at := range []string{"after the eligibility read", "before the check registers"} {
		t.Run(at, func(t *testing.T) {
			x := newSyncSetup(t)
			var hook atomic.Pointer[func()]
			fire := func() {
				if f := hook.Swap(nil); f != nil {
					(*f)()
				}
			}
			o := Options{Sync: SyncOptions{noPoll: true}}
			if at == "after the eligibility read" {
				o.unconfirmedRead = fire
			} else {
				o.beforeCheck = fire
			}
			x.w.startWith(x.n2, x.n2.st, o)
			if k := x.n2.agentKeys(); k != 1 {
				t.Fatalf("setup: the agent serves %d key(s)", k)
			}
			laptop := laptopID(t, x.n2)
			x.n2.pause(true)
			d := x.n2.d
			d.mu.Lock()
			d.unconfirmedLocked(store.ErrServerUnconfirmed)
			d.mu.Unlock()
			if info := x.n2.st.Info(); !info.Locked || !info.ServerUnconfirmed {
				t.Fatalf("setup: the vault is not locked as unconfirmed: %+v", info)
			}
			lock := func() { d.lockVault(d.store.(Vault), false) }
			hook.Store(&lock)

			ctx := context.Background()
			if at == "before the check registers" {
				refuseLaptop(x.w, laptop, model.ID{}, "no receipt")
				if d.retryUnconfirmed(ctx) {
					t.Fatal("the vault unlocked under a server that refuses the device")
				}
				if hook.Load() != nil {
					t.Fatal("setup: the lock did not happen")
				}
				if info := x.n2.st.Info(); !info.Locked || info.ServerUnconfirmed {
					t.Errorf("the manual lock is labelled unconfirmed: %+v", info)
				}
				x.w.intercept.Store(nil)
			}
			if d.retryUnconfirmed(ctx) {
				t.Error("the retry unlocked a vault hop lock locked")
			}
			if hook.Load() != nil {
				t.Fatal("setup: the lock did not happen")
			}
			if !x.n2.st.Info().Locked {
				t.Error("the vault is unlocked")
			}
			if k := x.n2.agentKeys(); k != 0 {
				t.Errorf("the agent serves %d key(s) after hop lock", k)
			}
		})
	}
}

// A pull the server refuses a session (a 401, then a refused challenge)
// locks the vault even when asking the server again gets a 503: the
// refusal was seen, and only an answer that accepts the device undoes it.
// Nothing is recorded or deleted. That holds for the sync loop's pulls
// and for hop sync's.
func TestRefusedSessionLocksWhenTheRecheckIsUnreachable(t *testing.T) {
	for _, path := range []string{"the sync loop", "hop sync"} {
		t.Run(path, func(t *testing.T) {
			x := newSyncSetup(t)
			x.w.start(x.n2, x.n2.st, SyncOptions{noPoll: path == "hop sync"})
			if k := x.n2.agentKeys(); k != 1 {
				t.Fatalf("setup: the agent serves %d key(s)", k)
			}
			const (
				serve = iota
				refuse
				down
			)
			var phase atomic.Int32
			var refused, unavailable atomic.Int32
			x.w.setIntercept(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
				switch phase.Load() {
				case refuse:
					if req.URL.Path == "/v1/auth/challenge" {
						phase.Store(down)
					}
					refused.Add(1)
					return unauthorized(rw)
				case down:
					unavailable.Add(1)
					http.Error(rw, "down for maintenance", http.StatusServiceUnavailable)
					return true
				}
				return false
			})
			phase.Store(refuse)
			if path == "hop sync" {
				x.n2.call(OpSyncNow, nil, nil) // fails: the session was refused
			} else {
				x.n2.d.sync.wake()
			}
			// The round ends once the recheck got its 503: sync backs off,
			// or the vault locked and the agent emptied.
			eventually(t, 10*time.Second, "the recheck after the refused session", func() bool {
				return unavailable.Load() > 0 && (x.n2.status().State == SyncBackingOff || x.n2.agentKeys() == 0)
			})
			if refused.Load() == 0 {
				t.Fatal("setup: nothing was refused")
			}
			if k := x.n2.agentKeys(); k != 0 {
				t.Errorf("after a refused session and an unreachable recheck, the agent serves %d key(s)", k)
			}
			if info := x.n2.st.Info(); !info.Locked || !info.ServerUnconfirmed {
				t.Errorf("the vault is not locked as unconfirmed: %+v", info)
			}
			data := x.n2.cfg.DataDir
			if exists(t, filepath.Join(data, "vault", "server-revoked.json")) {
				t.Error("a report was recorded")
			}
			if !exists(t, filepath.Join(data, "device.json")) || !exists(t, filepath.Join(data, "vault", "state.json")) {
				t.Fatal("the vault was deleted")
			}

			// The server back and accepting the device: the loop unlocks it.
			x.w.intercept.Store(nil)
			x.n2.d.sync.wake()
			eventually(t, 10*time.Second, "the key is back once the server accepts the device", func() bool { return x.n2.agentKeys() == 1 })
		})
	}
}
