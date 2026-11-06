package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// crashAt returns a test hook that fails the first time stage is reached.
func crashAt(stage string) func(string) error {
	done := false
	return func(s string) error {
		if s == stage && !done {
			done = true
			return errCrash
		}
		return nil
	}
}

func walExists(t *testing.T, cfg Config) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(cfg.DataDir, "vault", "wal.json"))
	return err == nil
}

// notJournaled reports whether a crash at stage comes before wal.json is
// renamed into place: the commit then did not happen, and the store stays
// unlocked.
func notJournaled(stage string) bool { return stage == "wal:before" || stage == "wal:install" }

// §13: write-ahead journal replay after a crash in each multi-file commit.
// A pull that verifies an entry commits the entry, state.json and the
// deletion of the outbox record it settles together: a crash at any
// durable step, or a failed fsync after it, leaves all of them or none.
func TestWALReplayVerifiedCommit(t *testing.T) {
	for _, stage := range []string{"wal:before", "wal:install", "wal:install:sync", "wal:written",
		"wal:op:0", "wal:op:0:sync", "wal:op:1", "wal:op:1:sync", "wal:op:2", "wal:op:2:sync", "wal:applied", "wal:removed"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			f, r := serverVault(t)
			s := f.s
			_, h := addHost(t, s, "web")
			pushAll(t, s, r)
			editHost(t, s, h.ItemID, func(h *model.Host) { h.Description = "edited" })
			// The post commits but the response is lost: the candidate is
			// live until a pull verifies it.
			r.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
			if _, err := s.PushHead(ctx, r); !errors.Is(err, errLostResponse) {
				t.Fatal(err)
			}
			r.onPost = nil
			before := headOf(t, s)
			if len(records(t, s)) != 1 {
				t.Fatal("setup: no record")
			}

			s.testHook = crashAt(stage)
			if err := s.Pull(ctx, r); !errors.Is(err, errCrash) {
				t.Fatalf("pull with a crash at %s: %v", stage, err)
			}
			if _, err := s.Snapshot(ctx); notJournaled(stage) != (err == nil) {
				t.Errorf("after a crash at %s: snapshot %v", stage, err)
			} else if err != nil && !errors.Is(err, model.ErrLocked) {
				t.Errorf("an interrupted commit left the store unlocked: %v", err)
			}
			s = open(t, f.cfg)
			recs := records(t, s)
			switch got := headOf(t, s); {
			case notJournaled(stage):
				if got != before || len(recs) != 1 || recs[0].live() == nil {
					t.Errorf("nothing journaled, yet head %d and %d records", got.Seq, len(recs))
				}
			default:
				if got.Seq != before.Seq+1 || len(recs) != 0 {
					t.Errorf("journaled commit not finished: head %d (was %d), %d records", got.Seq, before.Seq, len(recs))
				}
			}
			if walExists(t, f.cfg) {
				t.Error("wal.json is still there after the replay")
			}
			if res := pushAll(t, s, r); res.Outcome != PushEmpty {
				t.Fatalf("push: %+v", res)
			}
			if got, _ := verifiedHost(t, s, h.ItemID); got.Description != "edited" || headOf(t, s).Seq != r.head().Seq {
				t.Errorf("after recovery: %+v at %d", got, headOf(t, s).Seq)
			}
		})
	}
}

// Appending a record writes it together with the outbox counter.
func TestWALReplayAppend(t *testing.T) {
	for _, stage := range []string{"wal:before", "wal:install", "wal:install:sync", "wal:written",
		"wal:op:0", "wal:op:0:sync", "wal:op:1", "wal:op:1:sync", "wal:applied", "wal:removed"} {
		t.Run(stage, func(t *testing.T) {
			f, _ := serverVault(t)
			s := f.s
			s.testHook = crashAt(stage)
			if _, err := s.PutCredential(context.Background(), model.Credential{Name: "c", Username: "u", Password: "p"}); !errors.Is(err, errCrash) {
				t.Fatalf("put with a crash at %s: %v", stage, err)
			}
			s = open(t, f.cfg)
			m, err := s.readOutboxMeta()
			if err != nil {
				t.Fatal(err)
			}
			recs := records(t, s)
			if notJournaled(stage) {
				if len(recs) != 0 || m.Next != 1 {
					t.Errorf("nothing journaled, yet %d records, next %d", len(recs), m.Next)
				}
			} else if len(recs) != 1 || recs[0].N != 1 || m.Next != 2 {
				t.Errorf("journaled append not finished: %d records, next %d", len(recs), m.Next)
			}
			if c := newCredential(t, s, "d"); c.Name != "d" {
				t.Fatal(c)
			}
			if recs := records(t, s); recs[len(recs)-1].N != uint64(len(recs)) {
				t.Errorf("record numbers %d", recs[len(recs)-1].N)
			}
		})
	}
}

// A journal that hop did not write fails closed: one that does not parse,
// and one that names a path outside the vault.
func TestWALRefusesAForeignJournal(t *testing.T) {
	f, _ := serverVault(t)
	path := filepath.Join(f.cfg.DataDir, "vault", "wal.json")
	for name, body := range map[string]string{
		"garbage":           "{",
		"unknown member":    `{"v":1,"ops":[{"op":"delete","path":"outbox/1.json","data":""}],"x":1}`,
		"escaping path":     `{"v":1,"ops":[{"op":"delete","path":"../device.json","data":""}]}`,
		"the journal":       `{"v":1,"ops":[{"op":"delete","path":"wal.json","data":""}]}`,
		"unknown operation": `{"v":1,"ops":[{"op":"chmod","path":"state.json","data":""}]}`,
		"no operations":     `{"v":1,"ops":[]}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := tryOpen(t, f.cfg); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: open: %v", name, err)
		}
	}
	// A create that would replace an entry with other bytes fails closed.
	if err := os.WriteFile(path, []byte(`{"v":1,"ops":[{"op":"create","path":"entries/0.json","data":"e30"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tryOpen(t, f.cfg); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a create over an existing entry: %v", err)
	}
	os.Remove(path)
	if _, err := tryOpen(t, f.cfg); err != nil {
		t.Errorf("open without the journal: %v", err)
	}
}
