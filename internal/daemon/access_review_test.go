package daemon

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

// The access-review warnings of sync.status (crypto spec rev 17, §7.5;
// review r2 #3): a note shows until hop access ls acknowledges it
// (access.list, then access.review_ack), across restarts, whatever other
// notes come after it; once acknowledged it shows no more, also after a
// restart.

// putAccess has n write a new access record labelled label, pending on a
// host that need not exist.
func putAccess(t *testing.T, n *node, label string) model.Access {
	t.Helper()
	k, hk := genKey(t), genKey(t)
	var rid, host model.ID
	rand.Read(rid[:])
	rand.Read(host[:])
	var saved model.Access
	n.must(OpAccessPut, AccessPutParams{Access: model.Access{
		Label: label, RecordID: rid, PublicKey: k.line(), Fingerprint: ssh.FingerprintSHA256(k.pub),
		Options: model.AccessOptions{From: []string{}},
		Targets: []model.AccessTarget{{HostItemID: host, User: "root", ServerKeyFP: ssh.FingerprintSHA256(hk.pub), Gen: 1, State: model.AccessPending, Time: 1}},
	}}, &saved)
	return saved
}

// reviewWarnings are n's status warnings that are access-review notes.
func reviewWarnings(n *node) []string {
	var out []string
	for _, w := range n.status().Warnings {
		if strings.Contains(w, "hop access record") {
			out = append(out, w)
		}
	}
	return out
}

// restartNode stops n's daemon, opens its store again and starts a new
// daemon over it.
func (w *syncWorld) restartNode(n *node) {
	t := n.t
	t.Helper()
	n.c.Close()
	n.d.Close()
	st, err := store.Open(context.Background(), n.cfg)
	if err != nil {
		t.Fatal(err)
	}
	n.st = st
	w.start(n, st, SyncOptions{})
}

func TestAccessReviewWarningUntilAcknowledged(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	x.n1.must(OpSyncNow, nil, nil)
	x.n2.must(OpSyncNow, nil, nil)
	alice := putAccess(t, x.n2, "alice")
	x.n2.must(OpSyncNow, nil, nil)
	x.n1.must(OpSyncNow, nil, nil)
	x.revokeLaptop(t)
	x.n1.must(OpSyncNow, nil, nil)

	eventually(t, 10*time.Second, "the desk shows the note", func() bool { return len(reviewWarnings(x.n1)) == 1 })
	if w := reviewWarnings(x.n1)[0]; !strings.Contains(w, `"alice"`) || !strings.Contains(w, "at that checkpoint") {
		t.Fatalf("warning %q", w)
	}

	// Newer notes, more than the history keeps, don't push it out.
	for i := range maxReplacedNotes + 3 {
		x.n1.d.sync.addNote(fmt.Sprintf("note %d of another kind", i))
	}
	if got := reviewWarnings(x.n1); len(got) != 1 {
		t.Fatalf("after %d newer notes: %q", maxReplacedNotes+3, got)
	}

	// A restart brings it back: it isn't acknowledged.
	x.w.restartNode(x.n1)
	x.n1.must(OpSyncNow, nil, nil)
	eventually(t, 10*time.Second, "the note after a restart", func() bool { return len(reviewWarnings(x.n1)) == 1 })

	// hop access ls: list, then acknowledge exactly what it showed.
	var l AccessListResult
	x.n1.must(OpAccessList, nil, &l)
	if len(l.Reviews) != 1 || len(l.Reviews[0].Items) != 1 || l.Reviews[0].Items[0].ItemID != alice.ItemID.String() {
		t.Fatalf("access.list reviews %+v", l.Reviews)
	}
	x.n1.must(OpAccessReviewAck, AccessReviewAckParams{IDs: []uint64{l.Reviews[0].ID}}, nil)
	if got := reviewWarnings(x.n1); len(got) != 0 {
		t.Fatalf("status after the acknowledgement: %q", got)
	}
	var after AccessListResult // reviews is omitempty: decode into a new value
	x.n1.must(OpAccessList, nil, &after)
	if len(after.Reviews) != 0 {
		t.Fatalf("access.list after the acknowledgement: %+v", after.Reviews)
	}
	// And it stays gone after a sync and a restart.
	x.n1.must(OpSyncNow, nil, nil)
	x.w.restartNode(x.n1)
	x.n1.must(OpSyncNow, nil, nil)
	if got := reviewWarnings(x.n1); len(got) != 0 {
		t.Fatalf("status after a restart: %q", got)
	}
}
