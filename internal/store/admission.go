package store

import (
	"errors"
	"fmt"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// ErrTooLarge means a candidate entry exceeds what the server admits: an
// object over 1 MiB, a wire over 4 MiB as the server measures it, or too
// many ops or objects (crypto spec rev 17 amendment, §3.1).
var ErrTooLarge = errors.New("store: the change is larger than the server accepts")

// admitWire is the admission preflight (§3.1): before a candidate is
// journaled, it is checked against the server's admission limits, which
// are the publication check's (checkUpload). The wire is measured as the
// server keeps it, with only the objects its entry names. A failure holds
// the record with rule_failure, so nothing is posted.
func admitWire(w *vaultlog.Wire) error {
	if len(w.Entry.Ops) > maxOpsPerWire {
		return fmt.Errorf("%w: the entry has %d ops, at most %d", ErrTooLarge, len(w.Entry.Ops), maxOpsPerWire)
	}
	if len(w.Objects) > maxObjectsPerWire {
		return fmt.Errorf("%w: the entry has %d objects, at most %d", ErrTooLarge, len(w.Objects), maxObjectsPerWire)
	}
	named := map[crypto.Hash]bool{}
	for _, d := range w.Entry.ObjectDigests() {
		named[d] = true
	}
	kept := []vaultlog.Object{}
	for _, o := range w.Objects {
		if !named[o.SHA256] {
			continue
		}
		if len(o.Body) > maxObjectBody {
			return fmt.Errorf("%w: an item would be %s (%d bytes); the server takes at most %s (%d bytes) per item",
				ErrTooLarge, mib(len(o.Body)), len(o.Body), mib(maxObjectBody), maxObjectBody)
		}
		kept = append(kept, o)
	}
	sw := &vaultlog.Wire{Entry: w.Entry, Sigs: w.Sigs, Objects: kept}
	b, err := sw.Marshal()
	if err != nil {
		return err
	}
	n, err := singletonLen(sw, b)
	if err != nil {
		return err
	}
	if n > maxSingletonWire {
		return fmt.Errorf("%w: the change would be %s (%d bytes) as the server measures it; it takes at most %s (%d bytes)",
			ErrTooLarge, mib(n), n, mib(maxSingletonWire), maxSingletonWire)
	}
	return nil
}

func mib(n int) string { return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20)) }
