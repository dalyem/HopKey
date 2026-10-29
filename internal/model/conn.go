package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ConnString is what in h itself decides which server it reaches and how:
// its addresses, port, user, route, Tailscale link, pinned host keys and
// jump host. hop key rotate compares it, for h and each jump host on its
// way, to tell whether a record still reaches the server it checked.
func ConnString(h Host) string {
	ts := "-"
	if t := h.Tailscale; t != nil {
		ts = fmt.Sprintf("%q %q %q", t.StableNodeID, t.DNSName, t.SSH)
	}
	return fmt.Sprintf("%s %q %d %q %q %q %s jump %s", h.ItemID, h.Addresses, h.Port, h.User, h.Route, h.HostKeys, ts, h.JumpHostID)
}

// ConnDigest digests ConnString(h) and, when withKey, the key h names: what
// a conditional write of a host's key (store.PutHostIfChain) requires of
// the host itself (withKey) and of each jump host on its way.
func ConnDigest(h Host, withKey bool) string {
	s := ConnString(h)
	if withKey {
		s += " key " + h.KeyID.String()
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
