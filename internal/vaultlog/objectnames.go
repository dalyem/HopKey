package vaultlog

import "github.com/dalyem/hopkey/internal/crypto"

// ObjectDigests returns the digest of every object the entry's ops name, in
// op order, without duplicates: both credential blobs, the VK envelope, each
// device_add's unlock blob, each item_put's wrap and body, and each
// bundle_put's envelope. These are the objects the public stage fetches, so
// they are the only ones a server stores with the entry (§5.1).
func (e *Entry) ObjectDigests() []crypto.Hash {
	var out []crypto.Hash
	seen := map[crypto.Hash]bool{}
	add := func(hs ...crypto.Hash) {
		for _, h := range hs {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	for _, o := range e.Ops {
		switch o := o.(type) {
		case *CredsOp:
			add(o.PwBlobSHA256, o.RkBlobSHA256)
		case *VKWrapOp:
			add(o.EnvelopeSHA256)
		case *DeviceAddOp:
			add(o.UnlockSHA256)
		case *ItemPutOp:
			add(o.WrapSHA256, o.BodySHA256)
		case *BundlePutOp:
			add(o.EnvelopeSHA256)
		}
	}
	return out
}
