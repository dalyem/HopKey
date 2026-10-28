package syncclient

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Retirer is store.Retirer: the server as a logout uses it (§9). Since and
// Post run under the retiring device's session; RetireStatus and
// RetirePost authenticate each call with a "retire-status" challenge,
// which works after the session has ended.
type Retirer struct {
	c     *Client
	vault model.ID
}

var _ store.Retirer = (*Retirer)(nil)

// Retirer returns the Retirer for the vault vaultID.
func (c *Client) Retirer(vaultID model.ID) *Retirer { return &Retirer{c: c, vault: vaultID} }

// Since is store.Retirer.Since. An error matches ErrSessionEnded once the
// server has ended the device's sessions and refuses it another.
func (r *Retirer) Since(ctx context.Context, auth store.DeviceAuth, after uint64) (entries []store.Committed, head vaultlog.Head, err error) {
	err = r.c.withSession(ctx, deviceOf(auth), func(tok string) (err error) {
		entries, head, err = r.c.since(ctx, tok, r.vault, after, 0)
		return err
	})
	return entries, head, err
}

// Post is store.Retirer.Post, with Since's errors.
func (r *Retirer) Post(ctx context.Context, auth store.DeviceAuth, w *vaultlog.Wire) (head vaultlog.Head, err error) {
	err = r.c.withSession(ctx, deviceOf(auth), func(tok string) (err error) {
		head, err = r.c.post(ctx, tok, r.vault, w)
		return err
	})
	return head, err
}

// Reauthenticate is store.Retirer.Reauthenticate: a new session by a §9
// device-signature challenge, replacing any cached one.
func (r *Retirer) Reauthenticate(ctx context.Context, auth store.DeviceAuth) error {
	_, err := r.c.sessionToken(ctx, deviceOf(auth), "", true)
	return err
}

type retireStatusRequest struct {
	AccountID model.ID    `json:"account_id"`
	Challenge []byte      `json:"challenge"`
	DeviceID  model.ID    `json:"device_id"`
	H         crypto.Hash `json:"h"`
	Sig       []byte      `json:"sig"`
}

type receiptJSON struct {
	DeviceID model.ID    `json:"device_id"`
	H        crypto.Hash `json:"h"`
	How      string      `json:"how"`
	Seq      uint64      `json:"seq,string"`
}

// u64s is a u64 written as a decimal string (§3), for a member that may be
// null.
type u64s uint64

func (n *u64s) UnmarshalText(b []byte) error {
	s := string(b)
	if s == "" || (len(s) > 1 && s[0] == '0') || s[0] == '+' {
		return fmt.Errorf("syncclient: %q is not a u64s", s)
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fmt.Errorf("syncclient: %q is not a u64s", s)
	}
	*n = u64s(v)
	return nil
}

type retireStatusResponse struct {
	Committed bool          `json:"committed"`
	Head      vaultlog.Head `json:"head"`
	Receipt   *receiptJSON  `json:"receipt"`
	Seq       *u64s         `json:"seq"`
}

// retireAuth gets a "retire-status" challenge and the device's signature
// over it.
func (r *Retirer) retireAuth(ctx context.Context, dev Device) (chal, sig []byte, err error) {
	if chal, err = r.c.challenge(ctx, dev, crypto.OperationRetireStatus); err != nil {
		return nil, nil, err
	}
	if sig, err = r.c.sign(dev, crypto.OperationRetireStatus, chal); err != nil {
		return nil, nil, err
	}
	return chal, sig, nil
}

// RetireStatus is store.Retirer.RetireStatus: POST /v1/retire-status.
func (r *Retirer) RetireStatus(ctx context.Context, auth store.DeviceAuth, h crypto.Hash) (store.RetireStatus, error) {
	dev := deviceOf(auth)
	chal, sig, err := r.retireAuth(ctx, dev)
	if err != nil {
		return store.RetireStatus{}, err
	}
	var resp retireStatusResponse
	err = r.c.do(ctx, &call{
		method: http.MethodPost, path: "/v1/retire-status",
		body: retireStatusRequest{AccountID: dev.AccountID, Challenge: chal, DeviceID: dev.DeviceID, H: h, Sig: sig},
	}, &resp)
	if err != nil {
		return store.RetireStatus{}, err
	}
	if resp.Committed != (resp.Seq != nil) {
		return store.RetireStatus{}, fmt.Errorf("%w: retire-status committed=%v with seq %v", ErrMalformedResponse, resp.Committed, resp.Seq != nil)
	}
	st := store.RetireStatus{Committed: resp.Committed, Head: resp.Head}
	if resp.Seq != nil {
		st.Seq = uint64(*resp.Seq)
	}
	if rc := resp.Receipt; rc != nil {
		st.Receipt = &store.DeviceReceipt{DeviceID: rc.DeviceID, How: rc.How, Seq: rc.Seq, H: rc.H}
	}
	return st, nil
}

type retirePostRequest struct {
	AccountID model.ID      `json:"account_id"`
	Challenge []byte        `json:"challenge"`
	DeviceID  model.ID      `json:"device_id"`
	Sig       []byte        `json:"sig"`
	Wire      canonjson.Raw `json:"wire"`
}

// RetirePost is store.Retirer.RetirePost: POST /v1/retire-status/post. A
// head conflict is a *store.HeadConflictError.
func (r *Retirer) RetirePost(ctx context.Context, auth store.DeviceAuth, w *vaultlog.Wire) (vaultlog.Head, error) {
	raw, err := w.Marshal()
	if err != nil {
		return vaultlog.Head{}, err
	}
	dev := deviceOf(auth)
	chal, sig, err := r.retireAuth(ctx, dev)
	if err != nil {
		return vaultlog.Head{}, err
	}
	var head vaultlog.Head
	err = r.c.do(ctx, &call{
		method: http.MethodPost, path: "/v1/retire-status/post",
		body: retirePostRequest{AccountID: dev.AccountID, Challenge: chal, DeviceID: dev.DeviceID, Sig: sig, Wire: raw},
	}, &head)
	return head, err
}

type retireProofRequest struct {
	AccountID model.ID `json:"account_id"`
	After     uint64   `json:"after,string"`
	Challenge []byte   `json:"challenge"`
	DeviceID  model.ID `json:"device_id"`
	Sig       []byte   `json:"sig"`
}

type retireProofResponse struct {
	Entries []wireEntry `json:"entries"`
	Receipt receiptJSON `json:"receipt"`
}

// RevocationProof is store.ServerChecker.RevocationProof: POST
// /v1/retire-status/proof, one page of the entries after after up to the
// one this device's receipt names, each without its objects. A device
// with no receipt gets ErrNotFound.
func (r *Retirer) RevocationProof(ctx context.Context, auth store.DeviceAuth, after uint64) ([]store.Committed, store.DeviceReceipt, error) {
	dev := deviceOf(auth)
	chal, sig, err := r.retireAuth(ctx, dev)
	if err != nil {
		return nil, store.DeviceReceipt{}, err
	}
	var resp retireProofResponse
	err = r.c.do(ctx, &call{
		method: http.MethodPost, path: "/v1/retire-status/proof", maxResp: maxLogResponse,
		body: retireProofRequest{AccountID: dev.AccountID, After: after, Challenge: chal, DeviceID: dev.DeviceID, Sig: sig},
	}, &resp)
	if err != nil {
		return nil, store.DeviceReceipt{}, err
	}
	rc := store.DeviceReceipt{DeviceID: resp.Receipt.DeviceID, How: resp.Receipt.How, Seq: resp.Receipt.Seq, H: resp.Receipt.H}
	out := make([]store.Committed, 0, len(resp.Entries))
	next := after + 1
	for _, e := range resp.Entries {
		if e.Seq != next || e.Seq > rc.Seq {
			return nil, store.DeviceReceipt{}, fmt.Errorf("%w: proof entry %d, want %d", ErrMalformedResponse, e.Seq, next)
		}
		cm, err := e.committed()
		if err != nil {
			return nil, store.DeviceReceipt{}, err
		}
		out = append(out, cm)
		next++
	}
	return out, rc, nil
}
