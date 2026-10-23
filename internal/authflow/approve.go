package authflow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// ApproveResult is a device this device approved.
type ApproveResult struct {
	EnrollID   model.ID
	DeviceName string
}

// Approve is hop auth approve CODE, on the approving device A (§7): it
// claims the new device's mailbox by its routing code, reserves an
// attempt in the approval budget (crypto.ErrBudgetExhausted,
// crypto.ErrChallengeOutstanding), sends chal, checks D's open, shows the
// SAS and the device name for the user to compare, and only on a match
// commits the device_add and sends the delivery.
//
// A mismatch ends the attempt (ErrSASMismatch) with nothing committed or
// delivered; so do an open that does not match the commit and the
// deadline. Any other failure leaves the attempt as it is persisted, and
// Approve with the same code resumes it; AbortApproval ends it.
func Approve(ctx context.Context, env *Env, v *Vault, routingCode string) (*ApproveResult, error) {
	s, c := v.Store, v.Client
	code := normalizeRoutingCode(routingCode)
	var cl syncclient.Claim
	if err := env.retry(ctx, func() (err error) { cl, err = c.Claim(ctx, v.dev, code); return err }); err != nil {
		return nil, err
	}
	info, err := s.Approval()
	if err != nil {
		return nil, err
	}
	switch {
	case info != nil && info.EnrollID == cl.EnrollID && info.State == crypto.ApprovalFailed:
		return nil, ErrApprovalFailed
	case info == nil || info.EnrollID != cl.EnrollID:
		// A new attempt. An unfinished one for another device is
		// store.ErrApprovalPending; a finished one is replaced.
		if err := s.ApproveStart(cl.EnrollID); err != nil {
			return nil, err
		}
		if info, err = s.Approval(); err != nil {
			return nil, err
		}
	}
	// Otherwise this device's attempt for the same mailbox resumes where it
	// stopped; a delivered one sends its delivery again (an identical
	// retransmission), in case that post was lost.
	a := &approverSide{env: env, v: v, relay: c.ApproverRelay(cl.EnrollID, v.dev), deadline: info.Deadline}
	name, err := a.run(ctx, info.State, &cl.Commit)
	if err != nil {
		return nil, err
	}
	return &ApproveResult{EnrollID: cl.EnrollID, DeviceName: name}, nil
}

// AbortApproval ends this device's unfinished approval as a failure. A
// device_add it already committed stays until a checkpoint revokes it
// (Devices lists it as Undelivered).
func AbortApproval(v *Vault) error { return v.Store.ApproveAbort() }

// normalizeRoutingCode drops the spaces and hyphens a user may type.
func normalizeRoutingCode(code string) string {
	return strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(code))
}

type approverSide struct {
	env      *Env
	v        *Vault
	relay    *syncclient.Relay
	deadline time.Time
}

// fail ends the attempt as a failure and returns err.
func (a *approverSide) fail(err error) error {
	if aerr := a.v.Store.ApproveAbort(); aerr != nil {
		// An attempt that already ended (a mismatch, the deadline) has
		// nothing to abort.
		if info, ierr := a.v.Store.Approval(); ierr != nil || info == nil || info.State != crypto.ApprovalFailed {
			return errors.Join(err, aerr)
		}
	}
	return err
}

// relayGone reports whether a relay error means the mailbox is gone (it
// expired) or no longer this device's.
func relayGone(err error) bool { return errors.Is(err, syncclient.ErrNotFound) }

func (a *approverSide) run(ctx context.Context, state crypto.ApprovalState, commit *crypto.EnrollCommit) (string, error) {
	s := a.v.Store
	var sas, name string
	var err error
	switch state {
	case crypto.ApprovalReserved, crypto.ApprovalChallenged:
		var ch crypto.EnrollChal
		if state == crypto.ApprovalReserved {
			ch, err = s.ApproveCommit(commit)
		} else {
			ch, err = s.ApproveChal()
		}
		if err != nil {
			return "", a.fail(err)
		}
		if err := a.env.retry(ctx, func() error { _, err := a.relay.Post(ctx, syncclient.MsgChal, &ch); return err }); err != nil {
			if relayGone(err) {
				return "", a.fail(fmt.Errorf("%w: %w", crypto.ErrEnrollExpired, err))
			}
			return "", err
		}
		if sas, name, err = a.awaitOpen(ctx); err != nil {
			return "", err
		}
		fallthrough
	case crypto.ApprovalOpened:
		if sas == "" {
			if sas, name, err = s.ApproveSAS(); err != nil {
				return "", a.fail(err)
			}
		}
		match, err := a.env.UI.ConfirmSAS(ctx, sas, name)
		if err != nil {
			return "", err
		}
		if err := s.ApproveConfirm(match); err != nil {
			return "", a.fail(err)
		}
		if !match {
			return "", ErrSASMismatch
		}
	}
	// CONFIRMED, PREPARED, or DELIVERED: commit the device_add (or find
	// it committed) and send the delivery.
	var env crypto.HPKEEnvelope
	if err := a.env.retry(ctx, func() (err error) { env, err = s.ApproveFinish(ctx, a.v.Remote); return err }); err != nil {
		if errors.Is(err, crypto.ErrEnrollExpired) {
			return "", a.fail(err)
		}
		return "", err
	}
	if err := a.env.retry(ctx, func() error { _, err := a.relay.Post(ctx, syncclient.MsgDeliver, env); return err }); err != nil {
		return "", fmt.Errorf("authflow: the device was added, but its delivery was not sent (approve again with the same code): %w", err)
	}
	if name == "" {
		_, name, _ = s.ApproveSAS()
	}
	return name, nil
}

// awaitOpen waits for D's open and checks it against the commit (§7 step
// 4). An open that does not match ends the attempt: the relay holds no
// other.
func (a *approverSide) awaitOpen(ctx context.Context) (sas, name string, err error) {
	for retries := 0; ; {
		if !a.deadline.IsZero() && time.Now().After(a.deadline) {
			return "", "", a.fail(crypto.ErrEnrollExpired)
		}
		wait := relayWait
		if !a.deadline.IsZero() {
			wait = min(wait, time.Until(a.deadline))
		}
		msgs, err := a.relay.Messages(ctx, 1, wait.Truncate(time.Second))
		switch {
		case err == nil:
			retries = 0
		case relayGone(err):
			return "", "", a.fail(fmt.Errorf("%w: %w", crypto.ErrEnrollExpired, err))
		case syncclient.Retryable(err) && retries < a.env.retries():
			if err := sleep(ctx, a.env.backoff(retries)); err != nil {
				return "", "", err
			}
			retries++
			continue
		default:
			return "", "", err
		}
		for _, m := range msgs {
			if m.Type != syncclient.MsgOpen {
				continue
			}
			var o crypto.EnrollOpen
			if err := crypto.ParseEnrollMessage(m.Body, &o); err != nil {
				return "", "", a.fail(fmt.Errorf("authflow: the new device's open is malformed: %w", err))
			}
			sas, name, err := a.v.Store.ApproveOpen(&o)
			if err != nil {
				return "", "", a.fail(err)
			}
			return sas, name, nil
		}
	}
}
