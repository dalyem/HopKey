package authflow

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// EnrollOptions are hop auth login --method approve's inputs, on the new
// device.
type EnrollOptions struct {
	// Email is the account's sign-in email, kept for later sign-ins, or ""
	// when the new device does not know it.
	Email string
	// DeviceName names this device in the account (open.name, §7); empty
	// means Config.DeviceName, then the host name.
	DeviceName string
	// DeviceStore is where this device's key goes (store.DeviceStoreKeychain,
	// the default, or store.DeviceStoreFile).
	DeviceStore string
	// VaultID, when set, is the account's vault, which the new device reads
	// the log of. Zero learns it from the server once the approving device
	// has added this one: the server binds the new device's session to its
	// account's vault (syncclient.Client.SessionVault). Either way the
	// installed vault's verified state names it.
	VaultID model.ID
	// Mailbox resumes an enrollment this process started, within the
	// mailbox's lifetime (EnrollInterruptedError.Mailbox).
	Mailbox *syncclient.Mailbox
	// Restart discards an enrollment in progress that can't be resumed
	// (rejected, expired, or interrupted in another process) and starts a
	// new one.
	Restart bool
}

// relayWait is the long-poll of each mailbox read.
const relayWait = syncclient.MaxWait

// LoginApprove enrolls this machine by approval, as the new device D
// (§7): it posts the commit, shows the routing code, answers the
// approving device's chal with open, shows the SAS for the user to
// compare, and installs the vault once the confirmed delivery verifies.
//
// A chal or a delivery that fails its schema or its checks (a substituted
// one, say: store.ErrChalInvalid, store.ErrDeliveryInvalid) is discarded
// with no change of state, and LoginApprove keeps waiting for the real one
// (§7, invalid input). Any other failure to handle one is operational. A rejected SAS is
// terminal: the enrollment is discarded, nothing is installed, and the
// error matches crypto.ErrSASRejected. An attempt past its deadline, or
// whose mailbox the server no longer has, matches crypto.ErrEnrollExpired
// and is discarded too. Any other interruption (a cancelled context, a
// server still unreachable after the retries, a UI error) returns an
// *EnrollInterruptedError whose Mailbox resumes it in this process; the
// mailbox token is not persisted (gap G2). A delivery the store accepted
// is installed by the next call even without the mailbox.
func LoginApprove(ctx context.Context, env *Env, opts EnrollOptions) (*LoginResult, error) {
	cfg, c := env.Config, env.Client
	var reader store.EnrollRemote = &sessionReader{c: c}
	if !opts.VaultID.IsZero() {
		reader = c.Publisher(opts.VaultID)
	}
	e, err := store.ResumeEnrollment(cfg)
	switch {
	case errors.Is(err, store.ErrNoEnrollment):
		e = nil
	case err != nil:
		return nil, err
	}
	mb := opts.Mailbox
	if e != nil {
		switch st := e.State(); {
		case st == crypto.DeviceDone:
			// A delivery was accepted: only its install is left, which
			// needs no relay.
			s, err := installAccepted(ctx, env, e, reader)
			if err != nil {
				return nil, err
			}
			return enrolled(s, c)
		case st == crypto.DeviceRejected || st == crypto.DeviceFailed || mb == nil:
			if !opts.Restart {
				e.Close()
				switch st {
				case crypto.DeviceRejected:
					return nil, fmt.Errorf("%w (start again to enroll)", crypto.ErrSASRejected)
				case crypto.DeviceFailed:
					return nil, fmt.Errorf("%w (start again to enroll)", crypto.ErrEnrollExpired)
				}
				return nil, ErrEnrollmentInterrupted
			}
			if err := discard(cfg, e); err != nil {
				return nil, err
			}
			e, mb = nil, nil
		}
	} else {
		mb = nil
		if exists, err := store.Exists(cfg.DataDir); err != nil {
			return nil, err
		} else if exists {
			return nil, existingVault(ctx, cfg)
		}
	}
	if e == nil {
		var commit crypto.EnrollCommit
		e, commit, err = store.BeginEnrollment(cfg, store.EnrollParams{
			ServerURL: c.Origin(), Email: opts.Email, DeviceName: opts.DeviceName, DeviceStore: opts.DeviceStore,
		})
		if err != nil {
			return nil, err
		}
		err = env.retry(ctx, func() (err error) { mb, err = c.CreateMailbox(ctx, commit); return err })
		if err == nil {
			err = e.SetEnrollID(mb.EnrollID)
		}
		if err != nil {
			// Nothing was revealed: no other device can have seen more
			// than the commit.
			return nil, errors.Join(err, discard(cfg, e))
		}
	}
	d := &deviceSide{env: env, e: e, mb: mb, relay: c.DeviceRelay(mb), reader: reader}
	s, err := d.run(ctx)
	if err != nil {
		return nil, err
	}
	return enrolled(s, c)
}

// sessionReader is the log as the new device reads it before it knows its
// vault (store.EnrollRemote): its first read learns the vault its session
// is bound to (syncclient.Client.SessionVault), which works once the
// approving device's device_add committed, as it has before any delivery
// is sent. Nothing it returns is trusted: the store verifies the log from
// the delivered anchor.
type sessionReader struct {
	c   *syncclient.Client
	mu  sync.Mutex
	pub *syncclient.Publisher
}

func (r *sessionReader) publisher(ctx context.Context, auth store.DeviceAuth) (*syncclient.Publisher, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pub != nil {
		return r.pub, nil
	}
	dev, err := syncclient.StoreDevice(func() (store.DeviceAuth, error) { return auth, nil })
	if err != nil {
		return nil, err
	}
	id, err := r.c.SessionVault(ctx, dev)
	if err != nil {
		return nil, fmt.Errorf("authflow: learning the account's vault: %w", err)
	}
	r.pub = r.c.Publisher(id)
	return r.pub, nil
}

func (r *sessionReader) EntryAt(ctx context.Context, auth store.DeviceAuth, seq uint64) (store.Committed, error) {
	p, err := r.publisher(ctx, auth)
	if err != nil {
		return store.Committed{}, err
	}
	return p.EntryAt(ctx, auth, seq)
}

func (r *sessionReader) Since(ctx context.Context, auth store.DeviceAuth, after uint64) ([]store.Committed, vaultlog.Head, error) {
	p, err := r.publisher(ctx, auth)
	if err != nil {
		return nil, vaultlog.Head{}, err
	}
	return p.Since(ctx, auth, after)
}

// existingVault is the error for enrolling into a data directory that
// holds a vault.
func existingVault(ctx context.Context, cfg store.Config) error {
	s, err := store.Open(ctx, cfg)
	if err != nil {
		return fmt.Errorf("%w: %w", store.ErrVaultExists, err)
	}
	defer s.Close()
	if s.ServerBacked() {
		return ErrSignedIn
	}
	return ErrLocalVault
}

// enrolled is the installed store s as a signed-in vault, named by its
// verified state.
func enrolled(s *store.Store, c *syncclient.Client) (*LoginResult, error) {
	si, err := s.ServerInfo()
	if err == nil && si.VaultID.IsZero() {
		err = fmt.Errorf("%w: the installed vault has no vault ID", store.ErrCorrupt)
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	v, err := newVault(s, c, si.VaultID)
	if err != nil {
		s.Close()
		return nil, err
	}
	return &LoginResult{Vault: v}, nil
}

// discard closes e and deletes the enrollment and its keys.
func discard(cfg store.Config, e *store.Enrollment) error {
	return errors.Join(e.Close(), store.DiscardEnrollment(cfg))
}

// installAccepted installs the delivery an earlier call accepted,
// retrying the log reads that failed in a retryable way.
func installAccepted(ctx context.Context, env *Env, e *store.Enrollment, r store.EnrollRemote) (*store.Store, error) {
	var s *store.Store
	err := env.retry(ctx, func() (err error) {
		s, err = e.Install(ctx, r, nil)
		return err
	})
	if err != nil {
		e.Close()
		return nil, err
	}
	return s, nil
}

// deviceSide is D's relay loop.
type deviceSide struct {
	env    *Env
	e      *store.Enrollment
	mb     *syncclient.Mailbox
	relay  *syncclient.Relay
	reader store.EnrollRemote
	shown  bool
}

// interrupted closes the enrollment, which stays as it is persisted, and
// returns err with the mailbox that resumes it.
func (d *deviceSide) interrupted(err error) error {
	d.e.Close()
	return &EnrollInterruptedError{Mailbox: d.mb, Err: err}
}

// gone discards the enrollment, whose attempt is over, and returns err.
func (d *deviceSide) gone(err error) error {
	return errors.Join(err, discard(d.env.Config, d.e))
}

func (d *deviceSide) run(ctx context.Context) (*store.Store, error) {
	ui := d.env.UI
	// The attempt's persisted deadline: a resumed attempt waits no longer
	// than the first did.
	deadline := d.e.Deadline()
	if d.e.State() == crypto.DeviceCommitted {
		if err := ui.ShowRoutingCode(ctx, d.mb.RoutingCode); err != nil {
			return nil, d.interrupted(err)
		}
	}
	if d.e.State() == crypto.DeviceRevealed {
		// Resumed after open: send it again (an identical retransmission)
		// and ask about the SAS again.
		if err := d.reveal(ctx); err != nil {
			return nil, err
		}
	}
	after := uint64(0)
	for retries, discards := 0, 0; ; {
		if time.Now().After(deadline) {
			return nil, d.gone(crypto.ErrEnrollExpired)
		}
		wait := min(relayWait, time.Until(deadline)).Truncate(time.Second)
		msgs, err := d.relay.Messages(ctx, after, wait)
		switch {
		case err == nil:
			retries = 0
		case errors.Is(err, syncclient.ErrUnauthorized), errors.Is(err, syncclient.ErrNotFound):
			// The mailbox token is refused once the mailbox has expired.
			return nil, d.gone(fmt.Errorf("%w: the server no longer has this device's mailbox: %w", crypto.ErrEnrollExpired, err))
		case syncclient.Retryable(err) && retries < d.env.retries():
			if err := sleep(ctx, d.env.backoff(retries)); err != nil {
				return nil, d.interrupted(err)
			}
			retries++
			continue
		default:
			return nil, d.interrupted(err)
		}
		for _, m := range msgs {
			s, err := d.handle(ctx, m)
			if errors.Is(err, errDiscarded) {
				// Read the same position again, not at the relay's pace:
				// the real message may still arrive before the deadline.
				if err := sleep(ctx, d.env.discardPause(discards)); err != nil {
					return nil, d.interrupted(err)
				}
				discards++
				break
			}
			if err != nil || s != nil {
				return s, err
			}
			after = m.N
		}
	}
}

// handle acts on one relay message: a chal in COMMITTED, a delivery in
// CONFIRMED; anything else is skipped. A chal or a delivery that fails its
// schema or its checks (store.ErrChalInvalid, store.ErrDeliveryInvalid) is
// errDiscarded, with no change of state (§7, invalid input). The deadline
// and a rejection end the attempt; any other failure is operational and
// interrupts it, and the same process resumes it with the mailbox.
func (d *deviceSide) handle(ctx context.Context, m syncclient.Message) (*store.Store, error) {
	switch {
	case m.Type == syncclient.MsgChal && d.e.State() == crypto.DeviceCommitted:
		var ch crypto.EnrollChal
		if err := crypto.ParseEnrollMessage(m.Body, &ch); err != nil {
			return nil, fmt.Errorf("%w: the chal is malformed: %w", errDiscarded, err)
		}
		if _, err := d.e.HandleChal(&ch); err != nil {
			switch {
			case errors.Is(err, crypto.ErrEnrollExpired), errors.Is(err, crypto.ErrSASRejected):
				return nil, d.gone(err)
			case errors.Is(err, store.ErrChalInvalid):
				return nil, fmt.Errorf("%w: %w", errDiscarded, err)
			}
			return nil, d.interrupted(fmt.Errorf("authflow: handling the chal: %w", err))
		}
		return nil, d.reveal(ctx)
	case m.Type == syncclient.MsgDeliver && d.e.State() == crypto.DeviceConfirmed:
		var env crypto.HPKEEnvelope
		if err := canonjson.Unmarshal(m.Body, &env); err != nil {
			return nil, fmt.Errorf("%w: the delivery is malformed: %w", errDiscarded, err)
		}
		if err := env.Check(); err != nil {
			return nil, fmt.Errorf("%w: the delivery is malformed: %w", errDiscarded, err)
		}
		var s *store.Store
		err := d.env.retry(ctx, func() (err error) {
			s, err = d.e.Install(ctx, d.reader, &env)
			return err
		})
		if err == nil {
			return s, nil
		}
		switch st := d.e.State(); {
		case st == crypto.DeviceDone:
			// The delivery was accepted: the next call installs it, with or
			// without the mailbox.
			return nil, d.interrupted(fmt.Errorf("authflow: installing the approved device: %w", err))
		case st == crypto.DeviceFailed || st == crypto.DeviceRejected || errors.Is(err, crypto.ErrEnrollExpired):
			return nil, d.gone(err)
		case errors.Is(err, store.ErrDeliveryInvalid) && ctx.Err() == nil:
			// A delivery that fails a check of step 6 (a substituted one,
			// or one naming another anchor) changed nothing.
			return nil, fmt.Errorf("%w: %w", errDiscarded, err)
		}
		// The log could not be read or verified, or the state not saved:
		// the delivery stays in the mailbox, and the same process checks
		// it again.
		return nil, d.interrupted(fmt.Errorf("authflow: checking the delivery: %w", err))
	}
	return nil, nil
}

// reveal posts open (REVEALED), shows the SAS and records the user's
// answer before anything else (§7 step 4). A rejection is terminal.
func (d *deviceSide) reveal(ctx context.Context) error {
	open, err := d.e.Open()
	if err != nil {
		return d.interrupted(err)
	}
	if err := d.env.retry(ctx, func() error { _, err := d.relay.Post(ctx, syncclient.MsgOpen, &open); return err }); err != nil {
		if errors.Is(err, syncclient.ErrUnauthorized) || errors.Is(err, syncclient.ErrNotFound) {
			return d.gone(fmt.Errorf("%w: %w", crypto.ErrEnrollExpired, err))
		}
		return d.interrupted(err)
	}
	sas, err := d.e.SAS()
	if err != nil {
		return d.interrupted(err)
	}
	match, err := d.env.UI.ConfirmSAS(ctx, sas, open.Name)
	if err != nil {
		return d.interrupted(err)
	}
	if !match {
		if err := d.e.RejectSAS(); err != nil {
			return d.gone(err)
		}
		return d.gone(crypto.ErrSASRejected)
	}
	if err := d.e.ConfirmSAS(); err != nil {
		if errors.Is(err, crypto.ErrEnrollExpired) {
			return d.gone(err)
		}
		return d.interrupted(err)
	}
	return nil
}
