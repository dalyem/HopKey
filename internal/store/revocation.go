package store

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Revocation as the server reports it, and as the log proves it.
//
//	vault/server-revoked.json = JCS({"v":1, "account_id":id, "device_id":id, "how":"revoked"|"retired",
//	                                 "seq":u64s, "h":h, "at":ts, "mac":b64})
//	vault/contact.json        = JCS({"v":1, "at":ts})
//	<data>/revocation.json    = JCS({"v":1, "account_id":id, "device_id":id, "how":str, "seq":u64s, "h":h,
//	                                 "at":ts, "server":str, "email":str})
//
// The server's other answers decide less. A session refused without a
// receipt that names this device's departure, or any answer the client
// can't use, locks the vault in memory only (ErrServerUnconfirmed): nothing
// is recorded, and the next unlock or sync asks again. Only a server that
// can't be reached lets the keys load without an answer; the daemon decides
// that (internal/daemon/revocation.go).
//
// A device that left the account is refused a session, and the log can't
// show it the entry that removed it: its entries are no longer served to
// it. retire-status says how it left (§9). That answer is the server's
// word, so it decides only what can't hurt: server-revoked.json records it
// (its mac is HMAC-SHA256 under local_key over "hopkey/v1/server-revoked"
// and the JCS of the other members), and while it is there every unlock
// refuses, the device key's and the password's alike (ErrServerRevoked).
// The mac is verified whenever the device key is loaded to ask the server
// (CheckServer, ProveRevocation). One that does not verify, or a file that
// does not parse, still refuses every unlock, but Info calls it corrupt and
// does not show its members as the server's. The mac protects nothing
// else: whoever controls the device can delete the file, as they can the
// whole vault; it only keeps tampered metadata from being displayed as
// authentic.
// Only CheckServer removes it, once the server authenticates this device
// again: the report was wrong. A server that lies can lock a device out,
// which it can do anyway by refusing it, but it can't delete anything, and
// it can't unlock a device that really was revoked, since an honest
// server never authenticates one.
//
// The proof is an authenticated departure authorization: the signatures
// and the membership changes of every entry are verified, but not the
// vault contents those entries carry. It is the entries from this device's
// verified head up to the one
// that removed it, as the server's retire-status/proof endpoint serves them
// to a departed device: wires without their objects, checked by the public
// stage without objects (vaultlog.CheckHeader). Each must chain from the
// last, starting at the verified head, and carry the signatures its kind
// needs from devices and account keys that state knows; the last must be
// the receipt's entry and remove this device. A checkpoint carries the
// account's old signature, so only a member of the account can have made
// one. Once that verifies, the revocation is the account's, not the
// server's, and the device wipes itself as a logout does (wipeRevoked),
// keeping only revocation.json for hop auth status.
//
// contact.json is the time of the last request the server authenticated
// this device for: a session granted, or a pull. The store keeps the time
// of every contact in memory, and LastContact returns it; the file is
// written at most once a minute (contactEvery), on every contact while the
// account's max-offline policy is under ten minutes (shortPolicy), and at
// Close. After a restart the file is a lower bound. The daemon locks a
// device that has had none for longer than the policy allows
// (model.Policy). Someone who controls the device can edit the file or the
// clock; only rotating the keys helps against that.

var (
	// ErrServerRevoked means the server reported that this device left the
	// account: the vault stays locked until the server authenticates the
	// device again. It matches model.ErrLocked.
	ErrServerRevoked = fmt.Errorf("%w: the server reports that this device was revoked from the account, so the vault stays locked here; "+
		"hop auth logout wipes this device, and hop auth login signs in again", model.ErrLocked)
	// ErrServerUnconfirmed means the server answered, but did not confirm
	// that this device is still in the account: it refused it a session
	// without a valid report of its departure, or answered in a way the
	// client can't use. The vault is locked in memory only, and nothing is
	// recorded, until the server accepts the device again. It matches
	// model.ErrLocked.
	ErrServerUnconfirmed = fmt.Errorf("%w: the server did not confirm that this device is still in the account; "+
		"it stays locked until the server accepts it again (hop unlock asks)", model.ErrLocked)
	// ErrWipeIncomplete means a revocation was proven (ErrDeviceRevoked
	// matches too) but wiping this device's copy of the vault did not
	// finish; the next start finishes it.
	ErrWipeIncomplete = errors.New("store: wiping this device's copy of the vault did not finish; it finishes at the next start")
	// ErrOfflineTooLong means the account's max-offline policy locked the
	// vault. It matches model.ErrLocked.
	ErrOfflineTooLong = fmt.Errorf("%w: offline too long; connect to the server", model.ErrLocked)
	// ErrNoReport means ProveRevocation found no server report to prove.
	ErrNoReport = errors.New("store: the server has not reported this device revoked")
	// ErrProofRefused means the server's proof of this device's revocation
	// did not verify. Nothing was deleted.
	ErrProofRefused = errors.New("store: the server's proof that this device was revoked did not verify")
)

const (
	serverRevokedRel  = "server-revoked.json"
	contactRel        = "contact.json"
	revocationName    = "revocation.json"
	labelServerReport = "hopkey/v1/server-revoked"
	// contactEvery is how often a contact is written: once a minute at
	// most, unless the stored one is in the future, or the policy is
	// shorter than shortPolicy.
	contactEvery = time.Minute
	// shortPolicy is the max-offline policy under which every contact is
	// written.
	shortPolicy = 10 * time.Minute
	// maxProofEntries bounds the entries a proof may take, from this
	// device's head to the one that removed it.
	maxProofEntries = 1 << 20
)

func (l layout) serverRevokedFile() string { return filepath.Join(l.vault(), serverRevokedRel) }
func (l layout) contactFile() string       { return filepath.Join(l.vault(), contactRel) }
func (l layout) revocationFile() string    { return filepath.Join(l.data, revocationName) }

// ServerReport is the server's report that this device left the account,
// as server-revoked.json records it.
type ServerReport struct {
	AccountID model.ID        `json:"account_id"`
	DeviceID  model.ID        `json:"device_id"`
	How       string          `json:"how"` // "revoked" or "retired"
	Seq       uint64          `json:"seq,string"`
	H         crypto.Hash     `json:"h"`
	At        model.Timestamp `json:"at"`
}

type serverReportFile struct {
	V int `json:"v"`
	ServerReport
	MAC []byte `json:"mac"`
}

type serverReportBody struct {
	V int `json:"v"`
	ServerReport
}

func reportMAC(rec *deviceRecord, r ServerReport) ([]byte, error) {
	if rec == nil || rec.V != 2 || len(rec.LocalKey) != localKeySize {
		return nil, ErrLocalKey
	}
	b, err := canonjson.Marshal(serverReportBody{V: 1, ServerReport: r})
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, rec.LocalKey)
	m.Write(crypto.LP([]byte(labelServerReport)))
	m.Write(b)
	return m.Sum(nil), nil
}

// readReport reads server-revoked.json, or returns nil when there is none.
// Any file there counts as a report (only hop writes it), so one that does
// not parse is returned empty and corrupt, and so is one whose mac the last
// verifyReport of these very bytes refused. One not verified yet (the
// device key was not loaded since) is returned as it reads. The caller
// holds s.mu.
func (s *Store) readReport() (rep *ServerReport, corrupt bool, err error) {
	b, err := os.ReadFile(s.l.serverRevokedFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var f serverReportFile
	if canonjson.Unmarshal(b, &f) != nil || f.V != 1 {
		return &ServerReport{}, true, nil
	}
	if v := s.reportVerdict; v != nil && v.sum == sha256.Sum256(b) && !v.ok {
		return &ServerReport{}, true, nil
	}
	return &f.ServerReport, false, nil
}

// reportVerdict is what verifyReport found of server-revoked.json.
type reportVerdict struct {
	sum [sha256.Size]byte // of the bytes verified
	ok  bool
}

// verifyReport checks server-revoked.json's mac under rec's local_key, and
// keeps the verdict for readReport. The caller holds s.mu.
func (s *Store) verifyReport(rec *deviceRecord) {
	b, err := os.ReadFile(s.l.serverRevokedFile())
	if err != nil {
		return
	}
	v := &reportVerdict{sum: sha256.Sum256(b)}
	var f serverReportFile
	if canonjson.Unmarshal(b, &f) == nil && f.V == 1 {
		mac, err := reportMAC(rec, f.ServerReport)
		v.ok = err == nil && hmac.Equal(mac, f.MAC)
	}
	s.reportVerdict = v
}

// refuseReported fails with ErrServerRevoked while server-revoked.json is
// there. It reads only the name. The caller holds s.mu.
func (s *Store) refuseReported() error {
	if _, err := os.Lstat(s.l.serverRevokedFile()); err == nil {
		return ErrServerRevoked
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// writeReport records r, authenticated under rec's local_key, durably.
// The caller holds s.mu.
func (s *Store) writeReport(rec *deviceRecord, r ServerReport) error {
	mac, err := reportMAC(rec, r)
	if err != nil {
		return err
	}
	b, err := canonjson.Marshal(serverReportFile{V: 1, ServerReport: r, MAC: mac})
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.l.serverRevokedFile(), b); err != nil {
		return err
	}
	return syncDir(s.l.vault())
}

// clearReport removes server-revoked.json. The caller holds s.mu.
func (s *Store) clearReport() error {
	if err := os.Remove(s.l.serverRevokedFile()); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return syncDir(s.l.vault())
}

// Report returns the server's report that this device left the account,
// or nil when there is none. It reads the file only, so it works locked.
func (s *Store) Report() (*ServerReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rep, _, err := s.readReport()
	return rep, err
}

type contactFile struct {
	V  int             `json:"v"`
	At model.Timestamp `json:"at"`
}

// LastContact returns when the server last authenticated this device, and
// false when it never has (or the record is gone): the last contact this
// Store saw, or else contact.json.
func (s *Store) LastContact() (time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.contactAt.IsZero() {
		return s.contactAt, true, nil
	}
	return s.lastContact()
}

// lastContact reads contact.json.
func (s *Store) lastContact() (time.Time, bool, error) {
	b, err := os.ReadFile(s.l.contactFile())
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	var f contactFile
	if canonjson.Unmarshal(b, &f) != nil || f.V != 1 {
		return time.Time{}, false, fmt.Errorf("%w: %s does not parse", ErrCorrupt, s.l.contactFile())
	}
	return f.At.Time(), true, nil
}

// noteContact records that the server authenticated this device now: in
// memory always, and in contact.json at most once a minute, but always when
// the stored time is in the future (a clock that was set back), when the
// account's max-offline policy is short (shortPolicy), or when the vault is
// locked, so the policy is not known. Writing is best effort; the caller
// holds s.mu.
func (s *Store) noteContact() {
	now := time.Now()
	if s.cfg.Now != nil {
		now = s.cfg.Now()
	}
	s.contactAt = now
	if at, ok, err := s.lastContact(); err == nil && ok && !at.After(now) && now.Sub(at) < contactEvery &&
		s.sec != nil && !s.shortPolicyLocked() {
		return
	}
	s.writeContact(now)
}

// writeContact writes contact.json. The caller holds s.mu.
func (s *Store) writeContact(at time.Time) {
	b, err := canonjson.Marshal(contactFile{V: 1, At: model.TimestampOf(at)})
	if err == nil {
		writeFileAtomic(s.l.contactFile(), b)
	}
}

// saveContact writes the last contact this Store saw, unless contact.json
// has it or a later one, as Close does. A vault that is gone, or going (a
// logout or a revocation wipes it), gets nothing. The caller holds s.mu.
func (s *Store) saveContact() {
	if s.contactAt.IsZero() || s.revoked != nil {
		return
	}
	if _, err := os.Lstat(s.l.stateFile()); err != nil {
		return
	}
	if j, err := s.readRetireFile(); err != nil || j != nil {
		return
	}
	if at, ok, err := s.lastContact(); err == nil && ok && !at.Before(s.contactAt) {
		return
	}
	s.writeContact(s.contactAt)
}

// shortPolicyLocked reports whether the verified vault's max-offline policy
// is set and under shortPolicy. The caller holds s.mu; the vault is
// unlocked.
func (s *Store) shortPolicyLocked() bool {
	var ps []model.Policy
	for _, p := range s.sec.Items {
		if v, ok := p.Item.(*model.Policy); ok {
			ps = append(ps, *v)
		}
	}
	max := time.Duration(model.EffectiveMaxOffline(ps)) * time.Second
	return max > 0 && max < shortPolicy
}

// RevocationRecord is what a wiped device keeps of its revocation, beside
// device.json, for hop auth status.
type RevocationRecord struct {
	V         int             `json:"v"`
	AccountID model.ID        `json:"account_id"`
	DeviceID  model.ID        `json:"device_id"`
	How       string          `json:"how"`
	Seq       uint64          `json:"seq,string"`
	H         crypto.Hash     `json:"h"`
	At        model.Timestamp `json:"at"`
	Server    string          `json:"server"`
	Email     string          `json:"email"`
}

// ReadRevocation returns the record a revocation left in dataDir when it
// wiped this device, or nil.
func ReadRevocation(dataDir string) (*RevocationRecord, error) {
	b, err := os.ReadFile(layout{data: dataDir}.revocationFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r RevocationRecord
	if canonjson.Unmarshal(b, &r) != nil || r.V != 1 {
		return nil, fmt.Errorf("%w: %s does not parse", ErrCorrupt, layout{data: dataDir}.revocationFile())
	}
	return &r, nil
}

// ClearRevocation removes the record ReadRevocation reads.
func ClearRevocation(dataDir string) error {
	if err := os.Remove(layout{data: dataDir}.revocationFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ServerChecker is the server as CheckServer and ProveRevocation ask it
// (§9). syncclient's Retirer implements it.
type ServerChecker interface {
	// Reauthenticate gets a new session by a device-signature challenge;
	// it fails with ErrSessionEnded when the server refuses this device.
	Reauthenticate(ctx context.Context, auth DeviceAuth) error
	// RetireStatus is POST /v1/retire-status.
	RetireStatus(ctx context.Context, auth DeviceAuth, h crypto.Hash) (RetireStatus, error)
	// RevocationProof is POST /v1/retire-status/proof: the entries after
	// after up to the receipt's, without their objects, a page at a time,
	// and the receipt.
	RevocationProof(ctx context.Context, auth DeviceAuth, after uint64) ([]Committed, DeviceReceipt, error)
}

// ServerCheck is what CheckServer found.
type ServerCheck struct {
	// Active means the server authenticated this device: it is in the
	// account, and any report that it left is gone.
	Active bool
	// Report is the server's report that it left, now recorded.
	Report *ServerReport
}

// checkKey is the device key and verified state a check works with: the
// store's own while unlocked, otherwise a copy loaded for it and never
// installed.
type checkKey struct {
	key       *sessionAuth
	st        *vaultlog.State
	rec       *deviceRecord
	accountID model.ID
	deviceID  model.ID
}

func (k *checkKey) close() {
	k.key.close()
	if k.rec != nil {
		k.rec.zero()
	}
}

// checkKeyLocked returns the key for a check. passphrase, when set,
// opens a sealed device key file in place of HOP_DEVICE_PASSPHRASE, as for
// UnlockWithPassphrase. The caller holds s.mu.
func (s *Store) checkKeyLocked(passphrase []byte) (*checkKey, error) {
	if s.owner == nil || s.closing {
		return nil, ErrClosed
	}
	if server, err := s.l.serverBacked(); err != nil {
		return nil, err
	} else if !server {
		return nil, ErrNotServerBacked
	}
	if s.state != nil {
		return &checkKey{
			key: &sessionAuth{key: append(ed25519.PrivateKey(nil), s.dev.Sig...)}, st: s.state, rec: s.rec.clone(),
			accountID: s.state.Account.AccountID, deviceID: s.dev.ID,
		}, nil
	}
	if passphrase != nil {
		s.passphrase.Store(&passphrase)
		defer s.passphrase.Store(nil)
	}
	v, unlock, err := s.loadVault(false, true)
	if err != nil {
		return nil, err
	}
	unlock()
	k := &checkKey{
		key: &sessionAuth{key: append(ed25519.PrivateKey(nil), v.dev.Sig...)}, st: v.st, rec: v.rec.clone(),
		accountID: v.st.Account.AccountID, deviceID: v.dev.ID,
	}
	v.zero()
	zeroDevice(v.dev)
	return k, nil
}

// CheckServer asks the server whether this device is still in the
// account, locked or not, and acts on the answer: a session granted
// records the contact and clears a report that it left (the report was
// wrong); a refusal asks retire-status how it left, records that
// (server-revoked.json) and locks the vault. A refusal whose retire-status
// fails, or names no departure of this device, locks the vault in memory
// only and returns ErrServerUnconfirmed. It deletes nothing. Any other
// failure (the server unreachable, a response that does not parse)
// changes nothing and is returned; the caller decides what it means.
//
// It waits for a sync in progress (syncMu) only until ctx ends, and then
// returns an error wrapping ctx's, without asking. A lock or Close cancels
// it. passphrase is for a locked vault's sealed device key file
// (checkKeyLocked); nil uses HOP_DEVICE_PASSPHRASE, and without one the
// error matches ErrDeviceKey.
func (s *Store) CheckServer(ctx context.Context, r ServerChecker, passphrase []byte) (ServerCheck, error) {
	if err := s.lockSyncCtx(ctx); err != nil {
		return ServerCheck{}, err
	}
	defer s.syncMu.Unlock()
	s.mu.Lock()
	k, err := s.checkKeyLocked(passphrase)
	if err != nil {
		s.mu.Unlock()
		return ServerCheck{}, err
	}
	defer k.close()
	s.verifyReport(k.rec)
	ctx, gen, untrack := s.trackRequest(ctx)
	unlocked := s.state != nil
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		untrack()
		s.mu.Unlock()
	}()
	auth := k.key.auth(k.accountID, k.deviceID)

	err = r.Reauthenticate(ctx, auth)
	if err == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.noteContact()
		if s.state == nil && errors.Is(s.lockErr, ErrServerUnconfirmed) {
			// Confirmed now: an unlock opens it again.
			s.lockErr = nil
		}
		return ServerCheck{Active: true}, s.clearReport()
	}
	if !errors.Is(err, ErrSessionEnded) {
		return ServerCheck{}, err
	}
	rs, err := r.RetireStatus(ctx, auth, crypto.Hash{})
	rc := rs.Receipt
	if err == nil && (rc == nil || rc.DeviceID != k.deviceID || (rc.How != "revoked" && rc.How != "retired")) {
		err = errors.New("its retire-status names no departure of this device")
	}
	if err != nil {
		// The server's answer, but no report to record: locked in memory,
		// until it accepts the device again.
		why := fmt.Errorf("%w (the server refused this device a session; %v)", ErrServerUnconfirmed, err)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.gen.Load() == gen {
			if s.state != nil {
				s.dropLocked(why)
			} else {
				s.lockErr = why
			}
		}
		return ServerCheck{}, why
	}
	rep := ServerReport{AccountID: k.accountID, DeviceID: k.deviceID, How: rc.How, Seq: rc.Seq, H: rc.H, At: s.now()}
	s.mu.Lock()
	defer s.mu.Unlock()
	werr := s.writeReport(k.rec, rep)
	if unlocked && s.gen.Load() == gen && s.state != nil {
		s.dropLocked(ErrServerRevoked)
	}
	if werr != nil {
		return ServerCheck{Report: &rep}, fmt.Errorf("store: the server's report could not be recorded on disk: %w", werr)
	}
	s.lockErr = ErrServerRevoked
	s.verifyReport(k.rec)
	return ServerCheck{Report: &rep}, nil
}

// ProveRevocation asks the server for the proof of the departure it
// reported (server-revoked.json) and verifies it from this device's
// verified head. If it verifies, this device's copy of the vault is wiped
// (wipeRevoked) and ErrDeviceRevoked is returned; if it does not, nothing
// changes and the error says why (ErrProofRefused, or the server's error).
// A proof that verified, followed by a wipe that did not finish, returns
// an error that matches both ErrDeviceRevoked and ErrWipeIncomplete: the
// revocation is proven, and the next start finishes the wipe. ErrNoReport
// means there is nothing to prove. A lock or Close cancels it. passphrase
// is CheckServer's.
func (s *Store) ProveRevocation(ctx context.Context, r ServerChecker, passphrase []byte) error {
	if err := s.lockSyncCtx(ctx); err != nil {
		return err
	}
	defer s.syncMu.Unlock()
	s.mu.Lock()
	rep, _, err := s.readReport()
	if err == nil && rep == nil {
		err = ErrNoReport
	}
	if err != nil {
		s.mu.Unlock()
		return err
	}
	k, err := s.checkKeyLocked(passphrase)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	defer k.close()
	s.verifyReport(k.rec)
	ctx, _, untrack := s.trackRequest(ctx)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		untrack()
		s.mu.Unlock()
	}()
	auth := k.key.auth(k.accountID, k.deviceID)
	rc, err := verifyRevocation(ctx, r, auth, k.st, k.deviceID)
	if err != nil {
		return err
	}
	proven := fmt.Errorf("%w (device %v, %s by the entry at seq %d, verified)", ErrDeviceRevoked, k.deviceID, rc.How, rc.Seq)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner == nil || s.closing {
		return incompleteWipe(proven, ErrClosed)
	}
	if s.state != nil {
		s.dropLocked(ErrServerRevoked)
	}
	return s.wipeRevoked(RevocationRecord{
		V: 1, AccountID: k.accountID, DeviceID: k.deviceID, How: rc.How, Seq: rc.Seq, H: rc.H, At: s.now(),
	}, proven)
}

// incompleteWipe is the error of a proven revocation (proven matches
// ErrDeviceRevoked) whose wipe failed with err.
func incompleteWipe(proven, err error) error {
	return fmt.Errorf("%w; %w (%w)", proven, ErrWipeIncomplete, err)
}

// verifyRevocation fetches the proof page by page and checks it from st,
// the verified state: every entry passes vaultlog.CheckHeader on top of
// the one before, and the receipt's entry, the last, has the receipt's H
// and removes self as the receipt says. Nothing it reads is written.
func verifyRevocation(ctx context.Context, r ServerChecker, auth DeviceAuth, st *vaultlog.State, self model.ID) (DeviceReceipt, error) {
	refuse := func(format string, args ...any) (DeviceReceipt, error) {
		return DeviceReceipt{}, fmt.Errorf("%w: %s", ErrProofRefused, fmt.Sprintf(format, args...))
	}
	pre := st
	var want *DeviceReceipt
	for n := 0; n < maxProofEntries; {
		entries, rc, err := r.RevocationProof(ctx, auth, pre.Head.Seq)
		if err != nil {
			return DeviceReceipt{}, err
		}
		switch {
		case want == nil:
			want = &rc
		case rc != *want:
			return refuse("the server's receipt changed while it sent the proof")
		}
		if rc.DeviceID != self || (rc.How != "revoked" && rc.How != "retired") {
			return refuse("the receipt is not this device's departure")
		}
		if rc.Seq <= st.Head.Seq {
			return refuse("the receipt names seq %d, which this device holds already and which does not remove it", rc.Seq)
		}
		if len(entries) == 0 {
			return refuse("the server sent no entry past seq %d", pre.Head.Seq)
		}
		for _, c := range entries {
			n++
			if c.Wire == nil {
				return refuse("entry %d has no wire", c.Seq)
			}
			h, err := c.Wire.Entry.Hash()
			if err != nil || c.Wire.Entry.Seq != c.Seq || !h.Equal(c.H) {
				return refuse("entry %d does not match its seq and H", c.Seq)
			}
			cand, err := vaultlog.CheckHeader(pre, c.Wire)
			if err != nil {
				return refuse("entry %d: %v", c.Seq, err)
			}
			removes := (rc.How == "revoked" && cand.Revokes(self)) || (rc.How == "retired" && cand.Retires(self))
			if c.Seq == rc.Seq {
				if !h.Equal(rc.H) || !removes {
					return refuse("the entry at seq %d does not remove this device as the receipt says", c.Seq)
				}
				return rc, nil
			}
			if cand.Revokes(self) || cand.Retires(self) {
				return refuse("entry %d removes this device, but the receipt names seq %d", c.Seq, rc.Seq)
			}
			pre = cand.Post
		}
	}
	return refuse("the proof is longer than %d entries", maxProofEntries)
}

// LockFor locks the vault, as Lock does, and records why: until the next
// unlock, every use fails with reason when it is ErrOfflineTooLong.
func (s *Store) LockFor(reason error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropLocked(reason)
}

// WipeRevoked wipes this device's copy of the vault once a verified
// revocation (ErrDeviceRevoked: a checkpoint a pull verified, or a proof)
// is recorded, as a logout does. It does nothing for a device that is not
// known to be revoked. It returns ErrDeviceRevoked once the wipe is done.
func (s *Store) WipeRevoked() error {
	if err := s.lockSync(); err != nil {
		return err
	}
	defer s.syncMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner == nil {
		return ErrClosed
	}
	if err := s.checkRevoked(); !errors.Is(err, ErrDeviceRevoked) {
		return err
	}
	rec := RevocationRecord{V: 1, How: "revoked", At: s.now()}
	b, err := os.ReadFile(s.l.revokedFile())
	var f revokedFile
	if err == nil && canonjson.Unmarshal(b, &f) == nil && f.V == 1 {
		rec.DeviceID, rec.Seq, rec.H = f.DeviceID, f.Seq, f.H
	}
	return s.wipeRevoked(rec, s.revoked)
}

// wipeRevoked records rec beside device.json, journals RETIRED with the
// outcome departed, and runs the logout's cleanup (cleanupRetired): the
// outbox, the cache, every device record and device.json go, and the mark
// that the daemon owes the ssh config is left (LogoutCleanupPending). The
// store is revoked with why from then on. It returns why once all of that
// is done, and otherwise an error that matches why and ErrWipeIncomplete:
// a crash or a failure before the journal leaves the report, so the next
// start proves the revocation again, and one after it leaves the journal,
// whose cleanup the next Open finishes. The caller holds s.mu and syncMu;
// the store is locked.
func (s *Store) wipeRevoked(rec RevocationRecord, why error) error {
	if err := s.wipeRevokedSteps(rec, why); err != nil {
		return incompleteWipe(why, err)
	}
	return why
}

func (s *Store) wipeRevokedSteps(rec RevocationRecord, why error) error {
	cfg, err := s.readDeviceConfig()
	if err != nil {
		return err
	}
	if rec.AccountID.IsZero() {
		rec.AccountID = cfg.AccountID
	}
	if rec.DeviceID.IsZero() {
		rec.DeviceID = cfg.DeviceID
	}
	if f, err := s.l.readServerFile(); err == nil && f != nil {
		rec.Server, rec.Email = f.Server, f.Email
	}
	var vaultID model.ID
	if stored, _, err := s.readStoredState(); err == nil && stored != nil {
		vaultID = stored.VaultID
	}
	b, err := canonjson.Marshal(rec)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.l.revocationFile(), b); err != nil {
		return err
	}
	if j, err := s.readRetireFile(); err != nil {
		return err
	} else if j == nil || j.State != StateRetired {
		unlock, err := s.lockFile()
		if err != nil {
			return err
		}
		j := &retireJournal{V: retireVersion, State: StateRetired, Outcome: OutcomeDeparted,
			AccountID: cfg.AccountID, VaultID: vaultID, DeviceID: cfg.DeviceID, KeyStore: cfg.Store, Records: retireRecords(cfg)}
		t := &txn{}
		err = putRetirement(t, j)
		if err == nil {
			err = s.commitTxn(t)
		}
		unlock()
		if err != nil {
			return err
		}
	}
	s.setRevoked(why)
	if s.state != nil {
		s.dropLocked(why)
	}
	s.lockErr = why
	return s.cleanupRetired()
}
