package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Slice E3b: the store side of the authflow review's findings.

// setRecordSecretKey rewrites s's device record, durably, with sk as its
// Secret Key, as a device key store that was tampered with (or an older
// build) would leave it.
func setRecordSecretKey(t *testing.T, s *Store, sk string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.rec.clone()
	next.SecretKey = sk
	if err := s.deviceStore(s.devCfg).storeDurably(next); err != nil {
		t.Fatal(err)
	}
}

// Finding P1: a user with the Recovery Key and no Secret Key recovers. The
// sign-in takes no Secret Key, and the record holds none only while the
// recovery is due; the recovery's checkpoint stores the new one before it
// posts, so a crash between its commit and AckKit still leaves a record
// that unlocks; and the new Secret Key, stored, unlocks with the new
// password afterwards.
func TestRecoveryWithoutSecretKey(t *testing.T) {
	ctx := context.Background()
	d := newSignInFix(t)
	cfg := testConfig(t)
	p := d.params(t)
	p.Method, p.SecretKey = SignInRecovery, ""
	s, res, err := SignIn(ctx, cfg, d.srv.login(t), p)
	if err != nil {
		t.Fatalf("a recovery sign-in without the Secret Key: %v", err)
	}
	track(t, cfg, s)
	if !res.CheckpointDue {
		t.Fatal("no checkpoint due")
	}
	if sk := storedSecretKey(t, cfg, s); sk != "" {
		t.Fatalf("the record holds a Secret Key nobody gave: %q", sk)
	}
	// It unlocks while the recovery is due.
	s = open(t, cfg)
	if info := s.Info(); info.Locked {
		t.Fatalf("the recovering device does not reopen: %s", info.LockReason)
	}
	// A password sign-in still needs the Secret Key.
	pw := d.params(t)
	pw.SecretKey = ""
	if _, _, err := SignIn(ctx, testConfig(t), d.srv.login(t), pw); err == nil || !strings.Contains(err.Error(), "not a Secret Key") {
		t.Errorf("a password sign-in without the Secret Key: %v", err)
	}

	// The server commits the recovery's checkpoint and the process dies
	// before its kit is acknowledged: the record already holds its Secret
	// Key, so the device unlocks once the commit ends the recovery.
	s.testHook = crashAt("checkpoint:posted")
	if _, err := s.RecoveryCheckpoint(ctx, d.r, []byte(newPassword), CheckpointOptions{}); !errors.Is(err, errCrash) {
		t.Fatalf("crash: %v", err)
	}
	held := storedSecretKey(t, cfg, s)
	if held == "" {
		t.Fatal("the recovery's candidate was posted with no Secret Key in the record")
	}
	s = open(t, cfg)
	pull(t, s, d.r)
	if si, err := s.ServerInfo(); err != nil || si.CheckpointDue {
		t.Fatalf("still due after the commit verified: %+v %v", si, err)
	}
	s = open(t, cfg)
	if info := s.Info(); info.Locked {
		t.Fatalf("the recovered device does not reopen before AckKit: %s", info.LockReason)
	}
	kit, err := s.RecoveryCheckpoint(ctx, d.r, []byte(newPassword), CheckpointOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if kit.SecretKey != held || !opensAccount(t, s, newPassword, kit.SecretKey) {
		t.Fatal("the kit's Secret Key is not the one stored, or does not open the account")
	}
	if err := s.AckKit(); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	gen := s.state.Creds.Gen
	s.mu.Unlock()
	if g := diskDeviceConfig(t, cfg).SecretKeyGen; g.DeviceID != deviceID(t, s) || g.Gen != gen {
		t.Errorf("secret_key_gen %+v; want this device at gen %d", g, gen)
	}
	// A later password unlock uses the stored Secret Key with the new
	// password.
	s.Lock()
	if err := s.UnlockWithPasswordRemote(ctx, d.r, []byte(newPassword), ""); err != nil {
		t.Fatalf("password unlock with the stored Secret Key: %v", err)
	}
	if sk := storedSecretKey(t, cfg, s); sk != kit.SecretKey {
		t.Error("the replacement device record does not keep the new Secret Key")
	}
}

// Finding P1, the refusal: a record with no Secret Key unlocks only for a
// device enrolled by approval or a recovery that is due. A device signed in
// with the password, or a recovered one whose checkpoint committed, stays
// locked with one.
func TestEmptySecretKeyRefusedUnlessEnrolledOrRecovering(t *testing.T) {
	ctx := context.Background()
	t.Run("password sign-in", func(t *testing.T) {
		d := newSignInFix(t)
		cfg := testConfig(t)
		s, _, err := SignIn(ctx, cfg, d.srv.login(t), d.params(t))
		if err != nil {
			t.Fatal(err)
		}
		track(t, cfg, s)
		setRecordSecretKey(t, s, "")
		if info := open(t, cfg).Info(); !info.Locked || !strings.Contains(info.LockReason, "not enrolled by approval") {
			t.Errorf("locked=%v reason %q", info.Locked, info.LockReason)
		}
	})
	t.Run("recovery done", func(t *testing.T) {
		d := newSignInFix(t)
		cfg := testConfig(t)
		p := d.params(t)
		p.Method, p.SecretKey = SignInRecovery, ""
		s, _, err := SignIn(ctx, cfg, d.srv.login(t), p)
		if err != nil {
			t.Fatal(err)
		}
		track(t, cfg, s)
		if _, err := s.RecoveryCheckpoint(ctx, d.r, []byte(newPassword), CheckpointOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := s.AckKit(); err != nil {
			t.Fatal(err)
		}
		setRecordSecretKey(t, s, "")
		if info := open(t, cfg).Info(); !info.Locked || !strings.Contains(info.LockReason, "no recovery is due") {
			t.Errorf("locked=%v reason %q", info.Locked, info.LockReason)
		}
	})
}

// Finding P2 (passwd): a password change that names the devices the user
// was shown asks about any other active device before its first journal,
// one that joined while the passwords were typed, and journals the
// answer; it never keeps it silently.
func TestPasswordChangeAsksAboutUnshownDevices(t *testing.T) {
	ctx := context.Background()
	for _, keep := range []bool{false, true} {
		t.Run(fmt.Sprintf("keep %v", keep), func(t *testing.T) {
			a, b, r := newCkptPair(t)
			aID, bID := deviceID(t, a.s), deviceID(t, b.s)
			shown := []model.ID{aID, bID}
			// The tablet joins after the list was shown.
			c := secondDeviceNamed(t, a, r, "tablet")
			cID := deviceID(t, c.s)
			_, err := a.s.ChangePasswordRemote(ctx, r, []byte(testPassword), []byte(newPassword), CheckpointOptions{Shown: shown})
			var nd *NewDevicesError
			if !errors.As(err, &nd) || !slices.Equal(nd.Devices, []model.ID{cID}) {
				t.Fatalf("a password change with an unshown device: %v; want a NewDevicesError naming it", err)
			}
			if journalExists(t, a.cfg) {
				t.Error("the change was journaled before the unshown device was decided")
			}
			// Excluding a shown device contradicts the change.
			if _, err := a.s.ChangePasswordRemote(ctx, r, []byte(testPassword), []byte(newPassword),
				CheckpointOptions{Shown: shown, Keep: []string{cID.String()}, Exclude: []string{bID.String()}}); !errors.Is(err, ErrContradictsJournal) {
				t.Errorf("excluding a shown device: %v; want ErrContradictsJournal", err)
			}
			opts := CheckpointOptions{Shown: shown, Exclude: []string{cID.String()}}
			if keep {
				opts = CheckpointOptions{Shown: shown, Keep: []string{"tablet"}}
			}
			// The answer is journaled with the change.
			a.s.testHook = crashAt("checkpoint:post")
			if _, err := a.s.ChangePasswordRemote(ctx, r, []byte(testPassword), []byte(newPassword), opts); !errors.Is(err, errCrash) {
				t.Fatalf("crash before the post: %v", err)
			}
			a.s.testHook = nil
			a.s.mu.Lock()
			unlock, err := a.s.lockFile()
			if err != nil {
				a.s.mu.Unlock()
				t.Fatal(err)
			}
			j, err := a.s.readCheckpointJournal(a.s.rec, a.s.state.VaultID)
			unlock()
			a.s.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			j.zero()
			if !slices.Equal(j.Shown, sortIDs(slices.Clone(shown))) || slices.Contains(j.Survivors, cID) != keep || slices.Contains(j.Targets, cID) == keep {
				t.Errorf("journal shown %v survivors %v targets %v", j.Shown, j.Survivors, j.Targets)
			}
			kit, err := a.s.ChangePasswordRemote(ctx, r, []byte(testPassword), []byte(newPassword), opts)
			if err != nil {
				t.Fatal(err)
			}
			if !serverActive(t, r, aID) || !serverActive(t, r, bID) || serverActive(t, r, cID) != keep {
				t.Errorf("after the change: a %v b %v c %v; want c %v", serverActive(t, r, aID), serverActive(t, r, bID), serverActive(t, r, cID), keep)
			}
			if !opensAccount(t, a.s, newPassword, kit.SecretKey) {
				t.Error("the new kit does not open the account")
			}
			if err := a.s.AckKit(); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("only passwd", func(t *testing.T) {
		a, _, r := newCkptPair(t)
		if _, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{Shown: []model.ID{}}); !errors.Is(err, errShownOnlyPasswd) {
			t.Errorf("rotate with Shown: %v", err)
		}
	})
}

// A checkpoint journal from before shown (v 1) still opens: its checkpoint
// resumes and commits.
func TestCheckpointJournalV1StillOpens(t *testing.T) {
	ctx := context.Background()
	a, _, r := newCkptPair(t)
	a.s.testHook = crashAt("checkpoint:post")
	if _, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{}); !errors.Is(err, errCrash) {
		t.Fatalf("crash before the post: %v", err)
	}
	a.s.testHook = nil
	a.s.mu.Lock()
	unlock, err := a.s.lockFile()
	if err != nil {
		a.s.mu.Unlock()
		t.Fatal(err)
	}
	func() {
		defer unlock()
		defer a.s.mu.Unlock()
		j, err := a.s.readCheckpointJournal(a.s.rec, a.s.state.VaultID)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := canonjson.Marshal(ckptJournalV1{V: 1, Kind: j.Kind, Author: j.Author, Survivors: j.Survivors,
			Targets: j.Targets, Names: j.Names, Candidates: j.Candidates})
		if err != nil {
			t.Fatal(err)
		}
		key, err := a.s.rec.localKey()
		if err != nil {
			t.Fatal(err)
		}
		env, err := crypto.SealAEAD(key, pt, checkpointAAD(a.s.state.VaultID))
		key.Zero()
		if err != nil {
			t.Fatal(err)
		}
		b, err := canonjson.Marshal(ckptFile{V: checkpointVersion, VaultID: a.s.state.VaultID, Sealed: env})
		if err != nil {
			t.Fatal(err)
		}
		if err := writeFileAtomic(a.s.l.checkpointFile(), b); err != nil {
			t.Fatal(err)
		}
	}()
	a.s = open(t, a.cfg)
	if st, err := a.s.PendingCheckpoint(); err != nil || st == nil || st.Kind != CheckpointRotate || st.Live == nil {
		t.Fatalf("the v1 journal: %+v %v", st, err)
	}
	if _, err := a.s.ResumeCheckpoint(ctx, r); err != nil {
		t.Fatalf("resuming the v1 journal: %v", err)
	}
	if err := a.s.AckKit(); err != nil {
		t.Fatal(err)
	}
}

// codePublisher is the fake server as a Publisher whose registration codes
// are refused as the real server refuses one it does not know (401:
// ErrRegistrationRefused), with entryErr, when set, failing the reads.
type codePublisher struct {
	publisher
	entryErr error
}

func (p *codePublisher) Signup(ctx context.Context, req *SignupRequest) (vaultlog.Head, error) {
	if req.RegistrationCode != p.f.code {
		p.f.smu.Lock()
		p.f.signups++
		p.f.smu.Unlock()
		return vaultlog.Head{}, fmt.Errorf("%w: fake: 401", ErrRegistrationRefused)
	}
	return p.publisher.Signup(ctx, req)
}

func (p *codePublisher) EntryAt(ctx context.Context, auth DeviceAuth, seq uint64) (Committed, error) {
	if p.entryErr != nil {
		return Committed{}, p.entryErr
	}
	return p.publisher.EntryAt(ctx, auth, seq)
}

// Finding P2 (signup): a registration code the server refused, with no
// vault published, is replaced in the journal, sealed, and the same upload
// publishes with the new one. A code whose outcome is uncertain, or that
// another publication consumed, is never replaced.
func TestReplaceRegistrationCode(t *testing.T) {
	ctx := context.Background()
	typo := pubOpts
	typo.RegistrationCode = "invite-typo"
	t.Run("refused", func(t *testing.T) {
		f, srv := publishFixture(t)
		p := &codePublisher{publisher: publisher{srv}}
		if err := f.s.ReplaceRegistrationCode("invite-1"); !errors.Is(err, ErrNoPublication) {
			t.Errorf("replace with nothing pending: %v", err)
		}
		_, err := f.s.Publish(ctx, p, typo)
		if !errors.Is(err, ErrRegistrationRefused) || !errors.Is(err, ErrPublicationAbsent) {
			t.Fatalf("publish with a wrong code: %v; want ErrRegistrationRefused", err)
		}
		if srv.signups != 1 {
			t.Errorf("%d signups; a refused code is not posted again", srv.signups)
		}
		before, err := f.s.Publication()
		if err != nil || before == nil {
			t.Fatalf("pending publication %+v %v", before, err)
		}
		if err := f.s.ReplaceRegistrationCode(""); err == nil {
			t.Error("an empty code was accepted")
		}
		f.s.testHook = crashAt("publish:replace-code")
		if err := f.s.ReplaceRegistrationCode("invite-1"); !errors.Is(err, errCrash) {
			t.Fatalf("crash: %v", err)
		}
		f.s.testHook = nil
		if err := f.s.ReplaceRegistrationCode("invite-1"); err != nil {
			t.Fatalf("replace: %v", err)
		}
		if b := readFile(t, f.s.l.publishFile()); strings.Contains(b, "invite-1") || strings.Contains(b, "invite-typo") {
			t.Error("publish.json holds a registration code in the clear")
		}
		f.s.mu.Lock()
		j, err := f.s.readPublication(f.s.rec, f.s.state.VaultID)
		f.s.mu.Unlock()
		if err != nil || j.RegistrationCode != "invite-1" {
			t.Fatalf("journaled code after the replacement: %v", err)
		}
		if after, err := f.s.Publication(); err != nil || after == nil || after.Upload != before.Upload || after.VaultID != before.VaultID {
			t.Errorf("the upload changed: %+v, was %+v (%v)", after, before, err)
		}
		// Only once per refusal.
		if err := f.s.ReplaceRegistrationCode("invite-2"); !errors.Is(err, ErrPublicationUncertain) {
			t.Errorf("a second replacement: %v; want ErrPublicationUncertain", err)
		}
		pub, err := f.s.ResumePublish(ctx, p)
		if err != nil {
			t.Fatalf("publish with the replaced code: %v", err)
		}
		if !f.s.ServerBacked() || pub.VaultID != before.VaultID {
			t.Errorf("published %+v, server-backed %v", pub, f.s.ServerBacked())
		}
		sameLog(t, f.cfg, srv)
	})
	for name, c := range map[string]struct {
		pub   func(srv *fakeServer) Publisher
		setup func(srv *fakeServer)
	}{
		// The post's outcome is not known: a lost response.
		"lost response": {
			pub:   func(srv *fakeServer) Publisher { return publisher{srv} },
			setup: func(srv *fakeServer) { srv.onSignup = func() (bool, error) { return false, errLostResponse } },
		},
		// Refused, but the vault's absence was never read.
		"read fails": {
			pub: func(srv *fakeServer) Publisher {
				return &codePublisher{publisher: publisher{srv}, entryErr: errDown}
			},
		},
		// Another publication consumed the code: a conflict, not a
		// refusal.
		"consumed": {
			pub: func(srv *fakeServer) Publisher { return publisher{srv} },
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, srv := publishFixture(t)
			opts := pubOpts
			if name != "lost response" {
				opts = typo
			}
			if c.setup != nil {
				c.setup(srv)
			}
			if _, err := f.s.Publish(ctx, c.pub(srv), opts); err == nil || errors.Is(err, ErrRegistrationRefused) {
				t.Fatalf("publish: %v", err)
			}
			if err := f.s.ReplaceRegistrationCode("invite-1"); !errors.Is(err, ErrPublicationUncertain) {
				t.Errorf("replace: %v; want ErrPublicationUncertain", err)
			}
		})
	}
	t.Run("lock in between", func(t *testing.T) {
		f, srv := publishFixture(t)
		if _, err := f.s.Publish(ctx, &codePublisher{publisher: publisher{srv}}, typo); !errors.Is(err, ErrRegistrationRefused) {
			t.Fatalf("publish: %v", err)
		}
		f.s.Lock()
		if err := f.s.Unlock(ctx); err != nil {
			t.Fatal(err)
		}
		if err := f.s.ReplaceRegistrationCode("invite-1"); !errors.Is(err, ErrPublicationUncertain) {
			t.Errorf("replace after a lock: %v; want ErrPublicationUncertain", err)
		}
	})
}

// G4: the enrollment's deadline is the persisted one, after a restart too.
func TestEnrollmentDeadline(t *testing.T) {
	x := newEnrollFix(t)
	start := time.Now().Add(-time.Minute).Truncate(time.Second)
	x.cfg.Now = func() time.Time { return start }
	e, _ := x.begin(t)
	want := start.Add(crypto.EnrollDeadline)
	if got := e.Deadline(); !got.Equal(want) {
		t.Fatalf("deadline %v; want %v", got, want)
	}
	x.cfg.Now = nil
	if got := x.resume(t, e).Deadline(); !got.Equal(want) {
		t.Errorf("deadline after a restart %v; want %v", got, want)
	}
}

// The sentinels: a chal or a delivery refused for itself is
// ErrChalInvalid or ErrDeliveryInvalid, and changes nothing; a failure to
// save, or to read the log, is neither.
func TestEnrollmentSentinels(t *testing.T) {
	ctx := context.Background()
	x := newEnrollFix(t)
	e, commit := x.begin(t)
	id, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetEnrollID(id); err != nil {
		t.Fatal(err)
	}
	if err := x.a.s.ApproveStart(id); err != nil {
		t.Fatal(err)
	}
	chal, err := x.a.s.ApproveCommit(&commit)
	if err != nil {
		t.Fatal(err)
	}
	wrong := chal
	wrong.EnrollID, _ = vaultlog.NewID()
	if _, err := e.HandleChal(&wrong); !errors.Is(err, ErrChalInvalid) || !errors.Is(err, crypto.ErrWrongEnrollID) {
		t.Errorf("a chal for another enrollment: %v; want ErrChalInvalid", err)
	}
	bad := chal
	bad.NA = bad.NA[:4]
	if _, err := e.HandleChal(&bad); !errors.Is(err, ErrChalInvalid) {
		t.Errorf("a malformed chal: %v; want ErrChalInvalid", err)
	}
	// A chal that can't be saved is not the chal's fault.
	e.Close()
	e2, err := resumeEnrollment(x.cfg, crashAt("enroll:persist"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e2.HandleChal(&chal); !errors.Is(err, errCrash) || errors.Is(err, ErrChalInvalid) {
		t.Errorf("a chal that was not saved: %v; want the crash, not ErrChalInvalid", err)
	}
	e2.Close()
	e = x.resume(t, e)
	open, err := e.HandleChal(&chal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.HandleChal(&chal); !errors.Is(err, ErrChalInvalid) || !errors.Is(err, crypto.ErrChalAfterReveal) {
		t.Errorf("a second chal: %v; want ErrChalInvalid", err)
	}
	if _, _, err := x.a.s.ApproveOpen(&open); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	env := x.approve(t)
	tampered := env
	tampered.CT = slices.Clone(env.CT)
	tampered.CT[len(tampered.CT)/2] ^= 1
	if _, err := e.Install(ctx, x.remote(), &tampered); !errors.Is(err, ErrDeliveryInvalid) {
		t.Errorf("a tampered delivery: %v; want ErrDeliveryInvalid", err)
	}
	// A log that can't be read is not the delivery's fault.
	x.srv.down = errDown
	if _, err := e.Install(ctx, x.remote(), &env); !errors.Is(err, errDown) || errors.Is(err, ErrDeliveryInvalid) {
		t.Errorf("a delivery with the log down: %v; want errDown, not ErrDeliveryInvalid", err)
	}
	x.srv.down = nil
	if e.State() != crypto.DeviceConfirmed {
		t.Fatalf("state %s; want CONFIRMED", e.State())
	}
	if _, err := os.Lstat(x.cfg.DataDir + "/device.json"); !errors.Is(err, os.ErrNotExist) {
		t.Error("a refused delivery wrote device.json")
	}
	s, err := e.Install(ctx, x.remote(), &env)
	if err != nil {
		t.Fatal(err)
	}
	track(t, x.cfg, s)
	x.installed(t, s)
}

// A delivery that fails a check, whose staging then can't be undone, is an
// operational failure: the error must not match ErrDeliveryInvalid, so a
// caller does not discard it as a bad message and keep waiting.
func TestRefusedDeliveryWhoseUndoFailsIsNotInvalidInput(t *testing.T) {
	ctx := context.Background()
	x := newEnrollFix(t)
	e, commit := x.begin(t)
	x.reveal(t, e, commit)
	if err := e.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	if err := x.a.s.ApproveConfirm(true); err != nil {
		t.Fatal(err)
	}
	x.a.s.testHook = crashAt("approve:deliver")
	if _, err := x.a.s.ApproveFinish(ctx, x.r); !errors.Is(err, errCrash) {
		t.Fatalf("finish: %v", err)
	}
	x.a.s.testHook = nil
	h, err := x.a.s.entryHash(0)
	if err != nil {
		t.Fatal(err)
	}
	h[0] ^= 1 // a wrong anchor_h: the delivery fails a check
	env := x.rawDelivery(t, 0, h)
	e.s.testHook = crashAt("enroll:unstage") // undoing the staging fails
	_, err = e.Install(ctx, laxReader{x.srv}, &env)
	if err == nil {
		t.Fatal("install of a refused delivery succeeded")
	}
	if errors.Is(err, ErrDeliveryInvalid) {
		t.Errorf("install: %v; a failed undo must not read as an invalid delivery", err)
	}
	if !errors.Is(err, errCrash) {
		t.Errorf("install: %v; want the undo's failure", err)
	}
	if exists, _ := (layout{data: x.cfg.DataDir}).exists(); exists {
		t.Error("a refused delivery installed a vault")
	}
}
