package authflow_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/authflow"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// Slice E3b: the authflow review's findings that needed the store.

// Finding P2 (passwd): a device that joins while the user types the
// passwords was not in the list shown; the change asks about it instead
// of keeping it.
func TestPasswdAsksAboutDeviceJoiningDuringPrompts(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	env1, v1, kit := signedUp(t, w)
	_, v2 := loggedIn(t, w, "laptop", password, kit.SecretKey)
	id1, id2 := deviceID(t, v1), deviceID(t, v2)
	var v3 *authflow.Vault
	ui1 := env1.UI.(*scriptUI)
	ui1.newPassword = newPassword
	ui1.onPassword = func() { _, v3 = loggedIn(t, w, "tablet", password, kit.SecretKey) }
	ui1.keepNew = func([]store.DeviceListing) []model.ID { return nil }
	cr, err := authflow.ChangePassword(ctx, env1, v1)
	if err != nil {
		t.Fatalf("passwd: %v", err)
	}
	id3 := deviceID(t, v3)
	if len(ui1.shown) != 1 || len(ui1.shown[0]) != 2 {
		t.Errorf("devices shown: %+v; want devices 1 and 2", ui1.shown)
	}
	if len(ui1.newDevices) != 1 || len(ui1.newDevices[0]) != 1 || ui1.newDevices[0][0].ID != id3 {
		t.Fatalf("new devices asked about: %+v; want only the tablet", ui1.newDevices)
	}
	if got, want := deviceIDs(t, v1), sortedIDs(id1, id2); !slices.Equal(got, want) || len(cr.Devices) != 2 {
		t.Errorf("devices after the change: %v; want %v (the tablet, not kept, revoked)", got, want)
	}
}

// Finding P2 (signup): a registration code the server refuses is asked
// for again, and the same vault publishes with the new one; a code that
// another publication consumed is not replaced.
func TestSignupAsksAgainForARefusedCode(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	local := func(t *testing.T, env *authflow.Env) (*store.Store, store.Kit) {
		t.Helper()
		p, err := store.PrepareInit(env.Config, store.InitOptions{Password: []byte(password)})
		if err != nil {
			t.Fatal(err)
		}
		s, err := p.Commit()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		snippet(t, s, "deploy")
		return s, p.Kit()
	}
	code := w.invite(t)
	ui := &scriptUI{codes: []string{code}}
	env := w.env(t, "desk", ui)
	s, kit := local(t, env)
	res, err := authflow.Signup(ctx, env, authflow.SignupOptions{Email: email, RegistrationCode: "not-an-invite-code", Local: s})
	if err != nil {
		t.Fatalf("signup after a refused code: %v", err)
	}
	if ui.codePrompts != 1 || !s.ServerBacked() || res.Created {
		t.Fatalf("signup %+v: %d code prompts, server-backed %v", res, ui.codePrompts, s.ServerBacked())
	}
	_, v2 := loggedIn(t, w, "laptop", password, kit.SecretKey)
	wantSnippets(t, v2.Store, "device 2", "deploy")
	if v2.VaultID != res.Vault.VaultID {
		t.Errorf("device 2 in %v; want %v", v2.VaultID, res.Vault.VaultID)
	}

	// The same code again, for another vault: consumed, a conflict, never
	// asked about.
	ui2 := &scriptUI{codes: []string{w.invite(t)}}
	env2 := w.env(t, "spare", ui2)
	s2, _ := local(t, env2)
	if _, err := authflow.Signup(ctx, env2, authflow.SignupOptions{Email: email, RegistrationCode: code, Local: s2}); !errors.Is(err, syncclient.ErrRegistrationConflict) {
		t.Fatalf("signup with a consumed code: %v; want ErrRegistrationConflict", err)
	}
	if ui2.codePrompts != 0 {
		t.Errorf("a consumed code was asked about %d times", ui2.codePrompts)
	}
	if err := s2.ReplaceRegistrationCode(w.invite(t)); !errors.Is(err, store.ErrPublicationUncertain) {
		t.Errorf("replacing a consumed code: %v; want ErrPublicationUncertain", err)
	}
}

// Finding P2 (vaultIDOf): the vault ID comes from the store's state, never
// from an entry file on disk, unlocked or locked in a logout.
func TestVaultIDIsNotReadFromEntryFiles(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	env1, v1, kit := signedUp(t, w)
	env2, v2 := loggedIn(t, w, "laptop", password, kit.SecretKey)
	// Another vault's genesis entry.
	other := w.env(t, "other", &scriptUI{})
	p, err := store.PrepareInit(other.Config, store.InitOptions{Password: []byte(password)})
	if err != nil {
		t.Fatal(err)
	}
	o, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	o.Close()
	foreign, err := os.ReadFile(filepath.Join(other.Config.DataDir, "vault", "entries", "0.json"))
	if err != nil {
		t.Fatal(err)
	}
	// tamper puts the foreign entry in env's vault and returns what it
	// replaced.
	tamper := func(env *authflow.Env) []byte {
		t.Helper()
		path := filepath.Join(env.Config.DataDir, "vault", "entries", "0.json")
		orig, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, foreign, 0o600); err != nil {
			t.Fatal(err)
		}
		return orig
	}

	orig := tamper(env1)
	v, err := authflow.NewVault(env1.Config, v1.Store, env1.Client)
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	if v.VaultID != v1.VaultID {
		t.Errorf("NewVault names vault %v; want %v", v.VaultID, v1.VaultID)
	}
	if err := os.WriteFile(filepath.Join(env1.Config.DataDir, "vault", "entries", "0.json"), orig, 0o600); err != nil {
		t.Fatal(err)
	}

	// A logout locked in RETIRING addresses the vault the stored state
	// names (ServerInfo). A tampered entry 0 can't redirect it either, but
	// it can't be shown here: the retirement's own verification refuses
	// that entry before anything is sent.
	if _, err := v2.Store.Logout(ctx, nil, store.LogoutOptions{}); !errors.Is(err, store.ErrLogoutPending) {
		t.Fatalf("logout without a server: %v; want ErrLogoutPending", err)
	}
	if !v2.Store.Info().Locked {
		t.Fatal("RETIRING left the vault unlocked")
	}
	if si, err := v2.Store.ServerInfo(); err != nil || si.VaultID != v1.VaultID {
		t.Fatalf("locked server info %+v %v; want vault %v", si, err, v1.VaultID)
	}
	res, err := authflow.Logout(ctx, env2, v2.Store, store.LogoutOptions{})
	if err != nil || !res.Done || res.Outcome != store.OutcomeCommitted {
		t.Fatalf("logout resumed: %+v %v; want done", res, err)
	}
	if got := deviceIDs(t, v1); !slices.Equal(got, []model.ID{deviceID(t, v1)}) {
		t.Errorf("devices after the logout: %v; want only device 1", got)
	}
}

// G1: a device enrolls by approval without being told the vault ID; it
// learns it from its session once it is added.
func TestApprovalLoginWithoutVaultID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	w := newWorld(t)
	envA, vA, _ := signedUp(t, w)
	setSAS(envA, yes)
	d := startEnrollIn(t, ctx, w, model.ID{}, yes)
	if _, err := authflow.Approve(ctx, envA, vA, d.code); err != nil {
		t.Fatalf("approve: %v", err)
	}
	res, err := d.wait(t)
	if err != nil {
		t.Fatalf("D without the vault ID: %v", err)
	}
	if res.Vault.VaultID != vA.VaultID {
		t.Errorf("D in vault %v; want %v", res.Vault.VaultID, vA.VaultID)
	}
	wantSnippets(t, res.Vault.Store, "the approved device", "deploy")
}

// G4: a resumed enrollment waits only until its persisted deadline, not
// for a new one from the time it resumed.
func TestEnrollResumeKeepsTheDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	w := newWorld(t)
	routing := make(chan string, 1)
	ui := &scriptUI{routing: routing}
	env := w.env(t, "phone", ui)
	// The enrollment began long enough ago that 5 seconds of it are left.
	env.Config.Now = func() time.Time { return time.Now().Add(5*time.Second - crypto.EnrollDeadline) }
	first, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, err := authflow.LoginApprove(first, env, authflow.EnrollOptions{Email: email, DeviceName: "phone"})
		done <- err
	}()
	<-routing
	stop()
	err := <-done
	var ie *authflow.EnrollInterruptedError
	if !errors.As(err, &ie) || ie.Mailbox == nil {
		t.Fatalf("D stopped: %v; want an *EnrollInterruptedError", err)
	}
	env.Config.Now = nil
	start := time.Now()
	_, err = authflow.LoginApprove(ctx, env, authflow.EnrollOptions{Email: email, DeviceName: "phone", Mailbox: ie.Mailbox})
	if !errors.Is(err, crypto.ErrEnrollExpired) {
		t.Fatalf("D resumed past its deadline: %v; want ErrEnrollExpired", err)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("D waited %v past its persisted deadline", d)
	}
}

// The sentinels: a failure to check a delivery that is not the delivery's
// fault (here the log answering 404, which is not retryable) interrupts D
// at once instead of being taken for an invalid delivery and waited past;
// D resumes and installs once the log answers.
func TestEnrollUnclassifiedErrorIsOperational(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	w := newWorld(t)
	envA, vA, _ := signedUp(t, w)
	tp := &relayTap{}
	var broken atomic.Bool
	broken.Store(true)
	f := tapFunc(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if broken.Load() && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vaults/") && tp.count("post deliver") > 0 {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusNotFound)
			rw.Write([]byte(`{"error":"not_found"}`))
			return
		}
		tp.serve(rw, r, next)
	})
	w.tap.Store(&f)
	setSAS(envA, yes)
	d := startEnroll(t, ctx, w, vA, yes)
	if _, err := authflow.Approve(ctx, envA, vA, d.code); err != nil {
		t.Fatalf("approve: %v", err)
	}
	start := time.Now()
	_, err := d.wait(t)
	var ie *authflow.EnrollInterruptedError
	if !errors.As(err, &ie) || ie.Mailbox == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("D with the log answering 404: %v; want an *EnrollInterruptedError for the 404", err)
	}
	if !errors.Is(err, syncclient.ErrNotFound) {
		t.Errorf("D's error %v does not carry the 404", err)
	}
	if el := time.Since(start); el > 30*time.Second {
		t.Errorf("D took %v to stop", el)
	}
	broken.Store(false)
	d.resume(ctx, authflow.EnrollOptions{Email: email, DeviceName: "phone", VaultID: vA.VaultID, Mailbox: ie.Mailbox})
	res, err := d.wait(t)
	if err != nil {
		t.Fatalf("D resumed: %v", err)
	}
	wantSnippets(t, res.Vault.Store, "the approved device", "deploy")
}
