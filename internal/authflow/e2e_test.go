package authflow_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/dalyem/hopkey/internal/authflow"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/server"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

const (
	password    = "correct horse battery staple"
	newPassword = "tr0ub4dor and three more words"
	email       = "Me@Example.COM"
)

// memRing is an in-memory store.Keyring.
type memRing struct {
	mu sync.Mutex
	m  map[string]string
	// failDelete fails that many deletions, as a keychain that is locked
	// for a moment would.
	failDelete atomic.Int32
}

func (r *memRing) Get(service, user string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.m[service+"/"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (r *memRing) Set(service, user, secret string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[service+"/"+user] = secret
	return nil
}

var errKeychain = errors.New("memRing: the keychain is locked")

func (r *memRing) Delete(service, user string) error {
	if r.failDelete.Add(-1) >= 0 {
		return errKeychain
	}
	r.failDelete.Store(0)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, service+"/"+user)
	return nil
}

// world is a real hop-server on SQLite behind an httptest TLS server whose
// certificate the clients trust. The server's clock runs skew ahead of the
// real one, and tap, when set, sees every request first.
type world struct {
	st     *server.SQLite
	origin string
	pool   *x509.CertPool
	skew   atomic.Int64 // a time.Duration
	tap    atomic.Pointer[tapFunc]
}

// tapFunc serves a request in the server's place; next is the server.
type tapFunc func(rw http.ResponseWriter, r *http.Request, next http.Handler)

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{}
	ts := httptest.NewUnstartedServer(nil)
	origin := "https://" + ts.Listener.Addr().String()
	st, err := server.OpenSQLite(filepath.Join(t.TempDir(), "hop.db"))
	if err != nil {
		t.Fatal(err)
	}
	r := server.Rate{N: 100_000, Per: time.Minute}
	rates := server.Rates{PreloginIP: r, PreloginEmail: r, LoginIP: r, LoginAccount: r, IP: r, Account: r, Device: r, EnrollIP: r, Claim: r}
	srv, err := server.New(context.Background(), server.Config{
		Origin: origin, Store: st, Rates: &rates,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:    func() time.Time { return time.Now().Add(time.Duration(w.skew.Load())) },
	})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	ts.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if f := w.tap.Load(); f != nil {
			(*f)(rw, r, h)
			return
		}
		h.ServeHTTP(rw, r)
	})
	ts.StartTLS()
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
		st.Close()
	})
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	w.st, w.origin, w.pool = st, origin, pool
	return w
}

// env is a device's environment: a data directory of its own, a client
// and a scripted UI.
func (w *world) env(t *testing.T, name string, ui *scriptUI) *authflow.Env {
	t.Helper()
	dir, err := os.MkdirTemp("", "hkauth")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	c, err := syncclient.New(w.origin, syncclient.Options{RootCAs: w.pool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	ui.t = t
	return &authflow.Env{
		Config: store.Config{
			DataDir: filepath.Join(dir, "data"), Keyring: &memRing{m: map[string]string{}},
			Getenv: func(string) string { return "" }, DeviceName: name,
		},
		Client: c, UI: ui, Backoff: 10 * time.Millisecond,
	}
}

func (w *world) invite(t *testing.T) string {
	t.Helper()
	code, err := server.CreateInvite(context.Background(), w.st, email, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// scriptUI answers every prompt from its fields. The zero value fails any
// prompt it has no answer for.
type scriptUI struct {
	t *testing.T

	mu          sync.Mutex
	password    string // the current master password
	newPassword string
	secretKey   string
	recoveryKey string
	// failNew fails NewPassword, as a UI with no way to ask would.
	failNew error
	// onPassword runs once, when Password is first asked.
	onPassword func()
	// failSAS fails the next ConfirmSAS, once.
	failSAS error
	// routing receives the routing code.
	routing chan string
	// sas answers ConfirmSAS; nil fails it.
	sas func(sas, name string) bool
	// keep answers ChooseSurvivors.
	keep func(authflow.SurvivorChoice) []string
	// keepNew answers ConfirmNewDevices.
	keepNew func([]store.DeviceListing) []model.ID
	// typeBack answers ConfirmKit; nil types back the kit shown.
	typeBack func(attempt int) authflow.KitTypeBack

	// What the UI was asked and shown.
	kits       []store.Kit
	staleSK    int // SecretKey prompts for a stale one
	skPrompts  int
	choices    []authflow.SurvivorChoice
	newDevices [][]store.DeviceListing
	shown      [][]store.DeviceListing
	sasShown   []string
}

var errNoAnswer = errors.New("scriptUI: no answer scripted")

func (u *scriptUI) Password(context.Context, authflow.Reason) ([]byte, error) {
	u.mu.Lock()
	f := u.onPassword
	u.onPassword = nil
	u.mu.Unlock()
	if f != nil {
		f()
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.password == "" {
		return nil, errNoAnswer
	}
	return []byte(u.password), nil
}

func (u *scriptUI) NewPassword(context.Context, authflow.Reason) ([]byte, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.failNew != nil {
		return nil, u.failNew
	}
	if u.newPassword == "" {
		return nil, errNoAnswer
	}
	return []byte(u.newPassword), nil
}

func (u *scriptUI) SecretKey(_ context.Context, _ authflow.Reason, stale bool) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.skPrompts++
	if stale {
		u.staleSK++
	}
	if u.secretKey == "" {
		return "", errNoAnswer
	}
	return u.secretKey, nil
}

func (u *scriptUI) RecoveryKey(context.Context) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.recoveryKey == "" {
		return "", errNoAnswer
	}
	return u.recoveryKey, nil
}

func (u *scriptUI) ShowRoutingCode(_ context.Context, code string) error {
	if u.routing == nil {
		return errNoAnswer
	}
	u.routing <- code
	return nil
}

func (u *scriptUI) ConfirmSAS(_ context.Context, sas, name string) (bool, error) {
	u.mu.Lock()
	u.sasShown = append(u.sasShown, sas)
	f, ferr := u.sas, u.failSAS
	u.failSAS = nil
	u.mu.Unlock()
	if ferr != nil {
		return false, ferr
	}
	if f == nil {
		return false, errNoAnswer
	}
	return f(sas, name), nil
}

func (u *scriptUI) ShowDevices(_ context.Context, d []store.DeviceListing) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.shown = append(u.shown, d)
	return nil
}

func (u *scriptUI) ChooseSurvivors(_ context.Context, c authflow.SurvivorChoice) ([]string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.choices = append(u.choices, c)
	if u.keep == nil {
		return nil, nil
	}
	return u.keep(c), nil
}

func (u *scriptUI) ConfirmNewDevices(_ context.Context, d []store.DeviceListing) ([]model.ID, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.newDevices = append(u.newDevices, d)
	if u.keepNew == nil {
		return nil, errNoAnswer
	}
	return u.keepNew(d), nil
}

func (u *scriptUI) ShowKit(_ context.Context, k store.Kit) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.kits = append(u.kits, k)
	return nil
}

func (u *scriptUI) ConfirmKit(_ context.Context, attempt int) (authflow.KitTypeBack, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.typeBack != nil {
		return u.typeBack(attempt), nil
	}
	k := u.kits[len(u.kits)-1]
	return authflow.KitTypeBack{SecretKey: store.LastGroup(k.SecretKey), RecoveryKey: store.LastGroup(k.RecoveryKey)}, nil
}

func (u *scriptUI) lastKit(t *testing.T) store.Kit {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.kits) == 0 {
		t.Fatal("no kit was shown")
	}
	return u.kits[len(u.kits)-1]
}

func snippet(t *testing.T, s *store.Store, name string) {
	t.Helper()
	if _, err := s.PutSnippet(context.Background(), model.Snippet{Name: name, Command: "echo " + name}); err != nil {
		t.Fatal(err)
	}
}

func wantSnippets(t *testing.T, s *store.Store, who string, want ...string) {
	t.Helper()
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, sn := range snap.Snippets {
		got = append(got, sn.Name)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("%s has snippets %v; want %v", who, got, want)
	}
}

// deviceIDs are the active devices the vault lists, after a pull.
func deviceIDs(t *testing.T, v *authflow.Vault) []model.ID {
	t.Helper()
	if err := v.Store.Pull(context.Background(), v.Remote); err != nil {
		t.Fatalf("pull: %v", err)
	}
	ds, err := v.Store.Devices()
	if err != nil {
		t.Fatal(err)
	}
	var ids []model.ID
	for _, d := range ds {
		ids = append(ids, d.ID)
	}
	slices.SortFunc(ids, func(a, b model.ID) int { return slices.Compare(a[:], b[:]) })
	return ids
}

func sortedIDs(ids ...model.ID) []model.ID {
	slices.SortFunc(ids, func(a, b model.ID) int { return slices.Compare(a[:], b[:]) })
	return ids
}

func deviceID(t *testing.T, v *authflow.Vault) model.ID {
	t.Helper()
	id, err := model.ParseID(v.Store.Info().DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// pushAll pushes the outbox until it is empty.
func pushAll(t *testing.T, v *authflow.Vault) {
	t.Helper()
	for range 20 {
		res, err := v.Store.PushHead(context.Background(), v.Remote)
		if err != nil {
			t.Fatal(err)
		}
		switch res.Outcome {
		case store.PushEmpty:
			return
		case store.PushHeld:
			t.Fatalf("held: %+v", res.Hold)
		}
	}
	t.Fatal("the outbox did not drain")
}

// signedUp is device 1: a local vault with a snippet, published by
// Signup.
func signedUp(t *testing.T, w *world) (*authflow.Env, *authflow.Vault, store.Kit) {
	t.Helper()
	ui := &scriptUI{password: password}
	env := w.env(t, "desk", ui)
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
	res, err := authflow.Signup(context.Background(), env, authflow.SignupOptions{Email: email, RegistrationCode: w.invite(t), Local: s})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	if res.Created || !s.ServerBacked() || res.Vault.VaultID != res.Publication.VaultID || res.Publication.Server != w.origin {
		t.Fatalf("signup %+v, server-backed %v", res, s.ServerBacked())
	}
	return env, res.Vault, p.Kit()
}

// loggedIn is a device signed in with the password method.
func loggedIn(t *testing.T, w *world, name, pw, sk string) (*authflow.Env, *authflow.Vault) {
	t.Helper()
	ui := &scriptUI{password: pw, secretKey: sk}
	env := w.env(t, name, ui)
	res, err := authflow.LoginPassword(context.Background(), env, authflow.LoginOptions{Email: email, DeviceName: name})
	if err != nil {
		t.Fatalf("%s: password login: %v", name, err)
	}
	t.Cleanup(func() { res.Vault.Store.Close() })
	return env, res.Vault
}

// Signup publishes a local vault; a second device signs in with the
// password and sees it; a wrong password signs nothing in; a local-only
// vault is refused without --merge and merged with it.
func TestSignupAndPasswordLogin(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	_, v1, kit := signedUp(t, w)

	_, v2 := loggedIn(t, w, "laptop", password, kit.SecretKey)
	wantSnippets(t, v2.Store, "device 2", "deploy")
	if v2.VaultID != v1.VaultID || !v2.Store.ServerBacked() {
		t.Errorf("device 2 in vault %v, server-backed %v; want %v", v2.VaultID, v2.Store.ServerBacked(), v1.VaultID)
	}
	if got, want := deviceIDs(t, v1), sortedIDs(deviceID(t, v1), deviceID(t, v2)); !slices.Equal(got, want) {
		t.Errorf("devices %v; want %v", got, want)
	}

	// A wrong password: the server refuses, and nothing is signed in.
	bad := w.env(t, "bad", &scriptUI{password: "not the password at all", secretKey: kit.SecretKey})
	if _, err := authflow.LoginPassword(ctx, bad, authflow.LoginOptions{Email: email}); !errors.Is(err, authflow.ErrLoginFailed) || !errors.Is(err, store.ErrWrongPassword) {
		t.Errorf("a wrong password: %v; want ErrLoginFailed", err)
	}
	if ok, err := store.Exists(bad.Config.DataDir); err != nil || ok {
		t.Errorf("after a failed login the data directory has a vault: %v %v", ok, err)
	}

	// A local-only vault: refused, then merged.
	ui4 := &scriptUI{password: password, secretKey: kit.SecretKey}
	env4 := w.env(t, "spare", ui4)
	p, err := store.PrepareInit(env4.Config, store.InitOptions{Password: []byte("a local password")})
	if err != nil {
		t.Fatal(err)
	}
	s4, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	snippet(t, s4, "local")
	s4.Close()
	if _, err := authflow.LoginPassword(ctx, env4, authflow.LoginOptions{Email: email}); !errors.Is(err, authflow.ErrLocalVault) {
		t.Fatalf("login over a local vault: %v; want ErrLocalVault", err)
	}
	res, err := authflow.LoginPassword(ctx, env4, authflow.LoginOptions{Email: email, Merge: true})
	if err != nil {
		t.Fatalf("merge login: %v", err)
	}
	t.Cleanup(func() { res.Vault.Store.Close() })
	if res.Merge == nil || len(res.Merge.Items) != 1 || res.Vault.VaultID != v1.VaultID {
		t.Fatalf("merge %+v", res.Merge)
	}
	pushAll(t, res.Vault)
	if err := v2.Store.Pull(ctx, v2.Remote); err != nil {
		t.Fatal(err)
	}
	wantSnippets(t, v2.Store, "device 2 after the merge", "deploy", "local")
}

// Signup on a machine with no vault creates one, and writes nothing until
// the user types the kit back.
func TestSignupFresh(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	ui := &scriptUI{newPassword: password, typeBack: func(int) authflow.KitTypeBack {
		return authflow.KitTypeBack{SecretKey: "WRONG", RecoveryKey: "WRONG"}
	}}
	env := w.env(t, "desk", ui)
	if _, err := authflow.Signup(ctx, env, authflow.SignupOptions{Email: email, RegistrationCode: w.invite(t)}); !errors.Is(err, authflow.ErrKitNotConfirmed) {
		t.Fatalf("signup with a wrong type-back: %v; want ErrKitNotConfirmed", err)
	}
	if ok, err := store.Exists(env.Config.DataDir); err != nil || ok {
		t.Fatalf("an unconfirmed kit wrote a vault: %v %v", ok, err)
	}
	ui.typeBack = nil
	res, err := authflow.Signup(ctx, env, authflow.SignupOptions{Email: email, RegistrationCode: w.invite(t)})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	t.Cleanup(func() { res.Vault.Store.Close() })
	if !res.Created || !res.Vault.Store.ServerBacked() {
		t.Fatalf("signup %+v", res)
	}
	kit := ui.lastKit(t)
	_, v2 := loggedIn(t, w, "laptop", password, kit.SecretKey)
	if v2.VaultID != res.Vault.VaultID {
		t.Errorf("device 2 in %v; want %v", v2.VaultID, res.Vault.VaultID)
	}
}

// enrollRun is D (LoginApprove) running in the background.
type enrollRun struct {
	env  *authflow.Env
	ui   *scriptUI
	code string
	done chan enrollOutcome
}

type enrollOutcome struct {
	res *authflow.LoginResult
	err error
}

// startEnroll starts D with opts (VaultID set from vA) and waits for its
// routing code.
func startEnroll(t *testing.T, ctx context.Context, w *world, vA *authflow.Vault, sasD func(sas, name string) bool) *enrollRun {
	t.Helper()
	routing := make(chan string, 1)
	ui := &scriptUI{routing: routing, sas: sasD}
	r := &enrollRun{env: w.env(t, "phone", ui), ui: ui, done: make(chan enrollOutcome, 1)}
	r.resume(ctx, authflow.EnrollOptions{Email: email, DeviceName: "phone", VaultID: vA.VaultID})
	select {
	case r.code = <-routing:
	case o := <-r.done:
		t.Fatalf("D ended before showing a routing code: %v", o.err)
	}
	return r
}

// resume runs LoginApprove again with opts.
func (r *enrollRun) resume(ctx context.Context, opts authflow.EnrollOptions) {
	go func() {
		res, err := authflow.LoginApprove(ctx, r.env, opts)
		r.done <- enrollOutcome{res, err}
	}()
}

// wait returns D's outcome; a vault it returns is closed at cleanup.
func (r *enrollRun) wait(t *testing.T) (*authflow.LoginResult, error) {
	t.Helper()
	select {
	case o := <-r.done:
		if o.res != nil {
			t.Cleanup(func() { o.res.Vault.Store.Close() })
		}
		return o.res, o.err
	case <-time.After(3 * time.Minute):
		t.Fatal("D did not finish")
	}
	return nil, nil
}

func setSAS(env *authflow.Env, sas func(sas, name string) bool) {
	ui := env.UI.(*scriptUI)
	ui.mu.Lock()
	ui.sas = sas
	ui.mu.Unlock()
}

// approval runs D (LoginApprove) and A (Approve) concurrently, each
// answering the SAS with its own function, and returns both outcomes.
func approval(t *testing.T, w *world, envA *authflow.Env, vA *authflow.Vault, sasD, sasA func(sas, name string) bool) (*authflow.Env, *authflow.LoginResult, error, *authflow.ApproveResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	setSAS(envA, sasA)
	d := startEnroll(t, ctx, w, vA, sasD)
	ar, aerr := authflow.Approve(ctx, envA, vA, d.code)
	if aerr != nil {
		// D may wait for a delivery that never comes: give it a moment to
		// end on its own (a rejection), then stop it.
		go func() {
			select {
			case <-time.After(30 * time.Second):
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	res, err := d.wait(t)
	return d.env, res, err, ar, aerr
}

// A third device signs in by approval: both devices show the same SAS,
// the user confirms on both, and the new device installs the vault.
func TestApprovalLogin(t *testing.T) {
	w := newWorld(t)
	envA, vA, kit := signedUp(t, w)
	var mu sync.Mutex
	var codes []string
	record := func(sas, name string) bool {
		mu.Lock()
		defer mu.Unlock()
		codes = append(codes, sas)
		return name == "phone"
	}
	envD, res, err, ar, aerr := approval(t, w, envA, vA, record, record)
	if aerr != nil || err != nil {
		t.Fatalf("approval: A %v, D %v", aerr, err)
	}
	if ar.DeviceName != "phone" {
		t.Errorf("A approved %q; want phone", ar.DeviceName)
	}
	if len(codes) != 2 || codes[0] != codes[1] || len(codes[0]) != 8 {
		t.Errorf("the devices showed %q; want the same 8 digits", codes)
	}
	vD := res.Vault
	wantSnippets(t, vD.Store, "the approved device", "deploy")
	if vD.VaultID != vA.VaultID {
		t.Errorf("D in vault %v; want %v", vD.VaultID, vA.VaultID)
	}
	ds, err := vA.Store.Devices()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ds {
		if d.Undelivered {
			t.Errorf("device %s is undelivered", d.Name)
		}
	}
	if got, want := deviceIDs(t, vA), sortedIDs(deviceID(t, vA), deviceID(t, vD)); !slices.Equal(got, want) {
		t.Errorf("devices %v; want %v", got, want)
	}
	// D syncs both ways.
	snippet(t, vD.Store, "from-phone")
	pushAll(t, vD)
	if err := vA.Store.Pull(context.Background(), vA.Remote); err != nil {
		t.Fatal(err)
	}
	wantSnippets(t, vA.Store, "device 1", "deploy", "from-phone")

	// The approved device stores no Secret Key (§11 addendum): its password
	// change asks for it.
	uiD := &scriptUI{t: t, password: password, newPassword: newPassword, secretKey: kit.SecretKey}
	envD.UI = uiD
	cr, err := authflow.ChangePassword(context.Background(), envD, vD)
	if err != nil {
		t.Fatalf("passwd on the approved device: %v", err)
	}
	if uiD.skPrompts != 1 || uiD.staleSK != 0 || cr.Kind != store.CheckpointPasswd || vD.Store.PendingKit() != nil {
		t.Errorf("passwd %+v: %d Secret Key prompts (%d stale); want 1 (0)", cr, uiD.skPrompts, uiD.staleSK)
	}
}

// A mismatch rejected on both devices ends the attempt on both, and the
// new device installs nothing. A new device whose user rejects installs
// nothing even when the approving device's user confirms and delivers.
func TestApprovalRejected(t *testing.T) {
	for _, aConfirms := range []bool{false, true} {
		t.Run(fmt.Sprintf("A confirms %v", aConfirms), func(t *testing.T) {
			w := newWorld(t)
			envA, vA, _ := signedUp(t, w)
			envD, res, err, _, aerr := approval(t, w, envA, vA,
				func(string, string) bool { return false },
				func(string, string) bool { return aConfirms })
			if !errors.Is(err, crypto.ErrSASRejected) || res != nil {
				t.Fatalf("D after its rejection: %+v %v; want ErrSASRejected", res, err)
			}
			if aConfirms {
				if aerr != nil {
					t.Fatalf("A: %v", aerr)
				}
			} else if !errors.Is(aerr, authflow.ErrSASMismatch) {
				t.Fatalf("A after its rejection: %v; want ErrSASMismatch", aerr)
			}
			// Nothing of the enrollment is left on D: no vault, no
			// enrollment to resume or install.
			if ok, err := store.Exists(envD.Config.DataDir); err != nil || ok {
				t.Errorf("D has a vault after rejecting: %v %v", ok, err)
			}
			if _, err := store.ResumeEnrollment(envD.Config); !errors.Is(err, store.ErrNoEnrollment) {
				t.Errorf("D's enrollment after rejecting: %v; want ErrNoEnrollment", err)
			}
			ds, err := vA.Store.Devices()
			if err != nil {
				t.Fatal(err)
			}
			// A that confirmed committed the device_add and delivered it
			// (it can't know D rejected): the device stays listed, never
			// usable, until a checkpoint revokes it.
			n := 0
			for _, d := range ds {
				if !d.This {
					n++
				}
			}
			if want := map[bool]int{false: 0, true: 1}[aConfirms]; n != want {
				t.Errorf("A lists %d other devices; want %d", n, want)
			}
		})
	}
}

// A recovery login must run its checkpoint: until it commits, the login
// reports ErrRecoveryIncomplete and the store allows no other checkpoint.
// The checkpoint keeps only the survivors chosen, shows a new kit, and
// the new credentials sign in.
func TestRecoveryLogin(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	_, v1, kit := signedUp(t, w)
	_, v2 := loggedIn(t, w, "laptop", password, kit.SecretKey)
	id1, id2 := deviceID(t, v1), deviceID(t, v2)

	uiR := &scriptUI{recoveryKey: kit.RecoveryKey, secretKey: kit.SecretKey, password: "whatever",
		failNew: errors.New("no terminal to ask on"),
		keep:    func(authflow.SurvivorChoice) []string { return []string{id2.String()} }}
	envR := w.env(t, "spare", uiR)
	res, err := authflow.LoginRecovery(ctx, envR, authflow.LoginOptions{Email: email})
	if !errors.Is(err, authflow.ErrRecoveryIncomplete) || res == nil || res.Vault == nil {
		t.Fatalf("recovery with no new password: %+v %v; want ErrRecoveryIncomplete", res, err)
	}
	vR := res.Vault
	if si, err := vR.Store.ServerInfo(); err != nil || !si.CheckpointDue {
		t.Fatalf("server info %+v %v; want the checkpoint due", si, err)
	}
	// No other checkpoint gets past it.
	if _, err := authflow.Rotate(ctx, envR, vR); !errors.Is(err, store.ErrRecoveryDue) {
		t.Errorf("rotate during the recovery: %v; want ErrRecoveryDue", err)
	}
	vR.Store.Close()

	// The login again finishes it.
	uiR.mu.Lock()
	uiR.failNew, uiR.newPassword = nil, newPassword
	uiR.mu.Unlock()
	res, err = authflow.LoginRecovery(ctx, envR, authflow.LoginOptions{Email: email})
	if err != nil {
		t.Fatalf("the recovery's checkpoint: %v", err)
	}
	vR = res.Vault
	t.Cleanup(func() { vR.Store.Close() })
	if res.Recovery == nil || res.Recovery.Kind != store.CheckpointRecovery {
		t.Fatalf("recovery %+v", res.Recovery)
	}
	if si, err := vR.Store.ServerInfo(); err != nil || si.CheckpointDue || vR.Store.PendingKit() != nil {
		t.Errorf("after the checkpoint: %+v %v, kit pending %v", si, err, vR.Store.PendingKit() != nil)
	}
	c := uiR.choices[len(uiR.choices)-1]
	if c.Kind != store.CheckpointRecovery || len(c.Devices) != 3 {
		t.Errorf("survivor choice %+v; want the recovery's, of 3 devices", c)
	}
	idR := deviceID(t, vR)
	if got, want := deviceIDs(t, vR), sortedIDs(idR, id2); !slices.Equal(got, want) {
		t.Errorf("devices %v; want %v (device 1 revoked)", got, want)
	}
	if got := deviceIDs(t, v2); !slices.Contains(got, id2) || slices.Contains(got, id1) {
		t.Errorf("device 2 lists %v", got)
	}
	wantSnippets(t, vR.Store, "the recovered device", "deploy")

	// The new kit and password sign in; the old ones do not.
	newKit := uiR.lastKit(t)
	if newKit.SecretKey == kit.SecretKey || newKit.RecoveryKey == kit.RecoveryKey {
		t.Fatal("the recovery kept the old kit")
	}
	loggedIn(t, w, "new", newPassword, newKit.SecretKey)
	old := w.env(t, "old", &scriptUI{password: password, secretKey: kit.SecretKey})
	if _, err := authflow.LoginPassword(ctx, old, authflow.LoginOptions{Email: email}); !errors.Is(err, authflow.ErrLoginFailed) {
		t.Errorf("the old credentials: %v; want ErrLoginFailed", err)
	}
}

// joining is a Remote whose first Post lets another device sign in first
// and then fails as an unreachable server would, without posting.
type joining struct {
	store.Remote
	first func()
	once  sync.Once
	posts atomic.Int32
}

func (r *joining) Post(ctx context.Context, wire *vaultlog.Wire) (vaultlog.Head, error) {
	r.posts.Add(1)
	failed := false
	r.once.Do(func() {
		r.first()
		failed = true
	})
	if failed {
		return vaultlog.Head{}, fmt.Errorf("%w: injected", syncclient.ErrUnreachable)
	}
	return r.Remote.Post(ctx, wire)
}

// A password change that must be rebuilt asks about a device that joined
// meanwhile; a rotation on another device asks for the newest Secret Key
// (its stored one is stale) and keeps only the survivors chosen; a
// revocation names its target.
func TestPasswdRotateRevoke(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	env1, v1, kit := signedUp(t, w)
	env2, v2 := loggedIn(t, w, "laptop", password, kit.SecretKey)
	id1, id2 := deviceID(t, v1), deviceID(t, v2)

	// Device 1 changes the password; device 3 signs in while it runs.
	var v3 *authflow.Vault
	ui1 := env1.UI.(*scriptUI)
	ui1.newPassword = newPassword
	ui1.keepNew = func(d []store.DeviceListing) []model.ID { return []model.ID{d[0].ID} }
	remote := v1.Remote
	v1.Remote = &joining{Remote: remote, first: func() { _, v3 = loggedIn(t, w, "tablet", password, kit.SecretKey) }}
	cr, err := authflow.ChangePassword(ctx, env1, v1)
	v1.Remote = remote
	if err != nil {
		t.Fatalf("passwd: %v", err)
	}
	id3 := deviceID(t, v3)
	if len(ui1.newDevices) != 1 || len(ui1.newDevices[0]) != 1 || ui1.newDevices[0][0].ID != id3 {
		t.Errorf("new devices asked about: %+v; want only device 3", ui1.newDevices)
	}
	if len(ui1.shown) != 1 || len(ui1.shown[0]) != 2 {
		t.Errorf("devices shown: %+v; want devices 1 and 2", ui1.shown)
	}
	if cr.Kind != store.CheckpointPasswd || cr.Resumed || v1.Store.PendingKit() != nil || len(cr.Devices) != 3 {
		t.Errorf("passwd %+v", cr)
	}
	kit2 := ui1.lastKit(t)

	// Device 2: its stored Secret Key is stale; it keeps device 1 only.
	ui2 := env2.UI.(*scriptUI)
	ui2.password, ui2.secretKey = newPassword, kit2.SecretKey
	ui2.keep = func(authflow.SurvivorChoice) []string { return []string{id1.String()} }
	cr, err = authflow.Rotate(ctx, env2, v2)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if ui2.staleSK != 1 {
		t.Errorf("%d stale Secret Key prompts; want 1", ui2.staleSK)
	}
	if got, want := deviceIDs(t, v2), sortedIDs(id1, id2); !slices.Equal(got, want) || cr.Kind != store.CheckpointRotate {
		t.Errorf("after the rotation: %v; want %v (device 3 revoked)", got, want)
	}
	if got := deviceIDs(t, v1); !slices.Equal(got, sortedIDs(id1, id2)) {
		t.Errorf("device 1 lists %v", got)
	}
	kit3 := ui2.lastKit(t)

	// Device 1 revokes device 2 by name, with the newest Secret Key.
	ui1.password, ui1.secretKey = newPassword, kit3.SecretKey
	ui1.staleSK = 0
	cr, err = authflow.RevokeDevices(ctx, env1, v1, []string{"laptop"})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	c := ui1.choices[len(ui1.choices)-1]
	if c.Kind != store.CheckpointRevoke || !slices.Equal(c.Targets, []model.ID{id2}) || ui1.staleSK != 1 {
		t.Errorf("revoke choice %+v, %d stale prompts", c, ui1.staleSK)
	}
	if got := deviceIDs(t, v1); !slices.Equal(got, []model.ID{id1}) || cr.Kind != store.CheckpointRevoke {
		t.Errorf("after the revocation: %v; want only device 1", got)
	}
}

// Logout retires a device through the server; --local-only wipes one
// without it.
func TestLogout(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	_, v1, kit := signedUp(t, w)
	env2, v2 := loggedIn(t, w, "laptop", password, kit.SecretKey)
	env3, v3 := loggedIn(t, w, "tablet", password, kit.SecretKey)
	id1, id3 := deviceID(t, v1), deviceID(t, v3)

	res, err := authflow.Logout(ctx, env2, v2.Store, store.LogoutOptions{})
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	if res.State != store.StateRetired || res.Outcome != store.OutcomeCommitted || !res.Done || res.RevokeElsewhere {
		t.Errorf("logout %+v", res)
	}
	if got, want := deviceIDs(t, v1), sortedIDs(id1, id3); !slices.Equal(got, want) {
		t.Errorf("devices after the logout: %v; want %v", got, want)
	}

	res, err = authflow.Logout(ctx, &authflow.Env{Config: env3.Config}, v3.Store, store.LogoutOptions{LocalOnly: true})
	if err != nil {
		t.Fatalf("local-only logout: %v", err)
	}
	if !res.Done || !res.RevokeElsewhere {
		t.Errorf("local-only logout %+v", res)
	}
	for _, env := range []*authflow.Env{env2, env3} {
		if ok, err := store.Exists(env.Config.DataDir); err != nil || ok {
			t.Errorf("a vault is left after the logout: %v %v", ok, err)
		}
	}
	// The local-only logout told the server nothing: device 3 is still
	// listed until another device revokes it.
	if got, want := deviceIDs(t, v1), sortedIDs(id1, id3); !slices.Equal(got, want) {
		t.Errorf("devices after the local-only logout: %v; want %v", got, want)
	}
}

// crashing is a Remote whose Post commits the entry and then fails in a
// way that is not retryable, as a crash after the post would.
type crashing struct{ store.Remote }

var errCrash = errors.New("e2e: the process died after posting")

func (r crashing) Post(ctx context.Context, wire *vaultlog.Wire) (vaultlog.Head, error) {
	if _, err := r.Remote.Post(ctx, wire); err != nil {
		return vaultlog.Head{}, err
	}
	return vaultlog.Head{}, errCrash
}

// Resume finishes a checkpoint whose run died after its post, and shows a
// kit the user did not confirm until it is typed back.
func TestResume(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	env1, v1, kit := signedUp(t, w)
	loggedIn(t, w, "laptop", password, kit.SecretKey)
	id1 := deviceID(t, v1)

	if res, err := authflow.Resume(ctx, env1, v1); err != nil || res.Checkpoint != nil {
		t.Fatalf("resume with nothing pending: %+v %v", res, err)
	}
	ui1 := env1.UI.(*scriptUI)
	remote := v1.Remote
	v1.Remote = crashing{remote}
	if _, err := authflow.Rotate(ctx, env1, v1); !errors.Is(err, errCrash) {
		t.Fatalf("rotate that dies after its post: %v", err)
	}
	v1.Remote = remote
	if st, err := v1.Store.PendingCheckpoint(); err != nil || st == nil || st.Kind != store.CheckpointRotate || st.Live == nil {
		t.Fatalf("pending checkpoint %+v %v; want a live rotation", st, err)
	}

	// The kit is shown, but typed back wrong: it stays pending.
	ui1.typeBack = func(int) authflow.KitTypeBack { return authflow.KitTypeBack{SecretKey: "X", RecoveryKey: "Y"} }
	ui1.password = ""
	if _, err := authflow.Resume(ctx, env1, v1); !errors.Is(err, authflow.ErrKitNotConfirmed) {
		t.Fatalf("resume with a wrong type-back: %v; want ErrKitNotConfirmed", err)
	}
	if v1.Store.PendingKit() == nil {
		t.Fatal("an unconfirmed kit is no longer pending")
	}
	if _, err := authflow.Logout(ctx, env1, v1.Store, store.LogoutOptions{}); err == nil {
		t.Fatal("logout with a pending kit succeeded")
	}

	ui1.typeBack = nil
	res, err := authflow.Resume(ctx, env1, v1)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if res.Checkpoint == nil || res.Checkpoint.Kind != store.CheckpointRotate || !res.Checkpoint.Resumed || v1.Store.PendingKit() != nil {
		t.Errorf("resume %+v", res.Checkpoint)
	}
	if st, err := v1.Store.PendingCheckpoint(); err != nil || st != nil {
		t.Errorf("pending checkpoint after the resume: %+v %v", st, err)
	}
	// The rotation kept only device 1.
	if got := deviceIDs(t, v1); !slices.Equal(got, []model.ID{id1}) {
		t.Errorf("devices %v; want only device 1", got)
	}
}
