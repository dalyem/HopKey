package daemon

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/sshconfig"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Tests for the review of the revocation work (448a60e): the check before
// keys load fails closed on any answer but an unreachable server, is
// bounded while a sync holds the store, does not lock an idle online
// device, keeps asking for the passphrase it needs, and says what the wipe
// has and has not finished.

// laptopID is n's device ID.
func laptopID(t *testing.T, n *node) model.ID {
	t.Helper()
	id, err := model.ParseID(n.st.Info().DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// deviceOf reads the device a request names, and puts its body back.
func deviceOf(req *http.Request) (model.ID, string) {
	var body struct {
		DeviceID  model.ID `json:"device_id"`
		Operation string   `json:"operation"`
	}
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(b))
		json.Unmarshal(b, &body)
	}
	return body.DeviceID, body.Operation
}

func answerJSON(rw http.ResponseWriter, status int, v any) bool {
	b, err := canonjson.Marshal(v)
	if err != nil {
		panic(err)
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	rw.Write(b)
	return true
}

func unauthorized(rw http.ResponseWriter) bool {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusUnauthorized)
	rw.Write([]byte(`{"error":{"code":"unauthorized","message":"unauthorized"}}`))
	return true
}

// refuseLaptop is a server that answers the laptop, and only it, in one of
// the ways that are not an unreachable server and not a valid report.
func refuseLaptop(w *syncWorld, laptop, other model.ID, mode string) {
	f := interceptor(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		dev, op := deviceOf(req)
		if dev != laptop {
			return false
		}
		status := func(receipt any) bool {
			return answerJSON(rw, http.StatusOK, struct {
				Committed bool          `json:"committed"`
				Head      vaultlog.Head `json:"head"`
				Receipt   any           `json:"receipt"`
				Seq       *string       `json:"seq"`
			}{Head: vaultlog.Head{Seq: 1 << 20, H: crypto.SHA256([]byte("head"))}, Receipt: receipt})
		}
		session := req.URL.Path == "/v1/auth/challenge" && op == "session"
		switch mode {
		case "no receipt", "another device's receipt", "a malformed retire-status":
			switch {
			case session:
				return unauthorized(rw)
			case req.URL.Path != "/v1/retire-status":
			case mode == "no receipt":
				return status(nil)
			case mode == "another device's receipt":
				return status(struct {
					DeviceID model.ID    `json:"device_id"`
					H        crypto.Hash `json:"h"`
					How      string      `json:"how"`
					Seq      uint64      `json:"seq,string"`
				}{other, crypto.SHA256([]byte("x")), "revoked", 1 << 20})
			default:
				rw.Header().Set("Content-Type", "application/json")
				rw.Write([]byte(`{"receipt":`))
				return true
			}
		case "a 403 on the challenge":
			if session {
				return answerJSON(rw, http.StatusForbidden, map[string]any{"error": map[string]string{"code": "forbidden", "message": "forbidden"}})
			}
		case "a malformed challenge":
			if session {
				return answerJSON(rw, http.StatusOK, map[string]string{"challenge": "AAAA"})
			}
		}
		return false
	})
	w.intercept.Store(&f)
}

// P2: a server that answers, and refuses this device without a valid
// report, or answers in a way the client can't use, keeps the keys out at
// start and at unlock. The vault stays locked in memory only: nothing is
// recorded or deleted, the check is not called skipped, and once the server
// accepts the device again hop unlock brings the keys back.
func TestServerAnswerThatIsNotAPassKeepsTheKeysOut(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 5*time.Second, "web1 reaches the laptop", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })
	laptop, desk := laptopID(t, x.n2), laptopID(t, x.n1)
	data := x.n2.cfg.DataDir

	for _, mode := range []string{"no receipt", "another device's receipt", "a malformed retire-status", "a 403 on the challenge", "a malformed challenge"} {
		refuseLaptop(x.w, laptop, desk, mode)
		x.w.restart(x.n2) // fails if the agent serves a key from the start
		if k := x.n2.agentKeys(); k != 0 {
			t.Errorf("%s: at start, the agent serves %d key(s)", mode, k)
		}
		s := x.n2.status()
		if s.CheckSkipped != "" {
			t.Errorf("%s: status says the check was skipped (%s); the server answered", mode, s.CheckSkipped)
		}
		if s.State != SyncLocked {
			t.Errorf("%s: sync state %s, want locked", mode, s.State)
		}
		if exists(t, filepath.Join(data, "vault", "server-revoked.json")) {
			t.Errorf("%s: a report was recorded on disk without a receipt", mode)
		}
		if !exists(t, filepath.Join(data, "device.json")) || !exists(t, filepath.Join(data, "vault", "state.json")) {
			t.Fatalf("%s: the vault was deleted", mode)
		}
		var st StatusResult
		x.n2.must(OpStatus, nil, &st)
		if st.Vault == nil || !st.Vault.Locked || st.Vault.LockReason == "" {
			t.Errorf("%s: the vault status does not say why it is locked: %+v", mode, st.Vault)
		}

		// hop unlock under the same server refuses too.
		if err := x.n2.call(OpUnlock, nil, nil); err == nil {
			t.Errorf("%s: hop unlock succeeded", mode)
		}
		if k := x.n2.agentKeys(); k != 0 {
			t.Errorf("%s: after hop unlock, the agent serves %d key(s)", mode, k)
		}

		// The server accepts the device again.
		x.w.intercept.Store(nil)
		if err := x.n2.call(OpUnlock, nil, nil); err != nil {
			t.Errorf("%s: hop unlock with the server back: %v", mode, err)
		}
		if k := x.n2.agentKeys(); k != 1 {
			t.Errorf("%s: with the server back, the agent serves %d key(s)", mode, k)
		}
	}
}

// startTrusting is startWith with pool as the only roots the daemon
// trusts.
func (w *syncWorld) startTrusting(n *node, ms model.Store, pool *x509.CertPool) {
	t := n.t
	t.Helper()
	base := shortDir(t)
	n.paths = Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg"), StateDir: filepath.Join(base, "state")}
	name := n.name
	d, err := Start(Options{
		Paths: n.paths, Store: ms, Version: "test", Tailscale: fakeTS{},
		Sync: SyncOptions{Client: syncclient.Options{RootCAs: pool}},
		Logf: func(format string, args ...any) { t.Logf(name+": "+format, args...) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	c, err := Dial(context.Background(), d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	n.d, n.c = d, c
}

// A certificate that does not verify is a server that can't be reached
// (a captive portal, a proxy): the keys load and status says the check was
// skipped.
func TestUntrustedCertificateSkipsTheCheck(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 5*time.Second, "the desk pushes", func() bool { return x.n1.status().Pending == 0 })
	dev2, err := syncclient.StoreDevice(x.n2.st.DeviceAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.n2.st.Pull(context.Background(), x.w.client(t).Remote(x.pub.VaultID, dev2)); err != nil {
		t.Fatal(err)
	}
	x.w.startTrusting(x.n2, x.n2.st, x509.NewCertPool())
	if k := x.n2.agentKeys(); k != 1 {
		t.Errorf("with the server's certificate untrusted, the agent serves %d key(s)", k)
	}
	if s := x.n2.status(); !strings.Contains(s.CheckSkipped, "certificate") {
		t.Errorf("status does not say the check was skipped for the certificate: %q", s.CheckSkipped)
	}
}

// P2: hop unlock asks the server within its bound, even while the sync
// loop holds a long-poll open: the long-poll is cut short, and the answer
// is fresh, not skipped.
func TestUnlockCheckInterruptsTheLongPoll(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{Wait: 30 * time.Second})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 5*time.Second, "web1 reaches the laptop", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })
	eventually(t, 5*time.Second, "the laptop is online", func() bool { return x.n2.status().State == SyncOnline })
	time.Sleep(time.Second) // a long-poll is open

	start := time.Now()
	err := x.n2.call(OpUnlock, nil, nil)
	took := time.Since(start)
	if err != nil {
		t.Fatalf("hop unlock: %v", err)
	}
	if took > checkTimeout+time.Second {
		t.Errorf("hop unlock took %v with a long-poll open", took.Round(time.Millisecond))
	}
	if s := x.n2.status(); s.CheckSkipped != "" {
		t.Errorf("the check was skipped rather than the long-poll cut short: %s", s.CheckSkipped)
	}
	if x.n2.agentKeys() != 1 {
		t.Error("the keys are gone")
	}
	eventually(t, 10*time.Second, "the laptop syncs again", func() bool { return x.n2.status().State == SyncOnline })
}

// hangingProof is hostile, with a proof endpoint that answers only once the
// client gives up, or the test ends.
func hangingProof(t *testing.T, w *syncWorld, laptop model.ID, served *atomic.Int32) {
	hostile(w, laptop, false)
	inner := *w.intercept.Load()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) }) // before the server closes
	f := interceptor(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		if req.URL.Path == "/v1/retire-status/proof" {
			served.Add(1)
			select {
			case <-req.Context().Done():
			case <-stop:
			}
			http.Error(rw, `{"error":{"code":"unavailable","message":"unavailable"}}`, http.StatusServiceUnavailable)
			return true
		}
		return inner(rw, req, next)
	})
	w.intercept.Store(&f)
}

// P2: a proof that hangs holds the store's sync lock for minutes; hop
// unlock still answers within its bound, as a server that could not be
// asked, and other requests to the daemon are not held up past it.
func TestUnlockCheckIsBoundedWhileAProofHangs(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 5*time.Second, "web1 reaches the laptop", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })
	var served atomic.Int32
	hangingProof(t, x.w, laptopID(t, x.n2), &served)
	x.w.restart(x.n2)
	eventually(t, 5*time.Second, "the proof is asked for", func() bool { return served.Load() > 0 })

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- x.n2.call(OpUnlock, nil, nil) }()
	time.Sleep(200 * time.Millisecond)
	sstart := time.Now()
	var st StatusResult
	serr := x.n2.call(OpStatus, nil, &st)
	stook := time.Since(sstart)
	err := <-done
	took := time.Since(start)
	if !IsCode(err, CodeRevoked) {
		t.Errorf("hop unlock while the proof hangs: %v, want the report to stand", err)
	}
	if took > checkTimeout+time.Second {
		t.Errorf("hop unlock took %v while the proof hangs", took.Round(time.Millisecond))
	}
	if serr != nil || stook > checkTimeout+time.Second {
		t.Errorf("hop status during that unlock: %v after %v", serr, stook.Round(time.Millisecond))
	}
	assertCutOff(t, x.n2, "while the proof hangs")
}

// P2: an online device whose account allows one minute offline stays
// unlocked while it is idle: every long-poll that returns is a contact,
// whether or not it was written to disk. The laptop runs on a clock twenty
// times as fast, so each one-second long-poll is twenty seconds of its
// time, and twelve seconds four minutes.
func TestIdleOnlineDeviceWithAOneMinutePolicyStaysUnlocked(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	x.n1.must(OpPolicy, PolicyParams{MaxOffline: 60}, nil)
	eventually(t, 10*time.Second, "the policy reaches the laptop", func() bool {
		x.n1.call(OpSyncNow, nil, nil)
		x.n2.call(OpSyncNow, nil, nil)
		return x.n2.policy() == 60
	})

	x.n2.c.Close()
	x.n2.d.Close()
	base := time.Now()
	fast := func() time.Time { return base.Add(time.Since(base) * 20) }
	x.n2.cfg.Now = fast
	st, err := store.Open(context.Background(), x.n2.cfg)
	if err != nil {
		t.Fatal(err)
	}
	x.n2.st = st
	x.w.startWith(x.n2, st, Options{Sync: SyncOptions{Wait: time.Second}, offlineEvery: 50 * time.Millisecond, now: fast})
	eventually(t, 5*time.Second, "the laptop is online", func() bool { return x.n2.status().State == SyncOnline })
	if x.n2.agentKeys() != 1 {
		t.Fatal("the laptop starts without its key")
	}
	for end := time.Now().Add(12 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if s := x.n2.status(); s.OfflineLocked != "" || s.State == SyncLocked {
			t.Fatalf("an idle online device locked itself after %v of its time: %s", fast().Sub(base).Round(time.Second), s.OfflineLocked)
		}
	}
	if x.n2.agentKeys() != 1 {
		t.Error("the laptop lost its key")
	}
}

var errStuckWipe = errors.New("test: the ssh files can't be removed yet")

const sealedPassphrase = "the laptop's device passphrase"

// signInSealed is signIn with the device key in a file sealed by
// sealedPassphrase, which cfg.Getenv gives.
func signInSealed(t *testing.T, c *syncclient.Client, cfg store.Config, kit store.Kit, pub store.Publication) *store.Store {
	t.Helper()
	ctx := context.Background()
	pre, err := c.Prelogin(ctx, syncEmail)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := crypto.ParseSecretKey(kit.SecretKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := crypto.DeriveLoginKeys([]byte(syncPassword), pre.Salt, &sk, pre.AccountID, crypto.KDFv1)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := c.Login(ctx, pre.AccountID, keys.AuthKey[:])
	if err != nil {
		t.Fatal(err)
	}
	acct := openAccount(t, tr, keys)
	keys.Zero()
	s, _, err := store.SignIn(ctx, cfg, tr, store.SignInParams{
		ServerURL: pub.Server, Email: syncEmail, Account: acct, SecretKey: kit.SecretKey, DeviceName: cfg.DeviceName,
		DeviceStore: store.DeviceStoreFile,
	})
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	return s
}

// P2: a daemon a service started has no device passphrase. With a report
// the server made up, hop unlock needs the passphrase to authenticate the
// device again: the daemon says so, rather than that the device is
// revoked, so hop unlock can ask for it; with it, the vault unlocks once
// the server accepts the device.
func TestReportedDeviceWithASealedKeyAsksForThePassphrase(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	withPass := func(k string) string {
		if k == store.PassphraseEnv {
			return sealedPassphrase
		}
		return ""
	}
	cfg := syncStoreConfig(t, "sealed")
	cfg.Getenv = withPass
	n := &node{t: t, name: "sealed", cfg: cfg, st: signInSealed(t, x.w.client(t), cfg, x.kit, x.pub)}
	x.w.start(n, n.st, SyncOptions{})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 10*time.Second, "web1 reaches the sealed laptop", func() bool { return strings.Contains(n.config(), "Host web1\n") })

	hostile(x.w, laptopID(t, n), false)
	x.w.restart(n) // with the passphrase: it records the report
	if r := n.status().ServerRetirement; r == nil {
		t.Fatal("the report was not recorded")
	}
	// As a service starts it: no passphrase.
	n.cfg.Getenv = func(string) string { return "" }
	x.w.restart(n)

	x.w.intercept.Store(nil) // the server accepts the device again
	err := n.call(OpUnlock, nil, nil)
	if err == nil {
		t.Fatal("hop unlock without the passphrase unlocked a sealed device key")
	}
	if IsCode(err, CodeRevoked) || !strings.Contains(err.Error(), store.PassphraseEnv) {
		t.Errorf("hop unlock without the passphrase: %v, want it to ask for the device passphrase", err)
	}
	if err := n.call(OpUnlock, UnlockParams{DevicePassphrase: sealedPassphrase}, nil); err != nil {
		t.Fatalf("hop unlock with the passphrase: %v", err)
	}
	if n.agentKeys() != 1 {
		t.Error("the keys are not back")
	}
	if rep, _ := n.st.Report(); rep != nil {
		t.Errorf("the report is still recorded: %+v", rep)
	}
}

// Status says the revocation is proven as soon as the proof verifies, but
// calls the device wiped only once the ssh files are gone too; and while
// they are not, it never says the revocation is unproven or that nothing
// was deleted.
func TestWipedOnlyOnceTheSSHFilesAreGone(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	var stuck atomic.Bool
	stuck.Store(true)
	x.w.startWith(x.n2, x.n2.st, Options{configRetry: 100 * time.Millisecond, wipeConfig: func(o sshconfig.Options, done func() error) error {
		if stuck.Load() {
			return errStuckWipe
		}
		return sshconfig.WipeIf(o, nil, done)
	}})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 5*time.Second, "web1 reaches the laptop", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })
	x.n2.pause(true)
	x.revokeLaptop(t)
	x.n2.pause(false)

	eventually(t, 15*time.Second, "the revocation is proven", func() bool {
		r := x.n2.status().ServerRetirement
		return r != nil && !r.Unverified
	})
	time.Sleep(300 * time.Millisecond)
	s := x.n2.status()
	if r := s.ServerRetirement; r.Wiped {
		t.Error("status says wiped while the ssh files are still there")
	}
	for _, w := range s.Warnings {
		if strings.Contains(w, "Nothing was deleted") || strings.Contains(w, "not proven") {
			t.Errorf("a warning says the proven revocation is not: %s", w)
		}
	}
	if strings.Contains(x.n2.config(), "Host ") == false {
		t.Fatal("setup: the ssh config was emptied although the wipe is stuck")
	}

	stuck.Store(false)
	eventually(t, 10*time.Second, "the wipe finishes", func() bool {
		r := x.n2.status().ServerRetirement
		return r != nil && r.Wiped && !strings.Contains(x.n2.config(), "Host ")
	})
}

// Which failures to ask the server count as a server that can't be
// reached, the only ones that let keys load unasked.
func TestUnreachableClass(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("asking: %w", err) }
	for _, c := range []struct {
		err  error
		want bool
	}{
		{wrap(syncclient.ErrUnreachable), true},
		{wrap(syncclient.ErrTLS), true},
		{wrap(context.DeadlineExceeded), true},
		{wrap(&syncclient.APIError{Status: http.StatusServiceUnavailable}), true},
		{wrap(&syncclient.APIError{Status: http.StatusTooManyRequests}), true},
		{wrap(&syncclient.APIError{Status: http.StatusUnauthorized}), false},
		{wrap(&syncclient.APIError{Status: http.StatusForbidden}), false},
		{wrap(&syncclient.APIError{Status: http.StatusNotFound}), false},
		{wrap(syncclient.ErrMalformedResponse), false},
		{wrap(syncclient.ErrRedirect), false},
		{wrap(store.ErrSessionEnded), false},
		{wrap(store.ErrServerUnconfirmed), false},
		{wrap(context.Canceled), false},
	} {
		if got := unreachable(c.err); got != c.want {
			t.Errorf("unreachable(%v) = %v", c.err, got)
		}
	}
}
