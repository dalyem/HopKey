package daemon

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/model/modeltest"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/sshconfig"
)

// failingWrites is a writeConfig hook that fails while it is set.
func failingWrites(fail *atomic.Bool) func(sshconfig.Options, []sshconfig.Host) error {
	return func(o sshconfig.Options, hosts []sshconfig.Host) error {
		if fail.Load() {
			return errors.New("the directory is read-only")
		}
		return sshconfig.Write(o, hosts)
	}
}

// failingWipes is a wipeConfig hook that fails while it is set.
func failingWipes(fail *atomic.Bool) func(sshconfig.Options) error {
	return func(o sshconfig.Options) error {
		if fail.Load() {
			return errors.New("the directory is read-only")
		}
		return sshconfig.Wipe(o)
	}
}

// knownHosts is the known_hosts file that config points ssh at.
func knownHosts(t *testing.T, config string) string {
	t.Helper()
	for _, line := range strings.Split(config, "\n") {
		if path, ok := strings.CutPrefix(strings.TrimSpace(line), "UserKnownHostsFile "); ok {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			return string(data)
		}
	}
	t.Fatalf("the config names no known_hosts file:\n%s", config)
	return ""
}

func hasWarning(ws []string, parts ...string) bool {
	return slices.ContainsFunc(ws, func(w string) bool {
		for _, p := range parts {
			if !strings.Contains(w, p) {
				return false
			}
		}
		return true
	})
}

// A committed change to a host's pinned host key and user that the ssh
// config can't take: hop status and hop list still answer, but resolve
// refuses with config_stale, since ssh would read the old pin and user
// from the config. Once the config can be written, resolve writes it and
// answers. The timer retry is an hour away: the resolve itself retries.
func TestResolveRefusesWhileTheSSHConfigIsStale(t *testing.T) {
	ctx := context.Background()
	base := shortDir(t)
	paths := Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg")}
	st := modeltest.New()
	k, pinA, pinB := genKey(t), genKey(t), genKey(t)
	key, err := st.PutKey(ctx, model.Key{Name: "k1", KeyType: "ed25519", PrivateKey: k.pem, PublicKey: k.line()})
	if err != nil {
		t.Fatal(err)
	}
	web := webHost("web", key.ItemID, "203.0.113.10")
	web.HostKeys = []string{pinA.line()}
	if web, err = st.PutHost(ctx, web); err != nil {
		t.Fatal(err)
	}
	var fail atomic.Bool
	d, err := Start(Options{Paths: paths, Store: st, Version: "test", Tailscale: fakeTS{}, Logf: t.Logf,
		writeConfig: failingWrites(&fail), configRetry: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	c, err := Dial(ctx, d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	config := func() string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(paths.ConfigDir, "config"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	pinned := func(k testKey) bool {
		return strings.Contains(knownHosts(t, config()), base64.StdEncoding.EncodeToString(k.pub.Marshal()))
	}

	var res ResolveResult
	if err := c.Call(ctx, OpResolve, ResolveParams{Target: "web"}, &res); err != nil || res.SSHAlias != "web" {
		t.Fatalf("resolve before: %v %+v", err, res)
	}
	if !strings.Contains(config(), "User deploy") || !pinned(pinA) {
		t.Fatalf("starting point:\n%s", config())
	}

	// The change commits; the config can't follow it.
	fail.Store(true)
	changed := web
	changed.User, changed.HostKeys = "root", []string{pinB.line()}
	var saved model.Host
	w, err := c.CallWarn(ctx, OpPutHost, PutHostParams{Host: changed}, &saved)
	if err != nil || w == nil || w.Code != CodeConfigNotWritten || !strings.Contains(w.Message, "saved") {
		t.Fatalf("put_host with the config unwritable: %v, warning %+v", err, w)
	}
	if saved.ItemID != web.ItemID || saved.User != "root" || saved.ItemVersion <= web.ItemVersion {
		t.Errorf("put_host returned %+v; want the saved host", saved)
	}
	if !strings.Contains(config(), "User deploy") || pinned(pinB) {
		t.Fatalf("the config changed though it could not be written:\n%s", config())
	}

	for range 2 {
		err := c.Call(ctx, OpResolve, ResolveParams{Target: "web"}, &res)
		if !IsCode(err, CodeConfigStale) {
			t.Fatalf("resolve with the config stale: %v %+v", err, res)
		}
		if !strings.Contains(err.Error(), "read-only") || !strings.Contains(err.Error(), paths.ConfigDir) {
			t.Errorf("the refusal does not say why: %v", err)
		}
	}
	var status StatusResult
	if err := c.Call(ctx, OpStatus, nil, &status); err != nil || !hasWarning(status.Warnings, "ssh config", "out of date") {
		t.Errorf("status with the config stale: %v %q", err, status.Warnings)
	}
	var list ListResult
	if err := c.Call(ctx, OpList, nil, &list); err != nil || len(list.Hosts) != 1 || list.Hosts[0].User != "root" {
		t.Errorf("list with the config stale: %v %+v", err, list.Hosts)
	}

	fail.Store(false)
	if err := c.Call(ctx, OpResolve, ResolveParams{Target: "web"}, &res); err != nil {
		t.Fatalf("resolve once the config can be written: %v", err)
	}
	if res.SSHAlias != "web" || res.Host == nil || res.Host.User != "root" {
		t.Errorf("resolve after recovery: alias %q host %+v", res.SSHAlias, res.Host)
	}
	if cfg := config(); !strings.Contains(cfg, "User root") || strings.Contains(cfg, "User deploy") || !pinned(pinB) || pinned(pinA) {
		t.Errorf("the config after recovery:\n%s", cfg)
	}
	var after StatusResult
	if err := c.Call(ctx, OpStatus, nil, &after); err != nil || hasWarning(after.Warnings, "out of date") {
		t.Errorf("status after recovery: %v %q", err, after.Warnings)
	}
}

// The same refusal after a catch-up pull: the first look at the vault is
// current and finds nothing, the catch-up brings the host, and the reload
// that follows can't write the config. Resolve must not hand out an alias
// the config does not have.
func TestResolveAfterACatchUpRefusesWhileTheSSHConfigIsStale(t *testing.T) {
	x := newSyncSetup(t)
	var fail atomic.Bool
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.startWith(x.n2, x.n2.st, Options{
		Sync:        SyncOptions{noPoll: true, catchUpAge: time.Nanosecond},
		writeConfig: failingWrites(&fail), configRetry: time.Hour,
	})

	x.n1.putHost(webHost("fresh", x.keyID, "203.0.113.18"))
	eventually(t, 5*time.Second, "the desk pushes", func() bool { return x.n1.status().Pending == 0 })
	fail.Store(true)
	var res ResolveResult
	if err := x.n2.call(OpResolve, ResolveParams{Target: "fresh"}, &res); !IsCode(err, CodeConfigStale) {
		t.Fatalf("resolve after a catch-up with the config unwritable: %v %+v (alias %q)", err, res.Result, res.SSHAlias)
	}
	if x.n2.host("fresh") == nil {
		t.Fatal("the catch-up did not pull the host")
	}
	if strings.Contains(x.n2.config(), "Host fresh\n") {
		t.Fatal("the config was written though it could not be")
	}

	fail.Store(false)
	x.n2.must(OpResolve, ResolveParams{Target: "fresh"}, &res)
	if res.Result.Status != resolve.StatusMatched || res.SSHAlias != "fresh" || !strings.Contains(x.n2.config(), "Host fresh\n") {
		t.Errorf("resolve once the config can be written: %+v alias %q\n%s", res.Result, res.SSHAlias, x.n2.config())
	}
}

// A revocation empties the agent at once; when the ssh config can't be
// emptied with it, status says so, and the retry timer empties it once it
// can be written, with no vault to read.
func TestRevokedConfigIsClearedOnceItCanBeWritten(t *testing.T) {
	ctx := context.Background()
	base := shortDir(t)
	k := genKey(t)
	rs := &revocableStore{Store: modeltest.New(), signal: true, ch: make(chan struct{})}
	key, err := rs.PutKey(ctx, model.Key{Name: "k1", KeyType: "ed25519", PrivateKey: k.pem, PublicKey: k.line()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rs.PutHost(ctx, webHost("web", key.ItemID, "203.0.113.10")); err != nil {
		t.Fatal(err)
	}
	var fail atomic.Bool
	paths := Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg")}
	d, err := Start(Options{Paths: paths, Store: rs, Version: "test", Tailscale: fakeTS{}, Logf: t.Logf,
		writeConfig: failingWrites(&fail), wipeConfig: failingWipes(&fail), configRetry: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	c, err := Dial(ctx, d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	config := func() string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(paths.ConfigDir, "config"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	agentKeys := func() int { l, _ := d.live.List(); return len(l) }
	status := func() StatusResult {
		t.Helper()
		var st StatusResult
		if err := c.Call(ctx, OpStatus, nil, &st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	if agentKeys() != 1 || !strings.Contains(config(), "Host web\n") {
		t.Fatalf("setup: %d keys\n%s", agentKeys(), config())
	}

	fail.Store(true)
	rs.revoke()
	eventually(t, 5*time.Second, "the agent empties", func() bool { return agentKeys() == 0 })
	eventually(t, 5*time.Second, "status warns that the config was not emptied", func() bool {
		return hasWarning(status().Warnings, "revoked", "could not be emptied")
	})
	// Several retries fail, and the config is left as it was.
	time.Sleep(200 * time.Millisecond)
	if !strings.Contains(config(), "203.0.113.10") {
		t.Fatalf("the config changed though it could not be written:\n%s", config())
	}
	if st := status(); !hasWarning(st.Warnings, "could not be emptied") || st.Vault == nil || !st.Vault.Revoked {
		t.Errorf("status while the config can't be emptied: %q %+v", st.Warnings, st.Vault)
	}

	fail.Store(false)
	eventually(t, 5*time.Second, "the config is emptied", func() bool {
		cfg := config()
		return !strings.Contains(cfg, "web") && !strings.Contains(cfg, "203.0.113.10")
	})
	if st := status(); hasWarning(st.Warnings, "could not be emptied") || st.KeysInAgent != 0 {
		t.Errorf("status after the config was emptied: %d keys, %q", st.KeysInAgent, st.Warnings)
	}
	// The key files and the pins went with it, at once, not after the
	// grace period that keeps them for an ssh still reading them.
	for _, pattern := range []string{"known_hosts*", filepath.Join("keys", "*.pub")} {
		if left, _ := filepath.Glob(filepath.Join(paths.ConfigDir, pattern)); len(left) != 0 {
			t.Errorf("left behind after the revocation: %q", left)
		}
	}
}

// An unlock whose ssh config can't be written still unlocks and loads the
// keys: it answers with a success that carries a config_not_written
// warning, not a failure to unlock. This tests the daemon's answer only.
func TestUnlockWithAnUnwritableConfigIsAPartialSuccess(t *testing.T) {
	ctx := context.Background()
	base := shortDir(t)
	k := genKey(t)
	rs := &revocableStore{Store: modeltest.New(), ch: make(chan struct{})}
	key, err := rs.PutKey(ctx, model.Key{Name: "k1", KeyType: "ed25519", PrivateKey: k.pem, PublicKey: k.line()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rs.PutHost(ctx, webHost("web", key.ItemID, "203.0.113.10")); err != nil {
		t.Fatal(err)
	}
	var fail atomic.Bool
	paths := Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg")}
	d, err := Start(Options{Paths: paths, Store: rs, Version: "test", Tailscale: fakeTS{}, Logf: t.Logf,
		writeConfig: failingWrites(&fail), configRetry: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	c, err := Dial(ctx, d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	if err := c.Call(ctx, OpLock, nil, nil); err != nil {
		t.Fatal(err)
	}
	if l, _ := d.live.List(); len(l) != 0 {
		t.Fatalf("%d keys after lock", len(l))
	}
	fail.Store(true)
	w, err := c.CallWarn(ctx, OpUnlock, nil, nil)
	if err != nil || w == nil || w.Code != CodeConfigNotWritten {
		t.Fatalf("unlock with the config unwritable: %v, warning %+v", err, w)
	}
	for _, want := range []string{"vault unlocked and keys loaded", "ssh config could not be updated", "read-only"} {
		if !strings.Contains(w.Message, want) {
			t.Errorf("the unlock warning %q does not say %q", w.Message, want)
		}
	}
	if l, _ := d.live.List(); len(l) != 1 {
		t.Errorf("%d keys after the partial unlock; want 1", len(l))
	}
}

// Every change that takes effect while the ssh config can't be written is
// a success on the wire: ok, the op's result (the saved host or key, with
// its ID), and a config_not_written warning beside it. A caller that has
// to know what was saved, such as an import whose next host jumps through
// this one, gets it from the answer, not from reading the vault again.
func TestChangesWithAnUnwritableConfigAnswerWithTheirResult(t *testing.T) {
	ctx := context.Background()
	base := shortDir(t)
	paths := Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg")}
	var fail atomic.Bool
	d, err := Start(Options{Paths: paths, Store: modeltest.New(), Version: "test", Tailscale: fakeTS{}, Logf: t.Logf,
		writeConfig: failingWrites(&fail), configRetry: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	conn, err := net.Dial("unix", d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64<<10), maxRequest)
	// raw sends one request and returns the response line as it came.
	raw := func(op string, params any) Response {
		t.Helper()
		b, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		line, _ := json.Marshal(Request{Op: op, Params: b})
		if _, err := conn.Write(append(line, '\n')); err != nil {
			t.Fatal(err)
		}
		if !sc.Scan() {
			t.Fatalf("%s: no response: %v", op, sc.Err())
		}
		var resp Response
		if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
			t.Fatalf("%s: %v: %s", op, err, sc.Bytes())
		}
		if !resp.OK || resp.Error != nil || resp.Warning == nil || resp.Warning.Code != CodeConfigNotWritten ||
			!strings.Contains(resp.Warning.Message, "read-only") {
			t.Fatalf("%s with the config unwritable: %s", op, sc.Bytes())
		}
		return resp
	}

	fail.Store(true)
	k := genKey(t)
	resp := raw(OpPutKey, PutKeyParams{Name: "k1", PrivateKey: k.pem})
	var key KeyInfo
	if err := json.Unmarshal(resp.Result, &key); err != nil || key.ID == "" || key.Name != "k1" {
		t.Fatalf("put_key result %s: %v", resp.Result, err)
	}
	keyID, err := model.ParseID(key.ID)
	if err != nil {
		t.Fatal(err)
	}

	resp = raw(OpPutHost, PutHostParams{Host: webHost("bastion", keyID, "203.0.113.1")})
	var bastion model.Host
	if err := json.Unmarshal(resp.Result, &bastion); err != nil || bastion.ItemID.IsZero() || bastion.Name != "bastion" {
		t.Fatalf("put_host result %s: %v", resp.Result, err)
	}
	inner := webHost("inner", keyID, "10.0.0.5")
	inner.JumpHostID = bastion.ItemID
	resp = raw(OpPutHost, PutHostParams{Host: inner})
	var saved model.Host
	if err := json.Unmarshal(resp.Result, &saved); err != nil || saved.JumpHostID != bastion.ItemID {
		t.Fatalf("put_host of a host that jumps through the first: %s: %v", resp.Result, err)
	}

	resp = raw(OpDelete, DeleteParams{ID: saved.ItemID.String()})
	if len(resp.Result) != 0 {
		t.Errorf("delete result %s", resp.Result)
	}
	raw(OpReload, nil)

	// The vault has what the answers said; only the config is behind.
	snap, err := d.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Hosts) != 1 || snap.Hosts[0].ItemID != bastion.ItemID || len(snap.Keys) != 1 {
		t.Errorf("vault after the changes: %+v %+v", snap.Hosts, snap.Keys)
	}

	// Any other refusal is still an error, with no warning.
	fail.Store(false)
	b, _ := json.Marshal(PutHostParams{Host: model.Host{Name: "nowhere"}})
	line, _ := json.Marshal(Request{Op: OpPutHost, Params: b})
	conn.Write(append(line, '\n'))
	if !sc.Scan() {
		t.Fatal(sc.Err())
	}
	var bad Response
	json.Unmarshal(sc.Bytes(), &bad)
	if bad.OK || bad.Error == nil || bad.Warning != nil || len(bad.Result) != 0 {
		t.Errorf("a refused put_host: %s", sc.Bytes())
	}
}
