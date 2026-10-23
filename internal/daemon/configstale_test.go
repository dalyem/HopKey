package daemon

import (
	"context"
	"encoding/base64"
	"errors"
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
	err = c.Call(ctx, OpPutHost, PutHostParams{Host: changed}, nil)
	if !IsCode(err, CodeConfigNotWritten) || !strings.Contains(err.Error(), "saved") {
		t.Fatalf("put_host with the config unwritable: %v", err)
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
		writeConfig: failingWrites(&fail), configRetry: 50 * time.Millisecond})
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
}

// An unlock whose ssh config can't be written still unlocks and loads the
// keys: it answers with config_not_written, a partial success the CLI
// shows as a warning, not a failure to unlock.
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
	err = c.Call(ctx, OpUnlock, nil, nil)
	if !IsCode(err, CodeConfigNotWritten) {
		t.Fatalf("unlock with the config unwritable: %v", err)
	}
	for _, want := range []string{"vault unlocked and keys loaded", "ssh config could not be updated", "read-only"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the unlock message %q does not say %q", err, want)
		}
	}
	if l, _ := d.live.List(); len(l) != 1 {
		t.Errorf("%d keys after the partial unlock; want 1", len(l))
	}
}
