package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/model/modeltest"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/tailscale"
)

type fakeTS struct{ st *tailscale.Status }

func (f fakeTS) Status(context.Context) (*tailscale.Status, error) {
	if f.st == nil {
		return tailscale.Unavailable("tailscale is not installed"), nil
	}
	return f.st, nil
}

type testKey struct {
	pem string
	pub ssh.PublicKey
}

func genKey(t *testing.T) testKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return testKey{pem: string(pem.EncodeToMemory(block)), pub: signer.PublicKey()}
}

func (k testKey) line() string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.pub))) }

type fixture struct {
	t     *testing.T
	paths Paths
	store *modeltest.Store
	d     *Daemon
	key   model.Key
	pub   testKey
}

func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func newFixture(t *testing.T, ts TailscaleSource) *fixture {
	t.Helper()
	base := shortDir(t)
	f := &fixture{t: t, store: modeltest.New(), pub: genKey(t)}
	f.paths = Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "home", ".ssh", "hop"), StateDir: filepath.Join(base, "state")}
	k, err := f.store.PutKey(context.Background(), model.Key{Name: "k1", KeyType: "ed25519", PrivateKey: f.pub.pem, PublicKey: f.pub.line()})
	if err != nil {
		t.Fatal(err)
	}
	f.key = k
	f.start(ts)
	return f
}

func (f *fixture) start(ts TailscaleSource) {
	f.t.Helper()
	if ts == nil {
		ts = fakeTS{}
	}
	d, err := Start(Options{Paths: f.paths, Store: f.store, Version: "test", Tailscale: ts, Logf: f.t.Logf})
	if err != nil {
		f.t.Fatal(err)
	}
	f.d = d
	f.t.Cleanup(func() { d.Close() })
}

func (f *fixture) host(name string, mod func(*model.Host)) model.Host {
	h := model.Host{Name: name, Addresses: []string{"203.0.113.10"}, Port: 22, User: "deploy", KeyID: f.key.ItemID, Route: "auto", AgentAccess: "allow"}
	if mod != nil {
		mod(&h)
	}
	return h
}

func (f *fixture) put(h model.Host) model.Host {
	f.t.Helper()
	saved, err := f.store.PutHost(context.Background(), h)
	if err != nil {
		f.t.Fatal(err)
	}
	return saved
}

func (f *fixture) client() *Client {
	f.t.Helper()
	c, err := Dial(context.Background(), f.d.ControlSocket())
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { c.Close() })
	return c
}

func (f *fixture) config() string {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.paths.ConfigDir, "config"))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}

func (f *fixture) list() *ListResult {
	f.t.Helper()
	var l ListResult
	if err := f.client().Call(context.Background(), OpList, nil, &l); err != nil {
		f.t.Fatal(err)
	}
	return &l
}

func TestDefaultPaths(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	p := DefaultPaths("/home/u", env(nil))
	want := Paths{RunDir: "/home/u/.ssh/hop/run", ConfigDir: "/home/u/.ssh/hop", StateDir: "/home/u/.local/state/hop"}
	if p != want {
		t.Errorf("no env: %+v, want %+v", p, want)
	}
	p = DefaultPaths("/home/u", env(map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000", "XDG_STATE_HOME": "/var/u/state"}))
	if p.RunDir != "/run/user/1000/hop" || p.StateDir != "/var/u/state/hop" || p.ConfigDir != "/home/u/.ssh/hop" {
		t.Errorf("with XDG: %+v", p)
	}
	// A relative XDG_RUNTIME_DIR is ignored.
	p = DefaultPaths("/home/u", env(map[string]string{"XDG_RUNTIME_DIR": "run"}))
	if p.RunDir != "/home/u/.ssh/hop/run" {
		t.Errorf("relative XDG_RUNTIME_DIR: %+v", p)
	}
	if p.AgentSocket() != "/home/u/.ssh/hop/run/agent.sock" || p.ControlSocket() != "/home/u/.ssh/hop/run/control.sock" {
		t.Errorf("sockets: %s %s", p.AgentSocket(), p.ControlSocket())
	}
}

func TestStartLoadsTheKeyringAndWritesTheConfig(t *testing.T) {
	f := newFixture(t, nil)
	pin := genKey(t)
	f.put(f.host("prod-db", func(h *model.Host) {
		h.Aliases = []string{"db"}
		h.HostKeys = []string{pin.line()}
	}))
	if err := f.client().Call(context.Background(), OpReload, nil, nil); err != nil {
		t.Fatal(err)
	}

	cfg := f.config()
	for _, want := range []string{"Host db\n", "Host prod-db\n", "HostName 203.0.113.10", "User deploy", "IdentityAgent " + f.d.AgentSocket(), "StrictHostKeyChecking yes", "HostKeyAlias prod-db"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config lacks %q:\n%s", want, cfg)
		}
	}

	// The agent socket serves the key, and only lists and signs.
	conn, err := net.Dial("unix", f.d.AgentSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ag := agent.NewClient(conn)
	keys, err := ag.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "k1" || !slices.Equal(keys[0].Marshal(), f.pub.pub.Marshal()) {
		t.Fatalf("agent keys = %v, err %v", keys, err)
	}
	if _, err := ag.Sign(f.pub.pub, []byte("data")); err != nil {
		t.Errorf("sign: %v", err)
	}
	other := genKey(t)
	raw, _ := ssh.ParseRawPrivateKey([]byte(other.pem))
	if err := ag.Add(agent.AddedKey{PrivateKey: raw}); err == nil {
		t.Error("a client added a key to the agent")
	}
	if err := ag.RemoveAll(); err == nil {
		t.Error("a client removed the keys from the agent")
	}
}

func TestChangesThroughTheDaemonReloadEverything(t *testing.T) {
	f := newFixture(t, nil)
	c := f.client()
	ctx := context.Background()

	var saved model.Host
	if err := c.Call(ctx, OpPutHost, PutHostParams{Host: model.Host{Name: "web", Addresses: []string{"web.example.com"}, KeyID: f.key.ItemID}}, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.ItemID.IsZero() || saved.Port != 22 || saved.Route != "auto" || saved.AgentAccess != "allow" {
		t.Errorf("defaults were not filled in: %+v", saved)
	}
	if !strings.Contains(f.config(), "Host web\n") {
		t.Errorf("the new host is not in the config:\n%s", f.config())
	}

	// A new key goes to the agent without a restart.
	extra := genKey(t)
	var info KeyInfo
	if err := c.Call(ctx, OpPutKey, PutKeyParams{Name: "k2", PrivateKey: extra.pem}, &info); err != nil {
		t.Fatal(err)
	}
	if info.KeyType != "ed25519" || !strings.HasPrefix(info.Fingerprint, "SHA256:") || info.PublicKey != extra.line() {
		t.Errorf("key info = %+v", info)
	}
	var st StatusResult
	if err := c.Call(ctx, OpStatus, nil, &st); err != nil {
		t.Fatal(err)
	}
	if st.Keys != 2 || st.KeysInAgent != 2 || st.Hosts != 1 || st.SSHHosts != 1 {
		t.Errorf("status = %+v", st)
	}

	if err := c.Call(ctx, OpDelete, DeleteParams{ID: saved.ItemID.String()}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.config(), "Host web\n") {
		t.Error("the removed host is still in the config")
	}
	if err := c.Call(ctx, OpDelete, DeleteParams{ID: saved.ItemID.String()}, nil); !IsCode(err, CodeNotFound) {
		t.Errorf("deleting twice: %v", err)
	}
	if err := c.Call(ctx, OpDelete, DeleteParams{ID: "xyz"}, nil); !IsCode(err, CodeInvalid) {
		t.Errorf("deleting a malformed id: %v", err)
	}
}

func TestExternalStoreChangesAreNoticed(t *testing.T) {
	f := newFixture(t, nil)
	// Another process (a sync, say) changes the store directly.
	f.put(f.host("synced", nil))
	l := f.list()
	if len(l.Hosts) != 1 || l.Hosts[0].Name != "synced" || l.SSH[l.Hosts[0].ItemID.String()].Alias != "synced" {
		t.Fatalf("list = %+v", l)
	}
	if !strings.Contains(f.config(), "Host synced\n") {
		t.Error("the config was not regenerated for a change made behind the daemon's back")
	}
}

func TestHostsThatCannotGoInTheConfigSayWhy(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	cred, err := f.store.PutCredential(ctx, model.Credential{Name: "pw", Username: "u", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	nokey := f.put(f.host("nokey", func(h *model.Host) { h.KeyID = model.ID{} }))
	pw := f.put(f.host("pw", func(h *model.Host) { h.KeyID = model.ID{}; h.CredentialID = cred.ItemID }))
	bad := f.put(f.host("badaddr", func(h *model.Host) { h.Addresses = []string{"bad address!"} }))
	badUser := f.put(f.host("baduser", func(h *model.Host) { h.User = "no body" }))
	good := f.put(f.host("good", nil))
	badName := f.put(f.host("-leading-dash", nil))
	tail := f.put(f.host("tailonly", func(h *model.Host) { h.Route = "tailnet"; h.Addresses = []string{"203.0.113.77"} }))

	l := f.list()
	problem := func(h model.Host) string { return l.SSH[h.ItemID.String()].Problem }
	for _, tc := range []struct {
		h    model.Host
		want string
	}{
		{nokey, "no key assigned"},
		{pw, "password hosts are not supported"},
		{bad, "not usable in an ssh config"},
		{badUser, "not usable in an ssh config"},
		{badName, "no usable ssh alias"},
		{tail, "no tailnet address"},
	} {
		if p := problem(tc.h); !strings.Contains(p, tc.want) {
			t.Errorf("%s: problem = %q, want it to contain %q", tc.h.Name, p, tc.want)
		}
	}
	if l.SSH[good.ItemID.String()].Alias != "good" || problem(good) != "" {
		t.Errorf("good host: %+v", l.SSH[good.ItemID.String()])
	}
	cfg := f.config()
	if strings.Contains(cfg, "Host nokey") || strings.Contains(cfg, "Host pw\n") || !strings.Contains(cfg, "Host good\n") {
		t.Errorf("config does not match the problems:\n%s", cfg)
	}
	// The vault never refuses these at the store: the daemon reports them in status.
	var st StatusResult
	if err := f.client().Call(ctx, OpStatus, nil, &st); err != nil {
		t.Fatal(err)
	}
	if st.SSHHosts != 1 || st.Hosts != 7 {
		t.Errorf("status hosts=%d ssh_hosts=%d", st.Hosts, st.SSHHosts)
	}
}

func TestAliasCollisionsAreWarnedAboutNotWritten(t *testing.T) {
	f := newFixture(t, nil)
	f.put(f.host("alpha", func(h *model.Host) { h.Aliases = []string{"shared", "Alpha"} }))
	f.put(f.host("beta", func(h *model.Host) { h.Aliases = []string{"SHARED", "beta-2"} }))
	var st StatusResult
	if err := f.client().Call(context.Background(), OpStatus, nil, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Warnings) != 1 || !strings.Contains(st.Warnings[0], `alias "SHARED" is already used by host "alpha"`) {
		t.Errorf("warnings = %q", st.Warnings)
	}
	cfg := f.config()
	if strings.Count(cfg, "\nHost ") != 4 { // alpha, shared, beta, beta-2
		t.Errorf("config has the wrong blocks:\n%s", cfg)
	}
}

func TestJumpHostsBecomeProxyJump(t *testing.T) {
	f := newFixture(t, nil)
	bastion := f.put(f.host("bastion", func(h *model.Host) { h.Aliases = []string{"gw"} }))
	inner := f.put(f.host("inner", func(h *model.Host) { h.Addresses = []string{"10.0.0.5"}; h.JumpHostID = bastion.ItemID }))
	nokey := f.put(f.host("nokey", func(h *model.Host) { h.KeyID = model.ID{} }))
	deep := f.put(f.host("deep", func(h *model.Host) { h.JumpHostID = nokey.ItemID }))
	deeper := f.put(f.host("deeper", func(h *model.Host) { h.JumpHostID = deep.ItemID }))

	l := f.list()
	cfg := f.config()
	if !strings.Contains(cfg, "Host inner\n  HostName 10.0.0.5\n  Port 22\n  User deploy\n  ProxyJump bastion\n") {
		t.Errorf("inner has no ProxyJump through bastion:\n%s", cfg)
	}
	if l.SSH[inner.ItemID.String()].Alias != "inner" {
		t.Errorf("inner = %+v", l.SSH[inner.ItemID.String()])
	}
	// A host behind a host that cannot be used cannot be used either, however deep.
	for _, h := range []model.Host{deep, deeper} {
		if p := l.SSH[h.ItemID.String()].Problem; !strings.Contains(p, "jump host") {
			t.Errorf("%s: problem = %q, want a jump host problem", h.Name, p)
		}
	}
	if strings.Contains(cfg, "Host deep") {
		t.Error("deep is in the config")
	}
}

func TestResolveOverTheControlSocket(t *testing.T) {
	ts := &tailscale.Status{Available: true, MagicDNSSuffix: "tn.ts.net",
		Self:  tailscale.Node{ID: "nSELF", HostName: "me", DNSName: "me.tn.ts.net", Online: true, IPs: []string{"100.64.0.1"}},
		Peers: []tailscale.Node{{ID: "nPEER", HostName: "prodbox", DNSName: "prodbox.tn.ts.net", Online: true, IPs: []string{"100.64.0.2"}}}}
	f := newFixture(t, fakeTS{ts})
	f.put(f.host("prod-db", func(h *model.Host) {
		h.Tailscale = &model.Tailscale{StableNodeID: "nPEER", DNSName: "prodbox.tn.ts.net", SSH: "unknown"}
	}))
	f.put(f.host("prod-web", func(h *model.Host) { h.Addresses = []string{"203.0.113.20"} }))
	c := f.client()
	ctx := context.Background()

	var rr ResolveResult
	if err := c.Call(ctx, OpResolve, ResolveParams{Target: "root@100.64.0.2"}, &rr); err != nil {
		t.Fatal(err)
	}
	if rr.Result.Status != resolve.StatusMatched || rr.Result.Rule != resolve.RuleTailscale || rr.Result.User != "root" ||
		rr.Host == nil || rr.Host.Name != "prod-db" || rr.SSHAlias != "prod-db" {
		t.Errorf("resolve = %+v", rr)
	}
	if rr.Route == nil || rr.Route.Chosen != "tailnet" || rr.Route.Address != "100.64.0.2" || rr.Route.Fallback != "203.0.113.10" {
		t.Errorf("route = %+v", rr.Route)
	}

	// The config uses the same route decision.
	if cfg := f.config(); !strings.Contains(cfg, "Host prod-db\n  HostName 100.64.0.2\n") {
		t.Errorf("the config does not use the tailnet address:\n%s", cfg)
	}

	// Ambiguity and non-interactive rules reach the client unchanged.
	var amb ResolveResult
	if err := c.Call(ctx, OpResolve, ResolveParams{Target: "prod"}, &amb); err != nil {
		t.Fatal(err)
	}
	if amb.Result.Status != resolve.StatusNoMatch || len(amb.Result.Candidates) != 2 || amb.Host != nil {
		t.Errorf("non-interactive prefix: %+v", amb.Result)
	}
	if err := c.Call(ctx, OpResolve, ResolveParams{Target: "prod", Interactive: true}, &amb); err != nil {
		t.Fatal(err)
	}
	if amb.Result.Status != resolve.StatusAmbiguous || amb.Result.Rule != resolve.RulePrefix {
		t.Errorf("interactive prefix: %+v", amb.Result)
	}
	if err := c.Call(ctx, OpResolve, ResolveParams{Target: "-oProxyCommand=x"}, &amb); !IsCode(err, CodeInvalid) {
		t.Errorf("option-like target: %v", err)
	}

	var got tailscale.Status
	if err := c.Call(ctx, OpTailscale, nil, &got); err != nil || !got.Available || len(got.Peers) != 1 {
		t.Errorf("tailscale op: %+v, %v", got, err)
	}
}

func TestPutHostRefusesBadInput(t *testing.T) {
	f := newFixture(t, nil)
	f.put(f.host("existing", func(h *model.Host) { h.Aliases = []string{"old"} }))
	c := f.client()
	ctx := context.Background()
	ok := func() model.Host {
		return model.Host{Name: "new", Addresses: []string{"1.2.3.4"}, KeyID: f.key.ItemID}
	}
	tests := []struct {
		name string
		mod  func(*model.Host)
		want string
	}{
		{"no name", func(h *model.Host) { h.Name = "" }, "needs a name"},
		{"space in name", func(h *model.Host) { h.Name = "my host" }, "not a valid host name"},
		{"leading dash", func(h *model.Host) { h.Name = "-x" }, "not a valid host name"},
		{"bad alias", func(h *model.Host) { h.Aliases = []string{"a b"} }, "not a valid host name"},
		{"name used", func(h *model.Host) { h.Name = "EXISTING" }, `already a name or alias of host "existing"`},
		{"alias used", func(h *model.Host) { h.Aliases = []string{"old"} }, `already a name or alias of host "existing"`},
		{"alias is the name", func(h *model.Host) { h.Aliases = []string{"NEW"} }, "listed twice"},
		{"no address", func(h *model.Host) { h.Addresses = nil }, "at least one address"},
		{"bad address", func(h *model.Host) { h.Addresses = []string{"a;b"} }, "not usable"},
		{"bad user", func(h *model.Host) { h.User = "a b" }, "user"},
		{"bad port", func(h *model.Host) { h.Port = 99999 }, "out of range"},
		{"bad route", func(h *model.Host) { h.Route = "x" }, "route must be"},
		{"bad access", func(h *model.Host) { h.AgentAccess = "x" }, "agent_access"},
		{"bad host key", func(h *model.Host) { h.HostKeys = []string{"not a key"} }, "host key"},
		{"dangling key", func(h *model.Host) { h.KeyID = model.ID{7} }, "missing key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := ok()
			tt.mod(&h)
			err := c.Call(ctx, OpPutHost, PutHostParams{Host: h}, nil)
			if !IsCode(err, CodeInvalid) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want an invalid error containing %q", err, tt.want)
			}
		})
	}
	// None of that reached the store.
	if got := f.store.Writes(); got != 2 { // the key and "existing"
		t.Errorf("store writes = %d, want 2", got)
	}
	// Editing a host does not collide with itself.
	existing := f.list().Hosts[0]
	existing.Description = "edited"
	if err := c.Call(ctx, OpPutHost, PutHostParams{Host: existing}, nil); err != nil {
		t.Errorf("editing a host: %v", err)
	}
}

func TestPutKeyRefusesBadInput(t *testing.T) {
	f := newFixture(t, nil)
	c := f.client()
	ctx := context.Background()

	// A passphrase-protected key.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	enc := string(pem.EncodeToMemory(block))

	fresh := genKey(t)
	tests := []struct {
		name string
		p    PutKeyParams
		want string
	}{
		{"encrypted", PutKeyParams{Name: "x", PrivateKey: enc}, "passphrase"},
		{"garbage", PutKeyParams{Name: "x", PrivateKey: "-----BEGIN NOPE-----"}, "sshkeys"},
		{"no name", PutKeyParams{Name: " ", PrivateKey: fresh.pem}, "needs a name"},
		{"name used", PutKeyParams{Name: "K1", PrivateKey: fresh.pem}, "already exists"},
		{"same key again", PutKeyParams{Name: "other", PrivateKey: f.pub.pem}, `already in the vault as "k1"`},
	}
	for _, tt := range tests {
		err := c.Call(ctx, OpPutKey, tt.p, nil)
		if !IsCode(err, CodeInvalid) || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want an invalid error containing %q", tt.name, err, tt.want)
		}
	}
}

func TestSecondDaemonIsRefused(t *testing.T) {
	f := newFixture(t, nil)
	_, err := Start(Options{Paths: f.paths, Store: modeltest.New(), Tailscale: fakeTS{}})
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Start: %v, want ErrAlreadyRunning", err)
	}
	// The first is untouched.
	if err := f.client().Call(context.Background(), OpReload, nil, nil); err != nil {
		t.Errorf("first daemon after the refused second: %v", err)
	}
}

func TestShutdownRemovesTheSockets(t *testing.T) {
	f := newFixture(t, nil)
	if err := f.client().Call(context.Background(), OpShutdown, nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.d.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the daemon did not stop")
	}
	for _, p := range []string{f.paths.AgentSocket(), f.paths.ControlSocket()} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still exists after shutdown (%v)", p, err)
		}
	}
	if err := f.d.Close(); err != nil {
		t.Errorf("Close after shutdown: %v", err)
	}
	// And it can start again on the same directory.
	f.start(nil)
	if err := f.client().Call(context.Background(), OpStatus, nil, nil); err != nil {
		t.Errorf("restarted daemon: %v", err)
	}
}

func TestStartFailsWhenTheVaultCannotBeRead(t *testing.T) {
	base := shortDir(t)
	paths := Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg")}
	_, err := Start(Options{Paths: paths, Store: lockedStore{}, Tailscale: fakeTS{}})
	if !errors.Is(err, model.ErrLocked) {
		t.Fatalf("Start with a locked store: %v", err)
	}
	// Nothing is left running: the directory can be used at once.
	d, err := Start(Options{Paths: paths, Store: modeltest.New(), Tailscale: fakeTS{}})
	if err != nil {
		t.Fatalf("Start after a failed Start: %v", err)
	}
	d.Close()
}

type lockedStore struct{ model.Store }

func (lockedStore) Snapshot(context.Context) (model.Snapshot, error) {
	return model.Snapshot{}, model.ErrLocked
}

func TestMalformedAndUnknownRequests(t *testing.T) {
	f := newFixture(t, nil)
	conn, err := net.Dial("unix", f.d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	for _, req := range []string{"not json\n", `{"op":"bogus"}` + "\n", `{"op":"delete","params":"x"}` + "\n"} {
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatal(err)
		}
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(buf[:n]), `"code":"invalid"`) {
			t.Errorf("request %q answered %s", req, buf[:n])
		}
	}
}

func TestControlSocketIsPrivate(t *testing.T) {
	f := newFixture(t, nil)
	for _, p := range []string{f.paths.ControlSocket(), f.paths.AgentSocket()} {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
			t.Errorf("%s: mode %v", p, fi.Mode())
		}
	}
	fi, err := os.Stat(f.paths.RunDir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("run dir: %v %v", fi, err)
	}
}
