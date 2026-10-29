package daemon

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/redact"
	"github.com/dalyem/hopkey/internal/store"
)

// OpRedact says where the vault's secrets stand in a text, and of what
// kind, without ever sending one: not the Secret Key, not a password, not
// a key.
func TestRedactFindsVaultSecretsWithoutSendingThem(t *testing.T) {
	base := shortDir(t)
	ring := &memKeyring{m: map[string]string{}}
	cfg := store.Config{DataDir: filepath.Join(base, "data"), Keyring: ring, Getenv: func(string) string { return "" }}
	p, err := store.PrepareInit(cfg, store.InitOptions{Password: []byte("a master password")})
	if err != nil {
		t.Fatal(err)
	}
	sk := p.Kit().SecretKey
	s0, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	s0.Close()
	ctx := context.Background()
	s, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Start(Options{Paths: Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg")}, Store: s, Tailscale: fakeTS{}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	k := genKey(t)
	if _, err := s.PutKey(ctx, model.Key{Name: "k1", KeyType: "ed25519", PrivateKey: k.pem, PublicKey: k.line()}); err != nil {
		t.Fatal(err)
	}
	const password = "a credential password"
	if _, err := s.PutCredential(ctx, model.Credential{Name: "c", Username: "u", Password: password}); err != nil {
		t.Fatal(err)
	}
	c, err := Dial(ctx, d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	lines := strings.Split(strings.TrimSpace(k.pem), "\n")
	keyLine := lines[1]
	texts := []string{
		"sk " + sk + " lower " + strings.ToLower(sk),
		"pw=" + password + "\n" + keyLine + "\n",
		k.pem,
		"nothing here",
		"bad utf-8 \xff then " + password,
	}
	params := RedactParams{}
	for _, t := range texts {
		params.Texts = append(params.Texts, []byte(t))
	}
	var raw json.RawMessage
	if err := c.Call(ctx, OpRedact, params, &raw); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{sk, strings.ToLower(sk), password, keyLine} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the answer holds a secret (%.12s...): %s", secret, raw)
		}
	}
	var res RedactResult
	if err := json.Unmarshal(raw, &res); err != nil || len(res.Hits) != len(texts) {
		t.Fatalf("%v %s", err, raw)
	}
	found := func(i int) []string {
		var out []string
		for _, h := range res.Hits[i] {
			out = append(out, h.Kind+"="+texts[i][h.Lo:h.Hi])
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	if got := found(0); !slices.Contains(got, redact.KindVaultSecretKey+"="+sk) || !slices.Contains(got, redact.KindVaultSecretKey+"="+strings.ToLower(sk)) {
		t.Errorf("the Secret Key: %q", got)
	}
	if got := found(1); !slices.Contains(got, redact.KindVaultPassword+"="+password) || !slices.Contains(got, redact.KindVaultPrivateKey+"="+keyLine) {
		t.Errorf("the password and key line: %q", got)
	}
	if got := found(2); !slices.Contains(got, redact.KindVaultPrivateKey+"="+k.pem) {
		t.Errorf("the whole key: %q", got)
	}
	if got := found(3); len(got) != 0 {
		t.Errorf("plain text: %q", got)
	}
	if got := found(4); !slices.Equal(got, []string{redact.KindVaultPassword + "=" + password}) {
		t.Errorf("after a byte that is not UTF-8: %q", got)
	}

	// Locked, it has nothing to look for, and says so.
	if err := c.Call(ctx, OpLock, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Call(ctx, OpRedact, params, nil); !IsCode(err, CodeLocked) {
		t.Errorf("redact while locked: %v", err)
	}
}

// agent_output is stored as "" for redacted, and only the three policies
// are taken.
func TestPutHostAgentOutput(t *testing.T) {
	f := newFixture(t, nil)
	c := f.client()
	ctx := context.Background()
	for _, c2 := range []struct{ name, in, want string }{
		{"h-default", "", ""}, {"h-redacted", "redacted", ""}, {"h-full", "full", "full"}, {"h-none", "none", "none"},
	} {
		in, want := c2.in, c2.want
		var saved model.Host
		h := f.host(c2.name, func(h *model.Host) { h.AgentOutput = in })
		if err := c.Call(ctx, OpPutHost, PutHostParams{Host: h}, &saved); err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if saved.AgentOutput != want {
			t.Errorf("agent_output %q saved as %q, want %q", in, saved.AgentOutput, want)
		}
	}
	h := f.host("bad", func(h *model.Host) { h.AgentOutput = "some" })
	if err := c.Call(ctx, OpPutHost, PutHostParams{Host: h}, nil); !IsCode(err, CodeInvalid) || !strings.Contains(err.Error(), "agent_output") {
		t.Errorf("a bad agent_output: %v", err)
	}
}

// OpRedact looks text up in the vault's secrets, so it is rationed: a
// request holds at most 256 KiB, and the daemon takes about 8 MiB a
// minute after a 1 MiB burst. Past that it refuses until the budget
// refills. A request refused for its size costs nothing.
func TestRedactIsRationed(t *testing.T) {
	f := newFixture(t, nil)
	c := f.client()
	ctx := context.Background()
	half := []byte(strings.Repeat("a", 128<<10))
	if err := c.Call(ctx, OpRedact, RedactParams{Texts: [][]byte{half, half, []byte("a")}}, nil); !IsCode(err, CodeInvalid) {
		t.Errorf("a request of 256 KiB and a byte: %v, want it refused as invalid", err)
	}
	full := RedactParams{Texts: [][]byte{half, half}}
	for i := range 4 {
		if err := c.Call(ctx, OpRedact, full, nil); err != nil {
			t.Fatalf("request %d of 256 KiB, within the burst: %v", i+1, err)
		}
	}
	if err := c.Call(ctx, OpRedact, full, nil); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Errorf("a fifth request of 256 KiB: %v, want the budget exhausted", err)
	}
}

// The budget refills at about 8 MiB a minute, and never holds more than
// the 1 MiB burst.
func TestRedactBudgetRefills(t *testing.T) {
	f := newFixture(t, nil)
	var clock atomic.Int64
	clock.Store(time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC).UnixNano())
	f.d.redactBudget.mu.Lock()
	f.d.redactBudget.now = func() time.Time { return time.Unix(0, clock.Load()) }
	f.d.redactBudget.mu.Unlock()
	c := f.client()
	ctx := context.Background()
	half := []byte(strings.Repeat("a", 128<<10))
	full := RedactParams{Texts: [][]byte{half, half}}
	drain := func(want int) {
		t.Helper()
		for i := range want {
			if err := c.Call(ctx, OpRedact, full, nil); err != nil {
				t.Fatalf("request %d of %d: %v", i+1, want, err)
			}
		}
		if err := c.Call(ctx, OpRedact, full, nil); !IsCode(err, CodeRedactBudget) {
			t.Fatalf("request %d: %v, want the budget exhausted", want+1, err)
		}
	}
	drain(4)
	clock.Add(int64(2 * time.Second)) // 2 s of 8 MiB a minute: 273 KiB
	drain(1)
	clock.Add(int64(time.Hour)) // far more than the burst
	drain(4)
}

// At most four OpRedact calls run at once; a fifth waits for one to end.
func TestRedactRunsFourAtOnce(t *testing.T) {
	f := newFixture(t, nil)
	c := f.client()
	ctx := context.Background()
	if cap(f.d.redactSlots) != 4 {
		t.Fatalf("%d slots", cap(f.d.redactSlots))
	}
	for range 3 {
		f.d.redactSlots <- struct{}{}
	}
	if err := c.Call(ctx, OpRedact, RedactParams{Texts: [][]byte{[]byte("x")}}, nil); err != nil {
		t.Fatalf("with a slot free: %v", err)
	}
	f.d.redactSlots <- struct{}{}
	done := make(chan error, 1)
	go func() { done <- c.Call(ctx, OpRedact, RedactParams{Texts: [][]byte{[]byte("x")}}, nil) }()
	select {
	case err := <-done:
		t.Fatalf("a call ran with four running: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	<-f.d.redactSlots
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the call did not run once a slot was free")
	}
}
