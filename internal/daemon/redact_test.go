package daemon

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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
