package merge

import (
	"testing"

	"github.com/dalyem/hopkey/internal/model"
)

func mustID(t testing.TB, s string) model.ID {
	t.Helper()
	id, err := model.ParseID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Fixed IDs. The host under test is idHost.
const (
	idHost  = "11111111111111111111111111111111"
	idHost2 = "22222222222222222222222222222222"
	idCred  = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
	idCred2 = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"
	idKey   = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
	idSnip  = "5050505050505050505050505050505a"
	idFresh = "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"
)

type hostMod func(*model.Host)

func name(s string) hostMod     { return func(h *model.Host) { h.Name = s } }
func addrs(a ...string) hostMod { return func(h *model.Host) { h.Addresses = a } }
func user(s string) hostMod     { return func(h *model.Host) { h.User = s } }
func tags(a ...string) hostMod  { return func(h *model.Host) { h.Tags = a } }
func hostDesc(s string) hostMod { return func(h *model.Host) { h.Description = s } }
func credRef(t testing.TB, id string) hostMod {
	cid := mustID(t, id)
	return func(h *model.Host) { h.CredentialID = cid }
}

// host builds the base host at item_version ver with mods applied in order.
func host(t testing.TB, ver uint64, mods ...hostMod) *Item {
	t.Helper()
	h := model.Host{
		Header:       model.Header{V: 1, ItemID: mustID(t, idHost), Type: model.TypeHost, ItemVersion: ver},
		Name:         "web",
		Aliases:      []string{"w"},
		Addresses:    []string{"10.0.0.1"},
		Port:         22,
		User:         "root",
		CredentialID: mustID(t, idCred),
		Tags:         []string{"prod"},
		Description:  "d",
		Route:        "auto",
		AgentAccess:  "allow",
	}
	for _, m := range mods {
		m(&h)
	}
	it, err := ItemOf(h)
	if err != nil {
		t.Fatal(err)
	}
	return it
}

func credential(t testing.TB, ver uint64, mod func(*model.Credential)) *Item {
	t.Helper()
	c := model.Credential{
		Header:   model.Header{V: 1, ItemID: mustID(t, idCred), Type: model.TypeCredential, ItemVersion: ver},
		Name:     "root login",
		Username: "root",
		Password: "hunter2",
	}
	if mod != nil {
		mod(&c)
	}
	it, err := ItemOf(&c)
	if err != nil {
		t.Fatal(err)
	}
	return it
}

func key(t testing.TB, ver uint64, mod func(*model.Key)) *Item {
	t.Helper()
	k := model.Key{
		Header:     model.Header{V: 1, ItemID: mustID(t, idKey), Type: model.TypeKey, ItemVersion: ver},
		Name:       "deploy",
		KeyType:    "ed25519",
		PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBase deploy",
	}
	if mod != nil {
		mod(&k)
	}
	it, err := ItemOf(k)
	if err != nil {
		t.Fatal(err)
	}
	return it
}

func snippet(t testing.TB, ver uint64, mod func(*model.Snippet)) *Item {
	t.Helper()
	s := model.Snippet{
		Header:      model.Header{V: 1, ItemID: mustID(t, idSnip), Type: model.TypeSnippet, ItemVersion: ver},
		Name:        "restart",
		Command:     "systemctl restart {{unit}}",
		Params:      []string{"unit"},
		Description: "restart a unit",
	}
	if mod != nil {
		mod(&s)
	}
	it, err := ItemOf(s)
	if err != nil {
		t.Fatal(err)
	}
	return it
}

func intent(action Action, seen, want *Item) Intent {
	ref := seen
	if ref == nil {
		ref = want
	}
	return Intent{Action: action, ItemID: ref.ID(), Type: ref.Type(), Seen: seen, Want: want}
}

func put(seen, want *Item) Intent { return intent(ActionPut, seen, want) }
func del(seen *Item) Intent       { return intent(ActionDelete, seen, nil) }
func create(want *Item) Intent    { return intent(ActionCreate, nil, want) }

// samePlain fails the test unless a and b are the same item on every
// member, header included.
func samePlain(t testing.TB, got, want *Item) {
	t.Helper()
	if got == nil || want == nil {
		t.Fatalf("got %v, want %v", got, want)
	}
	if g, w := string(got.Plaintext()), string(want.Plaintext()); g != w {
		t.Errorf("plaintext differs\n got  %s\n want %s", g, w)
	}
}

func sameIntent(t testing.TB, got, want Intent) {
	t.Helper()
	if got.Action != want.Action || got.ItemID != want.ItemID || got.Type != want.Type {
		t.Fatalf("intent header: got %s %s %s, want %s %s %s",
			got.Action, got.ItemID, got.Type, want.Action, want.ItemID, want.Type)
	}
	for _, c := range []struct {
		which     string
		got, want *Item
	}{{"seen", got.Seen, want.Seen}, {"want", got.Want, want.Want}} {
		if (c.got == nil) != (c.want == nil) {
			t.Fatalf("%s: got %v, want %v", c.which, c.got, c.want)
		}
		if c.got != nil {
			if g, w := string(c.got.Plaintext()), string(c.want.Plaintext()); g != w {
				t.Errorf("%s differs\n got  %s\n want %s", c.which, g, w)
			}
		}
	}
}
