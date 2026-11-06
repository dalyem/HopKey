package merge

import (
	"crypto/sha256"
	"encoding/json"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// vectorFile is testdata/vectors.json, written by testdata/gen_vectors.py.
// Its digests come from an independent implementation, so other
// implementations of the spec can check themselves against it too.
type vectorFile struct {
	Resolve []struct {
		Name    string          `json:"name"`
		N       string          `json:"n"`
		Action  Action          `json:"action"`
		Seen    json.RawMessage `json:"seen"`
		Want    json.RawMessage `json:"want"`
		Message string          `json:"message"`
		Digest  string          `json:"digest"`
	} `json:"resolve"`
	MergeDiscard []struct {
		Name    string `json:"name"`
		VaultID string `json:"vault_id"`
		TxnID   string `json:"txn_id"`
		Rows    []struct {
			ItemID string `json:"item_id"`
			Type   string `json:"type"`
			Digest string `json:"digest"`
		} `json:"rows"`
		Message string `json:"message"`
		Digest  string `json:"digest"`
	} `json:"merge_discard"`
	MergeItem []struct {
		Name      string          `json:"name"`
		Plaintext json.RawMessage `json:"plaintext"`
		Message   string          `json:"message"`
		Digest    string          `json:"digest"`
	} `json:"merge_item"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Resolve) == 0 || len(v.MergeDiscard) == 0 || len(v.MergeItem) == 0 {
		t.Fatal("vectors.json is missing a section")
	}
	return v
}

func optItem(t *testing.T, raw json.RawMessage) *Item {
	t.Helper()
	if string(raw) == "null" {
		return nil
	}
	it, err := ParseItem(raw)
	if err != nil {
		t.Fatal(err)
	}
	return it
}

func TestKnownAnswerVectors(t *testing.T) {
	v := loadVectors(t)

	for _, tc := range v.Resolve {
		t.Run("resolve/"+tc.Name, func(t *testing.T) {
			seen, want := optItem(t, tc.Seen), optItem(t, tc.Want)
			ref := seen
			if ref == nil {
				ref = want
			}
			n, err := strconv.ParseUint(tc.N, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			in := Intent{Action: tc.Action, ItemID: ref.ID(), Type: ref.Type(), Seen: seen, Want: want}
			o, err := newResolveObject(n, in)
			if err != nil {
				t.Fatal(err)
			}
			msg, err := canonjson.Marshal(o)
			if err != nil {
				t.Fatal(err)
			}
			if string(msg) != tc.Message {
				t.Errorf("message\n got  %s\n want %s", msg, tc.Message)
			}
			got, err := ResolveDigest(n, in)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.Digest {
				t.Errorf("digest %s, want %s", got, tc.Digest)
			}
		})
	}

	for _, tc := range v.MergeItem {
		t.Run("merge-item/"+tc.Name, func(t *testing.T) {
			it := optItem(t, tc.Plaintext)
			msg, err := mergeItemObject(it)
			if err != nil {
				t.Fatal(err)
			}
			if string(msg) != tc.Message {
				t.Errorf("message\n got  %s\n want %s", msg, tc.Message)
			}
			got, err := MergeItemDigest(it)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.Digest {
				t.Errorf("digest %s, want %s", got, tc.Digest)
			}
		})
	}

	for _, tc := range v.MergeDiscard {
		t.Run("merge-discard/"+tc.Name, func(t *testing.T) {
			vault, txn := mustID(t, tc.VaultID), mustID(t, tc.TxnID)
			var rows []ManifestRow
			for _, r := range tc.Rows {
				row := ManifestRow{ItemID: mustID(t, r.ItemID), Type: model.Type(r.Type)}
				if err := row.Digest.UnmarshalText([]byte(r.Digest)); err != nil {
					t.Fatal(err)
				}
				rows = append(rows, row)
			}
			o, err := newDiscardObject(vault, txn, rows)
			if err != nil {
				t.Fatal(err)
			}
			msg, err := canonjson.Marshal(o)
			if err != nil {
				t.Fatal(err)
			}
			if string(msg) != tc.Message {
				t.Errorf("message\n got  %s\n want %s", msg, tc.Message)
			}
			got, err := MergeDiscardDigest(vault, txn, rows)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.Digest {
				t.Errorf("digest %s, want %s", got, tc.Digest)
			}
		})
	}
}

// d computes SHA-256(lp(label) || lp(msg)) by hand.
func d(label, msg string) string {
	lp := func(s string) []byte {
		n := len(s)
		return append([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, s...)
	}
	sum := sha256.Sum256(append(lp(label), lp(msg)...))
	return crypto.Hash(sum).String()
}

func TestResolveDigestEncoding(t *testing.T) {
	cred := credential(t, 2, nil)
	seen := string(cred.Plaintext())

	// Members sort by name, n is a decimal string, and an absent side is null.
	got, err := ResolveDigest(4, del(cred))
	if err != nil {
		t.Fatal(err)
	}
	if want := d("hopkey/v1/resolve", `{"action":"delete","n":"4","seen":`+seen+`,"want":null}`); got.String() != want {
		t.Errorf("delete: %s, want %s", got, want)
	}

	got, err = ResolveDigest(0, create(cred))
	if err != nil {
		t.Fatal(err)
	}
	if want := d("hopkey/v1/resolve", `{"action":"create","n":"0","seen":null,"want":`+seen+`}`); got.String() != want {
		t.Errorf("create: %s, want %s", got, want)
	}

	want2 := credential(t, 2, func(c *model.Credential) { c.Password = "new" })
	got, err = ResolveDigest(1<<63, put(cred, want2))
	if err != nil {
		t.Fatal(err)
	}
	msg := `{"action":"put","n":"9223372036854775808","seen":` + seen + `,"want":` + string(want2.Plaintext()) + `}`
	if want := d("hopkey/v1/resolve", msg); got.String() != want {
		t.Errorf("put: %s, want %s", got, want)
	}

	// Digests are 64 lowercase hex characters.
	if s := got.String(); len(s) != 64 || s != strings.ToLower(s) {
		t.Errorf("digest %q is not 64 lowercase hex characters", s)
	}
}

func TestResolveDigestRejectsMalformedIntents(t *testing.T) {
	h := host(t, 1)
	if _, err := ResolveDigest(1, Intent{Action: ActionPut, ItemID: h.ID(), Type: model.TypeHost, Want: h}); err == nil {
		t.Error("accepted a put without seen")
	}
	if _, err := ResolveDigest(1, Intent{Action: ActionDelete, ItemID: h.ID(), Type: model.TypeGrant, Seen: h}); err == nil {
		t.Error("accepted a grant")
	}
}

// TestStaleDigestIsDetected: automation confirms with c, the client
// recomputes c against current S, and a proposal that S changed no longer
// matches.
func TestStaleDigestIsDetected(t *testing.T) {
	seen := host(t, 1)
	held := put(seen, host(t, 2, credRef(t, idCred2)))
	s := host(t, 7, addrs("10.0.0.2"))

	propose := func(s *Item) crypto.Hash {
		t.Helper()
		rep, err := KeepMine(held, CauseGuardedConflict, s)
		if err != nil {
			t.Fatal(err)
		}
		c, err := ResolveDigest(3, rep)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	c := propose(s)
	if c2 := propose(s); c2 != c {
		t.Error("the same proposal gets a different digest")
	}
	// S changes a member the proposal keeps: the group the user approved is
	// no longer what would be written.
	if propose(host(t, 8, addrs("10.0.0.3"))) == c {
		t.Error("digest did not change when S changed an address")
	}
	// S changes a member the user's delta replaces: seen′ still changes.
	if propose(host(t, 8, addrs("10.0.0.2"), credRef(t, "c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9"))) == c {
		t.Error("digest did not change when S changed the credential")
	}
	// A new version of S, even with the same body, is a new seen′.
	if propose(host(t, 9, addrs("10.0.0.2"))) == c {
		t.Error("digest did not change when S moved to a new version")
	}
	// The queue position is part of what was approved.
	rep, err := KeepMine(held, CauseGuardedConflict, s)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ResolveDigest(4, rep)
	if err != nil {
		t.Fatal(err)
	}
	if other == c {
		t.Error("digest does not depend on n")
	}

	// Edit proposals are bound the same way.
	edit := func(s *Item) crypto.Hash {
		t.Helper()
		rep, err := Edit(held, CauseGuardedConflict, s, host(t, 0, name("edited")), nil)
		if err != nil {
			t.Fatal(err)
		}
		c, err := ResolveDigest(3, rep)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if edit(s) == edit(host(t, 8, addrs("10.0.0.3"))) {
		t.Error("an edit's digest did not change with S")
	}
}

func TestResolveDigestsDiffer(t *testing.T) {
	a, b := host(t, 1), host(t, 2, name("x"))
	base, err := ResolveDigest(1, put(a, b))
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]Intent{
		"swapped": put(b, a),
		"delete":  del(a),
		"create":  create(b),
	} {
		got, err := ResolveDigest(1, in)
		if err != nil {
			t.Fatal(err)
		}
		if got == base {
			t.Errorf("%s has the same digest as the put", name)
		}
	}
}

func manifestRows(t *testing.T) []ManifestRow {
	t.Helper()
	var rows []ManifestRow
	for i, id := range []string{
		"ff00000000000000000000000000000f", "00ff0000000000000000000000000000",
		"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "0100000000000000000000000000000a",
		"a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
	} {
		rows = append(rows, ManifestRow{
			ItemID: mustID(t, id),
			Type:   []model.Type{model.TypeHost, model.TypeKey, model.TypeCredential, model.TypeSnippet, model.TypeHost}[i],
			Digest: sha256.Sum256([]byte(id)),
		})
	}
	return rows
}

func TestMergeDiscardDigestOrdering(t *testing.T) {
	vault, txn := mustID(t, idHost), mustID(t, idHost2)
	rows := manifestRows(t)
	sorted := slices.Clone(rows)
	slices.SortFunc(sorted, func(a, b ManifestRow) int { return slices.Compare(a.ItemID[:], b.ItemID[:]) })

	want, err := MergeDiscardDigest(vault, txn, sorted)
	if err != nil {
		t.Fatal(err)
	}
	// The object that is hashed lists the rows in item_id order.
	o, err := newDiscardObject(vault, txn, rows)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(o.Items, sorted) {
		t.Errorf("rows are not sorted by item_id: %v", o.Items)
	}
	// Every input order gives the same digest, and the caller's slice is
	// left alone.
	r := rand.New(rand.NewPCG(1, 2))
	for range 20 {
		shuffled := slices.Clone(rows)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		before := slices.Clone(shuffled)
		got, err := MergeDiscardDigest(vault, txn, shuffled)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("order %v changed the digest", before)
		}
		if !slices.Equal(shuffled, before) {
			t.Fatal("MergeDiscardDigest reordered the caller's slice")
		}
	}

	// Anything that is part of the object changes the digest.
	mutate := func(name string, f func(rows []ManifestRow) ([]ManifestRow, model.ID, model.ID)) {
		t.Helper()
		rs, v, x := f(slices.Clone(sorted))
		got, err := MergeDiscardDigest(v, x, rs)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == want {
			t.Errorf("%s did not change the digest", name)
		}
	}
	mutate("a row's digest", func(r []ManifestRow) ([]ManifestRow, model.ID, model.ID) {
		r[2].Digest[0] ^= 1
		return r, vault, txn
	})
	mutate("a row's type", func(r []ManifestRow) ([]ManifestRow, model.ID, model.ID) {
		r[2].Type = model.TypeSnippet
		return r, vault, txn
	})
	mutate("a row's ID", func(r []ManifestRow) ([]ManifestRow, model.ID, model.ID) {
		r[2].ItemID[15] ^= 1
		return r, vault, txn
	})
	mutate("a missing row", func(r []ManifestRow) ([]ManifestRow, model.ID, model.ID) {
		return r[1:], vault, txn
	})
	mutate("another vault", func(r []ManifestRow) ([]ManifestRow, model.ID, model.ID) { return r, txn, txn })
	mutate("another transaction", func(r []ManifestRow) ([]ManifestRow, model.ID, model.ID) { return r, vault, vault })
}

func TestMergeDiscardDigestRefusals(t *testing.T) {
	vault, txn := mustID(t, idHost), mustID(t, idHost2)
	rows := manifestRows(t)
	if _, err := MergeDiscardDigest(vault, txn, nil); err != nil {
		t.Errorf("no rows: %v", err)
	}
	if empty, _ := MergeDiscardDigest(vault, txn, nil); empty == (crypto.Hash{}) {
		t.Error("empty digest is zero")
	}
	if _, err := MergeDiscardDigest(vault, txn, append(slices.Clone(rows), rows[1])); err == nil {
		t.Error("accepted a repeated item_id")
	}
	if _, err := MergeDiscardDigest(model.ID{}, txn, rows); err == nil {
		t.Error("accepted a zero vault_id")
	}
	if _, err := MergeDiscardDigest(vault, model.ID{}, rows); err == nil {
		t.Error("accepted a zero txn_id")
	}
	bad := slices.Clone(rows)
	bad[0].ItemID = model.ID{}
	if _, err := MergeDiscardDigest(vault, txn, bad); err == nil {
		t.Error("accepted a zero item_id")
	}
	bad = slices.Clone(rows)
	bad[0].Type = model.TypeGrant
	if _, err := MergeDiscardDigest(vault, txn, bad); err == nil {
		t.Error("accepted a grant row")
	}
}

func TestMergeItemDigest(t *testing.T) {
	v1 := key(t, 1, nil)
	v5 := key(t, 5, nil)
	a, err := MergeItemDigest(v1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := MergeItemDigest(v5)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("the digest depends on the source item_version")
	}
	if want := d("hopkey/v1/merge-item", string(v1.Plaintext())); a.String() != want {
		t.Errorf("digest %s, want D over the version-1 plaintext %s", a, want)
	}
	// The input is not changed.
	if m, _ := v5.Member("item_version"); string(m) != `"5"` {
		t.Errorf("item_version member became %s", m)
	}
	// Every other member counts.
	c, err := MergeItemDigest(key(t, 5, func(k *model.Key) { k.Name = "other" }))
	if err != nil {
		t.Fatal(err)
	}
	if c == a {
		t.Error("the digest ignores the name")
	}
	if _, err := MergeItemDigest(nil); err == nil {
		t.Error("accepted nil")
	}
}
