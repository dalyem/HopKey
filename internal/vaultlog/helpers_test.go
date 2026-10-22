package vaultlog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// fixedID returns an ID whose bytes are b, b+1, ..., b+15.
func fixedID(b byte) model.ID {
	var id model.ID
	for i := range id {
		id[i] = b + byte(i)
	}
	return id
}

// fixedBytes returns n bytes derived from a label.
func fixedBytes(label string, n int) []byte {
	var out []byte
	for i := 0; len(out) < n; i++ {
		s := sha256.Sum256(append([]byte(label), byte(i)))
		out = append(out, s[:]...)
	}
	return out[:n]
}

func fixedAccount(t testing.TB, akv uint32, label string) *crypto.AccountKeys {
	t.Helper()
	kem, err := crypto.DeriveKEMKey(fixedBytes(label+"-kem", 32))
	if err != nil {
		t.Fatal(err)
	}
	k, err := crypto.NewAccountKeys(idAccount, akv, kem, fixedBytes(label+"-sig", 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fixedDevice(t testing.TB, id model.ID, label string) (*LocalDevice, DeviceInfo) {
	t.Helper()
	kem, err := crypto.DeriveKEMKey(fixedBytes(label+"-kem", 32))
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.NewKeyFromSeed(fixedBytes(label+"-sig", 32))
	d := &LocalDevice{ID: id, KEM: kem, Sig: sig}
	return d, DeviceInfo{ID: id, Name: label, KEMPK: kem.PublicKey().Bytes(), SigPK: sig.Public().(ed25519.PublicKey)}
}

func ts(t testing.TB, s string) model.Timestamp {
	t.Helper()
	var x model.Timestamp
	if err := x.UnmarshalText([]byte(s)); err != nil {
		t.Fatal(err)
	}
	return x
}

func credsFor(t testing.TB, acct *crypto.AccountKeys, label string) CredsInput {
	t.Helper()
	var enc, rk crypto.SymKey
	copy(enc[:], fixedBytes(label+"-enc", 32))
	copy(rk[:], fixedBytes(label+"-rk", 32))
	pw, err := crypto.SealPwBlob(&enc, acct)
	if err != nil {
		t.Fatal(err)
	}
	rkb, err := crypto.SealRkBlob(&rk, acct)
	if err != nil {
		t.Fatal(err)
	}
	return CredsInput{
		KDFVersion: 1, Salt: fixedBytes(label+"-salt", 16),
		AuthSHA256: crypto.SHA256([]byte(label + "-auth")), RAuthSHA256: crypto.SHA256([]byte(label + "-rauth")),
		PwBlob: pw, RkBlob: rkb,
	}
}

// sshKey returns an OpenSSH public-key line and its fingerprint.
func sshKey(t testing.TB, label string) (string, string) {
	t.Helper()
	pub := ed25519.NewKeyFromSeed(fixedBytes(label, 32)).Public()
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " " + label, ssh.FingerprintSHA256(pk)
}

var (
	idAccount = fixedID(0x10)
	idVault   = fixedID(0x20)
	idDevA    = fixedID(0xa0)
	idDevB    = fixedID(0xb0)
	idDevC    = fixedID(0xc0)
	idK1      = fixedID(0x31)
	idK2      = fixedID(0x32)
	idH1      = fixedID(0x41)
	idH2      = fixedID(0x42)
	idC1      = fixedID(0x51)
	idS1      = fixedID(0x61)
	idRecord  = fixedID(0x71)
	idGrant   = fixedID(0x81)
	idOpD1    = fixedID(0x91)
	idOpD2    = fixedID(0x92)
	idK3      = fixedID(0x33)
)

// enrolled returns the DeviceInfo of id with an enroll_transcript, as
// enrollment by approval sets it (rev 10 item 14).
func (w *world) enrolled(id model.ID) DeviceInfo {
	d := w.infos[id]
	d.EnrollTranscript = crypto.SomeHash(crypto.SHA256(fixedBytes("transcript-"+d.Name, 32)))
	return d
}

// resignCert replaces a device_add's cert_sig with a valid one under acct,
// so a test reaches the rule it targets rather than the certificate check.
func resignCert(t testing.TB, d *DeviceAddOp, acct *crypto.AccountKeys) {
	t.Helper()
	sig, err := crypto.SignCert(acct, &d.Cert)
	if err != nil {
		t.Fatal(err)
	}
	d.CertSig = sig
}

// deviceAddFor returns the device_add op for id.
func deviceAddFor(t testing.TB, e *Entry, id model.ID) *DeviceAddOp {
	t.Helper()
	for _, d := range opsOf[*DeviceAddOp](e) {
		if d.Cert.DeviceID == id {
			return d
		}
	}
	t.Fatalf("no device_add for %v", id)
	return nil
}

func keyItem(t testing.TB, id model.ID, label string) *model.Key {
	pub, _ := sshKey(t, label)
	return &model.Key{
		Header: model.Header{ItemID: id, Type: model.TypeKey}, Name: label, KeyType: "ed25519",
		PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY----- " + label + " -----END OPENSSH PRIVATE KEY-----",
		PublicKey:  pub,
	}
}

func hostItem(id model.ID, name string, key, cred model.ID) *model.Host {
	return &model.Host{
		Header: model.Header{ItemID: id, Type: model.TypeHost}, Name: name,
		Aliases: []string{}, Addresses: []string{name + ".example"}, Port: 22, User: "root",
		KeyID: key, CredentialID: cred, Tags: []string{}, Route: "auto", HostKeys: []string{}, AgentAccess: "allow",
	}
}

// world is a vault built through the package's own builders, seen by
// device A. Each step is verified as a transition.
type world struct {
	t       testing.TB
	acct    *crypto.AccountKeys
	devs    map[model.ID]*LocalDevice
	infos   map[model.ID]DeviceInfo
	archive ObjectMap // every object ever posted ("the server")
	st      *State
	sec     *Secrets
	log     []*Wire
	tick    int64
	token   *crypto.Token
	pubK1   string
	fpK1    string
	fpK2    string
}

func (w *world) now() model.Timestamp {
	w.tick++
	return ts(w.t, "2026-10-22T00:00:00Z") + model.Timestamp(w.tick*60)
}

func (w *world) record(wire *Wire) {
	w.t.Helper()
	objs, err := WireObjects(wire)
	if err != nil {
		w.t.Fatal(err)
	}
	for h, b := range objs {
		w.archive[h] = b
	}
	w.log = append(w.log, wire)
}

func (w *world) devA() *LocalDevice { return w.devs[idDevA] }

// newWorld runs genesis (device A) and a bootstrap of device B.
func newWorld(t testing.TB) *world {
	t.Helper()
	w := &world{t: t, devs: map[model.ID]*LocalDevice{}, infos: map[model.ID]DeviceInfo{}, archive: ObjectMap{}}
	w.acct = fixedAccount(t, 1, "account1")
	for id, label := range map[model.ID]string{idDevA: "dev-a", idDevB: "dev-b", idDevC: "dev-c"} {
		w.devs[id], w.infos[id] = fixedDevice(t, id, label)
	}
	var vk crypto.SymKey
	copy(vk[:], fixedBytes("vk1", 32))
	wire, st, sec, err := BuildGenesis(GenesisParams{
		VaultID: idVault, Account: w.acct, VK: vk, Creds: credsFor(t, w.acct, "creds1"),
		Device: w.infos[idDevA], Time: w.now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	w.record(wire)
	w.st, w.sec = st, sec
	wire, st, sec, err = BuildBootstrap(w.st, w.sec, w.infos[idDevB], w.now())
	if err != nil {
		t.Fatal(err)
	}
	w.record(wire)
	w.st, w.sec = st, sec
	return w
}

// normal builds, verifies and applies a normal entry by A.
func (w *world) normal(ch Changes) *Wire {
	w.t.Helper()
	wire, st, sec, err := BuildNormal(w.st, w.sec, w.devA(), ch, w.now(), w.archive)
	if err != nil {
		w.t.Fatal(err)
	}
	w.record(wire)
	w.st, w.sec = st, sec
	return wire
}

// withItems adds K1, K2, H1 (key K1), H2 (key K2, credential C1), C1 and S1.
func (w *world) withItems() *world {
	w.t.Helper()
	w.pubK1, w.fpK1 = sshKey(w.t, "k1")
	_, w.fpK2 = sshKey(w.t, "k2")
	w.normal(Changes{Put: []crypto.Item{
		keyItem(w.t, idK1, "k1"), keyItem(w.t, idK2, "k2"),
		hostItem(idH1, "h1", idK1, model.ID{}), hostItem(idH2, "h2", idK2, idC1),
		&model.Credential{Header: model.Header{ItemID: idC1, Type: model.TypeCredential}, Name: "c1", Username: "u", Password: "p"},
		&model.Snippet{Header: model.Header{ItemID: idS1, Type: model.TypeSnippet}, Name: "s1", Command: "uptime", Params: []string{}},
	}})
	return w
}

func (w *world) grantRecord() *model.Grant {
	w.t.Helper()
	tkem, err := w.token.KEMKey()
	if err != nil {
		w.t.Fatal(err)
	}
	return &model.Grant{
		Header:  model.Header{ItemID: idRecord, Type: model.TypeGrant},
		GrantID: idGrant, Name: "ci", ExpiresAt: ts(w.t, "2030-01-01T00:00:00Z"),
		TokenKEMPK: tkem.PublicKey().Bytes(),
		Items:      []model.ID{idK1, idH1, idS1},
		HostKeyMap: map[model.ID]model.ID{idH1: idK1},
		KeyPolicy:  "shared",
	}
}

// withGrant adds grant G whose record lists K1, H1 and S1.
func (w *world) withGrant() *world {
	w.t.Helper()
	tok, err := crypto.NewToken(idGrant, ed25519.PublicKey(w.st.Account.SigPK))
	if err != nil {
		w.t.Fatal(err)
	}
	w.token = tok
	tauth, err := tok.Auth()
	if err != nil {
		w.t.Fatal(err)
	}
	w.normal(Changes{Grants: []NewGrant{{Record: w.grantRecord(), TAuthSHA256: crypto.SHA256(tauth)}}})
	return w
}

// withDeploy adds D1 (deploy K1 to H1, pending) and D2 (K2 to H2, done).
func (w *world) withDeploy() *world {
	w.t.Helper()
	w.normal(Changes{Deploy: []DeployOp{
		{OpID: idOpD1, Action: ActionDeploy, SSHPKFp: w.fpK1, KeyItemID: idK1, KeyItemVersion: 1,
			Targets: []Target{{HostItemID: idH1, State: TargetPending}}},
		{OpID: idOpD2, Action: ActionDeploy, SSHPKFp: w.fpK2, KeyItemID: idK2, KeyItemVersion: 1,
			Targets: []Target{{HostItemID: idH2, State: TargetDone}}},
	}})
	return w
}

// full is a world with items, a grant and deploy ops.
func full(t testing.TB) *world { return newWorld(t).withItems().withGrant().withDeploy() }

// item returns a copy of A's current plaintext of id.
func (w *world) item(id model.ID) crypto.Item {
	it, _, err := withHeader(w.sec.Items[id].Item, w.st.Items[id].ItemVersion)
	if err != nil {
		w.t.Fatal(err)
	}
	return it
}

func (w *world) host(id model.ID) *model.Host { return w.item(id).(*model.Host) }

// unverified builds a normal entry by A without verifying it.
func (w *world) unverified(ch Changes) *Wire {
	w.t.Helper()
	wire, err := buildNormalWire(w.st, w.sec, w.devA(), ch, w.now())
	if err != nil {
		w.t.Fatal(err)
	}
	return wire
}

// newAccount2 returns the akv-2 account keys used by checkpoints.
func (w *world) newAccount2() *crypto.AccountKeys {
	return fixedAccount(w.t, w.st.Account.AKV+1, "account2")
}

func (w *world) checkpointParams(revoke ...model.ID) CheckpointParams {
	na := w.newAccount2()
	var vk crypto.SymKey
	copy(vk[:], fixedBytes("vk2", 32))
	return CheckpointParams{NewAccount: na, NewVK: vk, Creds: credsFor(w.t, na, "creds2"), Revoke: revoke, Time: w.now()}
}

func (w *world) unverifiedCheckpoint(p CheckpointParams) *Wire {
	w.t.Helper()
	wire, err := buildCheckpointWire(w.st, w.sec, w.devA(), p)
	if err != nil {
		w.t.Fatal(err)
	}
	return wire
}

// cloneWire deep-copies a wire through its JSON form.
func cloneWire(t testing.TB, w *Wire) *Wire {
	t.Helper()
	b, err := w.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseWire(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type signer func(*Entry) ([]byte, error)

func acctSigner(k *crypto.AccountKeys) signer {
	return func(e *Entry) ([]byte, error) { return crypto.Sign(k.Sig, crypto.LabelLogEntry, e) }
}

func devSigner(d *LocalDevice) signer { return d.SignEntry }

// resign replaces the signature of each role in signers.
func resign(t testing.TB, w *Wire, signers map[Role]signer) {
	t.Helper()
	for i, s := range w.Sigs {
		f, ok := signers[s.Role]
		if !ok {
			continue
		}
		sig, err := f(&w.Entry)
		if err != nil {
			t.Fatal(err)
		}
		w.Sigs[i].Sig = sig
	}
}

// normalSigners re-signs a normal entry as device A.
func (w *world) normalSigners() map[Role]signer {
	return map[Role]signer{RoleDevice: devSigner(w.devA())}
}

// checkpointSigners re-signs a checkpoint by A from akv 1 to akv 2.
func (w *world) checkpointSigners(na *crypto.AccountKeys) map[Role]signer {
	return map[Role]signer{RoleDevice: devSigner(w.devA()), RoleAccountOld: acctSigner(w.acct), RoleAccountNew: acctSigner(na)}
}

// mutate clones wire, applies f to it and re-signs it.
func mutate(t testing.TB, wire *Wire, signers map[Role]signer, f func(e *Entry, w *Wire)) *Wire {
	t.Helper()
	c := cloneWire(t, wire)
	f(&c.Entry, c)
	resign(t, c, signers)
	return c
}

// opsOf returns the ops of type T.
func opsOf[T Op](e *Entry) []T {
	var out []T
	for _, o := range e.Ops {
		if x, ok := o.(T); ok {
			out = append(out, x)
		}
	}
	return out
}

// removeOps drops the ops for which drop returns true.
func removeOps(e *Entry, drop func(Op) bool) {
	e.Ops = slices.DeleteFunc(e.Ops, drop)
}

// putFor returns the item_put op for id.
func putFor(t testing.TB, e *Entry, id model.ID) *ItemPutOp {
	t.Helper()
	for _, p := range opsOf[*ItemPutOp](e) {
		if p.ItemID == id {
			return p
		}
	}
	t.Fatalf("no item_put for %v", id)
	return nil
}

// reseal replaces the item_put for the plaintext's ID with one sealed
// under ik and vk with the op's current ctx fields (after f adjusts them),
// adding the objects to the wire.
func reseal(t testing.TB, w *Wire, s *State, vk, ik crypto.SymKey, it crypto.Item, f func(p *ItemPutOp)) {
	t.Helper()
	h, err := crypto.ItemHeader(it)
	if err != nil {
		t.Fatal(err)
	}
	p := putFor(t, &w.Entry, h.ItemID)
	if f != nil {
		f(p)
	}
	it, _, err = withHeader(it, p.ItemVersion)
	if err != nil {
		t.Fatal(err)
	}
	ctx := itemContext(s, p)
	wrap, err := crypto.WrapItemKey(&vk, ctx, &ik)
	if err != nil {
		t.Fatal(err)
	}
	body, err := crypto.SealItem(&ik, ctx, it)
	if err != nil {
		t.Fatal(err)
	}
	p.WrapSHA256 = addObject(t, w, wrap)
	p.BodySHA256 = addObject(t, w, body)
}

func addObject(t testing.TB, w *Wire, env any) crypto.Hash {
	t.Helper()
	b := &builder{w: *w, seen: map[crypto.Hash]bool{}}
	for _, o := range w.Objects {
		b.seen[o.SHA256] = true
	}
	h, err := b.object(env)
	if err != nil {
		t.Fatal(err)
	}
	w.Objects = b.w.Objects
	return h
}

// transition runs Transition for device A.
func (w *world) transition(wire *Wire) error {
	_, _, err := Transition(w.st, w.sec, w.devA(), wire, w.archive)
	return err
}

func wantRule(t testing.TB, err error, r Rule) {
	t.Helper()
	if err == nil {
		t.Fatalf("entry accepted, want rejection by %s", r)
	}
	if got := RuleOf(err); got != r {
		t.Fatalf("rejected by %q, want %q: %v", got, r, err)
	}
}

func mustAccept(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("valid entry rejected: %v", err)
	}
}

// vector reads a testdata JSON object of strings.
func vector(t testing.TB, name string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
