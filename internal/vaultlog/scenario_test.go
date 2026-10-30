package vaultlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// client is one device's verified view of the vault.
type client struct {
	name string
	dev  DeviceKey
	st   *State
	sec  *Secrets
}

func (c *client) apply(t *testing.T, wire *Wire, server ObjectFetcher) {
	t.Helper()
	st, sec, err := Transition(c.st, c.sec, c.dev, wire, server)
	if err != nil {
		t.Fatalf("%s: seq %d: %v", c.name, wire.Entry.Seq, err)
	}
	c.st, c.sec = st, sec
}

// sameView requires two clients to hold byte-identical state and the same
// item keys and plaintexts. An anchor imports the signed history, so this
// holds for clients anchored at different entries too (rev 12).
func sameView(t *testing.T, a, b *client) {
	t.Helper()
	marshal := func(s *State) []byte {
		b, err := s.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sa, sb := marshal(a.st), marshal(b.st)
	if !bytes.Equal(sa, sb) {
		t.Fatalf("%s and %s hold different states:\n%s\n%s", a.name, b.name, sa, sb)
	}
	if a.sec.VK != b.sec.VK || !a.sec.Account.Pin().Equal(b.sec.Account.Pin()) {
		t.Fatalf("%s and %s hold different keys", a.name, b.name)
	}
	for id, pa := range a.sec.Items {
		pb := b.sec.Items[id]
		ja, _ := canonjson.Marshal(pa.Item)
		jb, _ := canonjson.Marshal(pb.Item)
		if pa.IK != pb.IK || !bytes.Equal(ja, jb) {
			t.Fatalf("%s and %s differ on item %v", a.name, b.name, id)
		}
	}
}

// The §13 multi-entry scenario: genesis, a bootstrapped second device,
// items, a grant, an edit of a granted item, deploy ops, a deletion with
// reference cleanup, an enrollment, and a checkpoint revoking the enrolled
// device. B verifies every entry as an existing client; F verifies the same
// log as a fresh client from the checkpoint anchor; both reach A's state.
func TestScenario(t *testing.T) {
	w := &world{t: t, devs: map[model.ID]*LocalDevice{}, infos: map[model.ID]DeviceInfo{}, archive: ObjectMap{}}
	for id, label := range map[model.ID]string{idDevA: "dev-a", idDevB: "dev-b", idDevC: "dev-c"} {
		w.devs[id], w.infos[id] = fixedDevice(t, id, label)
	}
	server := w.archive
	acct1 := fixedAccount(t, 1, "account1")
	w.acct = acct1

	// Signup on A.
	var vk1 crypto.SymKey
	copy(vk1[:], fixedBytes("vk1", 32))
	genesis, st, sec, err := BuildGenesis(GenesisParams{
		VaultID: idVault, Account: acct1, VK: vk1, Creds: credsFor(t, acct1, "creds1"), Device: w.infos[idDevA], Time: w.now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	w.record(genesis)
	a := &client{name: "A", dev: w.devA(), st: st, sec: sec}
	genesisAccount := st.Account

	// Password login on B: open pw_blob, anchor at genesis, bootstrap.
	var enc1 crypto.SymKey
	copy(enc1[:], fixedBytes("creds1-enc", 32))
	pwEnv, err := crypto.ParseAEADEnvelope(server[a.st.Creds.PwBlobSHA256])
	if err != nil {
		t.Fatal(err)
	}
	bAcct, err := crypto.OpenPwBlob(&enc1, pwEnv, idAccount, 1)
	if err != nil {
		t.Fatal(err)
	}
	bst, bsec, anchorID, err := Anchor(bAcct.Pin(), bAcct, genesis, server, nil)
	if err != nil {
		t.Fatal(err)
	}
	if anchorID.AKV != 1 || anchorID.VaultID != idVault || anchorID.AccountID != idAccount {
		t.Fatalf("anchor identity %+v", anchorID)
	}
	boot, bst, bsec, err := BuildBootstrap(bst, bsec, w.infos[idDevB], w.now())
	if err != nil {
		t.Fatal(err)
	}
	w.record(boot)
	b := &client{name: "B", dev: w.devs[idDevB], st: bst, sec: bsec}
	a.apply(t, boot, server)
	sameView(t, a, b)

	// post builds a normal entry on A and has every other client verify it.
	post := func(ch Changes, others ...*client) *Wire {
		t.Helper()
		wire, st, sec, err := BuildNormal(a.st, a.sec, a.dev, ch, w.now(), server)
		if err != nil {
			t.Fatal(err)
		}
		w.record(wire)
		a.st, a.sec = st, sec
		for _, o := range others {
			o.apply(t, wire, server)
			sameView(t, a, o)
		}
		return wire
	}

	// Items.
	w.pubK1, w.fpK1 = sshKey(t, "k1")
	_, w.fpK2 = sshKey(t, "k2")
	post(Changes{Put: []crypto.Item{
		keyItem(t, idK1, "k1"), keyItem(t, idK2, "k2"),
		hostItem(idH1, "h1", idK1, model.ID{}), hostItem(idH2, "h2", idK2, idC1),
		&model.Credential{Header: model.Header{ItemID: idC1, Type: model.TypeCredential}, Name: "c1", Username: "u", Password: "p"},
		&model.Snippet{Header: model.Header{ItemID: idS1, Type: model.TypeSnippet}, Name: "s1", Command: "uptime", Params: []string{}},
	}}, b)

	// A key item holding a real OpenSSH private key, which is multi-line
	// (text≤16384 allows LF since rev 8), and a host pinning a real host
	// key line.
	_, priv3, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv3, "k3")
	if err != nil {
		t.Fatal(err)
	}
	pem3 := string(pem.EncodeToMemory(block))
	if strings.Count(pem3, "\n") < 3 {
		t.Fatalf("fixture: private key is not multi-line: %q", pem3)
	}
	sshPub3, err := ssh.NewPublicKey(priv3.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub3 := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub3))) + " k3"
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostPub, err := ssh.NewPublicKey(hostPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	h2pinned := *a.sec.Items[idH2].Item.(*model.Host)
	h2pinned.HostKeys = []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostPub)))}
	post(Changes{Put: []crypto.Item{
		&model.Key{Header: model.Header{ItemID: idK3, Type: model.TypeKey}, Name: "k3", KeyType: "ed25519", PrivateKey: pem3, PublicKey: pub3},
		&h2pinned,
	}}, b)
	gotK3 := b.sec.Items[idK3].Item.(*model.Key)
	if gotK3.PrivateKey != pem3 {
		t.Fatal("B's private key differs from A's")
	}
	raw, err := ssh.ParseRawPrivateKey([]byte(gotK3.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := raw.(*ed25519.PrivateKey); !ok || !k.Equal(priv3) {
		t.Fatalf("B's private key parses as %T, not the generated key", raw)
	}
	if fp, err := SSHFingerprint(gotK3.PublicKey); err != nil || fp != ssh.FingerprintSHA256(sshPub3) {
		t.Fatalf("fingerprint of K3: %q, %v", fp, err)
	}

	// A grant over K1, H1 and S1.
	tok, err := crypto.NewToken(idGrant, ed25519.PublicKey(a.st.Account.SigPK))
	if err != nil {
		t.Fatal(err)
	}
	w.token = tok
	tauth, _ := tok.Auth()
	post(Changes{Grants: []NewGrant{{Record: w.grantRecord(), TAuthSHA256: crypto.SHA256(tauth)}}}, b)
	if a.st.Grants[idGrant].BundleVersion != 1 {
		t.Fatal("grant has no first bundle")
	}

	// Edit the granted host: the builder adds bundle version 2, and the
	// token client sees the new host version.
	h1 := a.sec.Items[idH1].Item.(*model.Host)
	h1c := *h1
	h1c.Description = "edited"
	edit := post(Changes{Put: []crypto.Item{&h1c}}, b)
	if len(opsOf[*BundlePutOp](&edit.Entry)) != 1 {
		t.Fatal("editing a granted item must put a bundle")
	}
	gs := a.st.Grants[idGrant]
	benv, err := crypto.ParseHPKEEnvelope(server[gs.EnvelopeSHA256])
	if err != nil {
		t.Fatal(err)
	}
	ob, err := crypto.OpenBundle(tok, benv, gs.BundleVersion, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if h, ok := ob.Items[idH1].(*model.Host); !ok || h.Description != "edited" || h.ItemVersion != 2 {
		t.Fatalf("token sees %+v", ob.Items[idH1])
	}

	// Deploy ops: one incomplete, one closed.
	post(Changes{Deploy: []DeployOp{
		{OpID: idOpD1, Action: ActionDeploy, SSHPKFp: w.fpK1, KeyItemID: idK1, KeyItemVersion: 1,
			Targets: []Target{{HostItemID: idH1, State: TargetPending}, {HostItemID: idH2, State: TargetFailed}}},
		{OpID: idOpD2, Action: ActionDeploy, SSHPKFp: w.fpK2, KeyItemID: idK2, KeyItemVersion: 1,
			Targets: []Target{{HostItemID: idH2, State: TargetDone}}},
	}}, b)

	// Delete C1 (cleaning H2's reference) and S1 (the builder drops it
	// from the grant record and puts a new bundle).
	h2 := *a.sec.Items[idH2].Item.(*model.Host)
	h2.CredentialID = model.ID{}
	del := post(Changes{Put: []crypto.Item{&h2}, Delete: []model.ID{idC1, idS1}}, b)
	if len(opsOf[*BundlePutOp](&del.Entry)) != 1 {
		t.Fatal("deleting a granted item must put a bundle")
	}
	if rec := a.sec.Items[idRecord].Item.(*model.Grant); len(rec.Items) != 2 {
		t.Fatalf("record still lists %v", rec.Items)
	}

	// Enroll C by approval. C opens its unlock blob, anchors at genesis
	// (anchor_seq, anchor_h) and replays the log as transitions.
	infoC := w.enrolled(idDevC)
	enroll := post(Changes{Devices: []DeviceInfo{infoC}}, b)
	addC := opsOf[*DeviceAddOp](&enroll.Entry)[0]
	unlockC, err := crypto.ParseHPKEEnvelope(server[addC.UnlockSHA256])
	if err != nil {
		t.Fatal(err)
	}
	cAcct, err := w.devs[idDevC].OpenUnlock(&addC.Cert, unlockC)
	if err != nil {
		t.Fatal(err)
	}
	gh, _ := genesis.Entry.Hash()
	cst, csec, _, err := Anchor(cAcct.Pin(), cAcct, genesis, server, &Head{Seq: 0, H: gh})
	if err != nil {
		t.Fatal(err)
	}
	c := &client{name: "C", dev: w.devs[idDevC], st: cst, sec: csec}
	for _, wire := range w.log[1:] {
		c.apply(t, wire, server)
	}
	sameView(t, a, c)
	if got := c.st.Devices[idDevC]; !sameJCS(&got.Cert, &addC.Cert) {
		t.Fatal("C's state lacks its own certificate")
	}

	// Checkpoint on A revoking C, with new credentials.
	acct2 := fixedAccount(t, 2, "account2")
	var vk2 crypto.SymKey
	copy(vk2[:], fixedBytes("vk2", 32))
	cp, st, sec, err := BuildCheckpoint(a.st, a.sec, a.dev, CheckpointParams{
		NewAccount: acct2, NewVK: vk2, Creds: credsFor(t, acct2, "creds2"), Revoke: []model.ID{idDevC}, Time: w.now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	w.record(cp)
	a.st, a.sec = st, sec
	b.apply(t, cp, server)
	sameView(t, a, b)
	if _, _, err := Transition(c.st, c.sec, c.dev, cp, server); err == nil {
		t.Fatal("C crossed the checkpoint that revokes it")
	} else if _, ok := err.(*RevokedError); !ok {
		t.Fatalf("C: %v, want a RevokedError", err)
	}
	if len(a.st.Grants) != 0 || len(a.st.DeployOps) != 2 || a.st.Account.AKV != 2 || a.st.KV != 2 {
		t.Fatal("checkpoint state is not as declared")
	}

	// The history holds both account keys and both VK commitments (rev 12).
	if h := a.st.History; len(h.Accounts) != 2 || !h.Accounts[0].matches(&genesisAccount) || !h.Accounts[1].matches(&a.st.Account) ||
		len(h.VKCommits) != 2 || h.VKCommits[0].Commit != crypto.VKCommit(&vk1) || h.VKCommits[1].Commit != crypto.VKCommit(&vk2) {
		t.Fatalf("A's history: %+v", h)
	}

	// A fresh client F logs in with the new password: it opens the new
	// pw_blob, anchors at the checkpoint for akv 2, and must reach the
	// byte-identical state, history included.
	var enc2 crypto.SymKey
	copy(enc2[:], fixedBytes("creds2-enc", 32))
	pw2, err := crypto.ParseAEADEnvelope(server[a.st.Creds.PwBlobSHA256])
	if err != nil {
		t.Fatal(err)
	}
	fAcct, err := crypto.OpenPwBlob(&enc2, pw2, idAccount, 2)
	if err != nil {
		t.Fatal(err)
	}
	fst, fsec, fid, err := Anchor(fAcct.Pin(), fAcct, cp, server, nil)
	if err != nil {
		t.Fatal(err)
	}
	cph, _ := cp.Entry.Hash()
	if fid.H != cph || fid.AKV != 2 || fid.FpSig != acct2.Pin().FpSig {
		t.Fatalf("anchor identity %+v", fid)
	}
	f := &client{name: "F", st: fst, sec: fsec}
	sameView(t, a, f)
	sameView(t, b, f)

	// After the checkpoint, B edits H2 and deletes the revoked grant's
	// record; A and F verify it as transitions.
	h2b := *b.sec.Items[idH2].Item.(*model.Host)
	h2b.Tags = []string{"prod"}
	wire, st, sec, err := BuildNormal(b.st, b.sec, b.dev, Changes{Put: []crypto.Item{&h2b}, Delete: []model.ID{idRecord}}, w.now(), server)
	if err != nil {
		t.Fatal(err)
	}
	w.record(wire)
	b.st, b.sec = st, sec
	a.apply(t, wire, server)
	f.apply(t, wire, server)
	sameView(t, a, b)
	sameView(t, a, f)
	// Secrets are a cache: each client can rebuild them from its state,
	// the objects and its device key.
	for _, cl := range []*client{a, b} {
		sec, err := OpenSecrets(cl.st, cl.dev, server)
		if err != nil {
			t.Fatal(err)
		}
		sameView(t, cl, &client{name: cl.name + " reopened", st: cl.st, sec: sec})
	}
	if _, err := OpenSecrets(a.st, c.dev, server); err == nil {
		t.Fatal("revoked device C reopened the vault")
	}
	if a.st.Head.Seq != uint64(len(w.log)-1) {
		t.Fatalf("head seq %d after %d entries", a.st.Head.Seq, len(w.log))
	}
}

// TestLogEntryVector pins H(E) for a fixed genesis entry (§13, §5.1),
// including its history op (rev 12).
func TestLogEntryVector(t *testing.T) {
	acct := fixedAccount(t, 1, "account1")
	_, dev := fixedDevice(t, idDevA, "dev-a")
	issued := ts(t, "2026-10-22T00:00:00Z")
	cert := crypto.Cert{
		V: 1, AccountID: idAccount, AKV: 1, DeviceID: idDevA, Name: "dev-a",
		KEMFp: crypto.FpKEM(dev.KEMPK), SigFp: crypto.FpSig(dev.SigPK), IssuedAt: issued,
	}
	certSig, err := crypto.SignCert(acct, &cert)
	if err != nil {
		t.Fatal(err)
	}
	var vk crypto.SymKey
	copy(vk[:], fixedBytes("vk1", 32))
	e := Entry{
		V: 1, Suite: 1, VaultID: idVault, Seq: 0, Kind: KindGenesis, AKV: 1, KV: 1, Author: idAccount, Time: issued,
		Ops: []Op{
			accountKeysOp(acct),
			&CredsOp{Op: OpCreds, Gen: 1, KDFVersion: 1, Salt: fixedBytes("salt", 16),
				AuthSHA256: crypto.SHA256([]byte("auth")), RAuthSHA256: crypto.SHA256([]byte("rauth")),
				PwBlobSHA256: crypto.SHA256([]byte("pw_blob")), RkBlobSHA256: crypto.SHA256([]byte("rk_blob"))},
			&DeviceAddOp{Op: OpDeviceAdd, Cert: cert, CertSig: certSig, KEMPK: dev.KEMPK, SigPK: dev.SigPK,
				UnlockSHA256: crypto.SHA256([]byte("unlock"))},
			&VKWrapOp{Op: OpVKWrap, KV: 1, Recipient: idAccount, EnvelopeSHA256: crypto.SHA256([]byte("vk"))},
			&HistoryOp{Op: OpHistory,
				Accounts:  []AccountRow{{AKV: 1, FpKEM: acct.Pin().FpKEM, FpSig: acct.Pin().FpSig}},
				VKCommits: []VKRow{{KV: 1, Commit: crypto.VKCommit(&vk)}}},
		},
	}
	jcs, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	h, err := e.Hash()
	if err != nil {
		t.Fatal(err)
	}
	// H(E) = SHA-256(lp("hopkey/v1/log-entry") || lp(JCS(E))), computed here
	// without crypto.D.
	label := []byte(crypto.LabelLogEntry)
	manual := crypto.SHA256(append(crypto.LP(label), crypto.LP(jcs)...))
	if manual != h {
		t.Fatal("H(E) differs from SHA-256(lp(label) || lp(JCS(E)))")
	}
	parsed, err := ParseEntry(jcs)
	if err != nil {
		t.Fatal(err)
	}
	if ph, _ := parsed.Hash(); ph != h {
		t.Fatal("parsed entry hashes differently")
	}
	want := vector(t, "log_entry.json")
	if string(jcs) != want["jcs"] || h.String() != want["h"] {
		t.Fatalf("vector mismatch:\njcs %s\nh   %s", jcs, h)
	}
}
