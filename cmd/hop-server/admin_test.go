package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/server"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

const testOrigin = "https://hop.example.com"

// hostileDevice is a device name the certificate schema accepts: a bidi
// override and a zero-width space, but no Cc character.
const hostileDevice = "evil\u202egnp.exe\u200b"

// hostileEmail is what a tampered database could hold: an ANSI sequence
// that clears the screen, a bidi override, a newline and invalid UTF-8.
const hostileEmail = "evil\x1b[2J\u202e\nx\xff@example.com"

func mustRun(t *testing.T, args ...string) (string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatalf("%v: %v\nstderr: %s", args, err, stderr.String())
	}
	return stdout.String(), stderr.String()
}

// assertTerminalSafe fails when out holds a character that could move
// the cursor, recolour or reorder the terminal. Newlines between lines are
// layout.
func assertTerminalSafe(t *testing.T, what, out string) {
	t.Helper()
	for _, c := range strings.ReplaceAll(out, "\n", "") {
		if unsafeRune(c) {
			t.Errorf("%s: raw %U in %q", what, c, out)
			return
		}
	}
}

func newID(t *testing.T) model.ID {
	t.Helper()
	id, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func random(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// post sends a canonical JSON request to h and decodes the answer into
// resp.
func post(t *testing.T, h http.Handler, path string, body, resp any) int {
	t.Helper()
	b, err := canonjson.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	h.ServeHTTP(rec, newRequest("POST", path, string(b)))
	if rec.Code == 200 && resp != nil {
		if err := canonjson.Unmarshal(rec.Body.Bytes(), resp); err != nil {
			t.Fatalf("%s: %v: %s", path, err, rec.Body)
		}
	}
	return rec.Code
}

// signup creates an account through the real server: an invite from the
// invite command, then the signup challenge and a genesis with one device
// named devName. It returns the account and device IDs.
func signup(t *testing.T, dir, addr, devName string) (model.ID, model.ID) {
	t.Helper()
	out, _ := mustRun(t, "invite", addr, "--data", dir)
	code := strings.TrimSpace(out)
	st, err := server.OpenSQLite(filepath.Join(dir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv, err := server.New(context.Background(), server.Config{Origin: testOrigin, Store: st})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	h := srv.Handler()

	var chal struct {
		Challenge []byte `json:"challenge"`
	}
	if c := post(t, h, "/v1/signup/challenge", map[string]string{"email": addr, "registration_code": code}, &chal); c != 200 {
		t.Fatalf("signup challenge: %d", c)
	}
	acct, err := crypto.GenerateAccountKeys(newID(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	vk, err := crypto.NewSymKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.NewSymKey()
	if err != nil {
		t.Fatal(err)
	}
	pw, err := crypto.SealPwBlob(&enc, acct)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := crypto.SealRkBlob(&enc, acct)
	if err != nil {
		t.Fatal(err)
	}
	kem, err := crypto.GenerateKEMKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dev := newID(t)
	w, _, _, err := vaultlog.BuildGenesis(vaultlog.GenesisParams{
		VaultID: newID(t), Account: acct, VK: vk,
		Creds: vaultlog.CredsInput{
			KDFVersion: 1, Salt: random(t, 16), AuthSHA256: crypto.SHA256(random(t, 32)),
			RAuthSHA256: crypto.SHA256(random(t, 32)), PwBlob: pw, RkBlob: rk,
		},
		Device: vaultlog.DeviceInfo{ID: dev, Name: devName, KEMPK: kem.PublicKey().Bytes(), SigPK: pub},
		Time:   model.TimestampOf(time.Now()),
	})
	if err != nil {
		t.Fatal(err)
	}
	eh, err := w.Entry.Hash()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.SignSignupPoP(acct, &crypto.SignupPoP{
		V: 1, Origin: testOrigin, Email: addr, AccountID: acct.AccountID, VaultID: w.Entry.VaultID,
		UploadSeq: 0, UploadH: eh, Challenge: chal.Challenge,
	})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := w.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	req := struct {
		Email            string          `json:"email"`
		RegistrationCode string          `json:"registration_code"`
		Challenge        []byte          `json:"challenge"`
		PopSig           []byte          `json:"pop_sig"`
		Wires            []canonjson.Raw `json:"wires"`
	}{addr, code, chal.Challenge, sig, []canonjson.Raw{wire}}
	if c := post(t, h, "/v1/signup", req, nil); c != 200 {
		t.Fatalf("signup: %d", c)
	}
	return acct.AccountID, dev
}

func rawDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// dump is every row of every table, for checking that nothing changed.
func dump(t *testing.T, dir string) string {
	t.Helper()
	db := rawDB(t, dir)
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, n)
	}
	rows.Close()
	var b strings.Builder
	for _, tbl := range tables {
		r, err := db.Query(`SELECT * FROM "` + tbl + `" ORDER BY rowid`)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := r.Columns()
		for r.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := r.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&b, "%s %q\n", tbl, vals)
		}
		r.Close()
	}
	return b.String()
}

// stubTerminal makes the confirmation prompt read answer from a terminal,
// or see no terminal when answer is "".
func stubTerminal(t *testing.T, answer string) {
	t.Helper()
	oldIn, oldTTY, oldActor := stdin, stdinIsTTY, actor
	stdin = strings.NewReader(answer)
	stdinIsTTY = func() bool { return answer != "" }
	actor = func() string { return "tester (uid 1000)" }
	t.Cleanup(func() { stdin, stdinIsTTY, actor = oldIn, oldTTY, oldActor })
}

func TestEsc(t *testing.T) {
	for in, want := range map[string]string{
		"alice@example.com":   "alice@example.com",
		"\x1b[2Jred":          `\x1b[2Jred`,
		"a\nb\tc\rd":          `a\x0ab\x09c\x0dd`,
		"\u202egnp.exe\u200b": `\u202egnp.exe\u200b`,
		"\u2066x\u2069":       `\u2066x\u2069`,
		"del\x7f c1\u0085":    `del\x7f c1\x85`,
		"bad\xff\xfeutf8":     `bad\xff\xfeutf8`,
		`back\slash`:          `back\\slash`,
		"line\u2028sep":       `line\u2028sep`,
		"tag\U000E0041":       `tag\U000e0041`,
		"Café ☕ 日本":           "Café ☕ 日本",
	} {
		got := esc(in)
		if got != want {
			t.Errorf("esc(%q) = %q, want %q", in, got, want)
		}
		assertTerminalSafe(t, "esc", got)
	}
}

// JSON output keeps a hostile value intact for a script and inert on a
// terminal.
func TestWriteJSONEscapes(t *testing.T) {
	in := map[string]string{"email": "a\x1b[2J\u202e\u0085\u200b\U000E0041@example.com"}
	var out bytes.Buffer
	if err := writeJSON(&out, in); err != nil {
		t.Fatal(err)
	}
	assertTerminalSafe(t, "writeJSON", out.String())
	var back map[string]string
	if err := json.Unmarshal(out.Bytes(), &back); err != nil || back["email"] != in["email"] {
		t.Errorf("round trip: %q, %v", back["email"], err)
	}
}

// accounts ls and show, human and JSON, on a real account whose device has
// a hostile name and whose email row was tampered with.
func TestAccountsCommands(t *testing.T) {
	dir := t.TempDir()
	stubTerminal(t, "")
	acct, dev := signup(t, dir, "alice@example.com", hostileDevice)
	signup(t, dir, "bob@example.com", "laptop")
	if _, err := rawDB(t, dir).Exec(`UPDATE accounts SET email = ? WHERE email = 'bob@example.com'`, hostileEmail); err != nil {
		t.Fatal(err)
	}

	out, _ := mustRun(t, "accounts", "ls", "--data", dir)
	assertTerminalSafe(t, "accounts ls", out)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "ACCOUNT") {
		t.Fatalf("accounts ls:\n%s", out)
	}
	if !strings.Contains(lines[1], acct.String()) || !strings.Contains(lines[1], "alice@example.com") || !strings.Contains(lines[1], "1/1") {
		t.Errorf("first row %q", lines[1])
	}
	if !strings.Contains(lines[2], esc(hostileEmail)) {
		t.Errorf("second row %q does not hold the escaped email %s", lines[2], esc(hostileEmail))
	}

	out, _ = mustRun(t, "accounts", "ls", "--json", "--data", dir)
	assertTerminalSafe(t, "accounts ls --json", out)
	var ls struct {
		Accounts []struct {
			AccountID     model.ID   `json:"account_id"`
			Email         string     `json:"email"`
			ActiveDevices int        `json:"active_devices"`
			Devices       int        `json:"devices"`
			HeadSeq       uint64     `json:"head_seq"`
			LastSeen      *time.Time `json:"last_seen"`
			LastBootstrap *int64     `json:"last_bootstrap_seq"`
			Checkpoint    *int64     `json:"last_checkpoint_seq"`
			Reserve       string     `json:"reserve"`
			UsedBytes     int64      `json:"used_bytes"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal([]byte(out), &ls); err != nil {
		t.Fatal(err)
	}
	if len(ls.Accounts) != 2 {
		t.Fatalf("accounts ls --json: %s", out)
	}
	a := ls.Accounts[0]
	if a.AccountID != acct || a.ActiveDevices != 1 || a.Devices != 1 || a.HeadSeq != 0 || a.LastSeen != nil ||
		a.LastBootstrap != nil || a.Checkpoint == nil || *a.Checkpoint != 0 || a.Reserve != "intact" || a.UsedBytes <= 0 {
		t.Errorf("first account %+v", a)
	}
	if !strings.HasPrefix(ls.Accounts[1].Email, "evil\x1b[2J\u202e\nx") {
		t.Errorf("JSON email %q is not the stored value", ls.Accounts[1].Email)
	}

	for _, who := range []string{acct.String(), "alice@example.com"} {
		out, _ = mustRun(t, "accounts", "show", who, "--data", dir)
		assertTerminalSafe(t, "accounts show", out)
		for _, want := range []string{"account       " + acct.String(), "email         alice@example.com", "sessions      0 live",
			"invites       none pending", "devices: 1 active, 1 in all", dev.String() + "  active", esc(hostileDevice)} {
			if !strings.Contains(out, want) {
				t.Errorf("accounts show %s lacks %q:\n%s", who, want, out)
			}
		}
	}
	out, _ = mustRun(t, "accounts", "show", acct.String(), "--json", "--data", dir)
	assertTerminalSafe(t, "accounts show --json", out)
	var show struct {
		Account struct {
			AccountID model.ID `json:"account_id"`
			Sessions  int      `json:"sessions"`
			Devices   []struct {
				DeviceID model.ID `json:"device_id"`
				Name     string   `json:"name"`
				Active   bool     `json:"active"`
			} `json:"device_list"`
			Invites []json.RawMessage `json:"pending_invites"`
		} `json:"account"`
	}
	if err := json.Unmarshal([]byte(out), &show); err != nil {
		t.Fatal(err)
	}
	if show.Account.AccountID != acct || len(show.Account.Devices) != 1 || show.Account.Devices[0].Name != hostileDevice ||
		show.Account.Devices[0].DeviceID != dev || !show.Account.Devices[0].Active || show.Account.Invites == nil {
		t.Errorf("accounts show --json: %s", out)
	}

	// The tampered email is shown escaped too.
	out, _ = mustRun(t, "accounts", "show", ls.Accounts[1].AccountID.String(), "--data", dir)
	assertTerminalSafe(t, "accounts show of a tampered email", out)
	if !strings.Contains(out, esc(hostileEmail)) {
		t.Errorf("accounts show:\n%s", out)
	}

	var stderr bytes.Buffer
	if err := run([]string{"accounts", "show", "nobody@example.com", "--data", dir}, io.Discard, &stderr); err == nil || !strings.Contains(err.Error(), "no such account") {
		t.Errorf("show of an unknown account: %v", err)
	}
	if err := run([]string{"accounts", "rm", "--data", dir}, io.Discard, &stderr); err == nil {
		t.Error("an unknown accounts command")
	}
	out, _ = mustRun(t, "accounts", "ls", "--data", t.TempDir())
	if strings.TrimSpace(out) != "no accounts" {
		t.Errorf("an empty server: %q", out)
	}
}

type auditLine struct {
	Audit struct {
		ID        int64           `json:"id"`
		Actor     string          `json:"actor"`
		Action    string          `json:"action"`
		AccountID *model.ID       `json:"account_id"`
		Params    json.RawMessage `json:"params"`
		Result    string          `json:"result"`
	} `json:"admin_audit"`
}

func parseAuditLine(t *testing.T, stderr string) auditLine {
	t.Helper()
	// After a prompt the line starts after the answer, which a real
	// terminal echoes with its newline.
	var a auditLine
	i := strings.LastIndex(stderr, `{"admin_audit"`)
	if i < 0 {
		t.Fatalf("no audit line in %q", stderr)
	}
	line, _, _ := strings.Cut(stderr[i:], "\n")
	if err := json.Unmarshal([]byte(line), &a); err != nil || a.Audit.ID == 0 {
		t.Fatalf("no audit line in %q: %v", stderr, err)
	}
	return a
}

// invites ls|revoke|reissue, with --dry-run changing nothing, the
// confirmation rules, the audit rows and their stderr lines.
func TestInvitesCommands(t *testing.T) {
	dir := t.TempDir()
	stubTerminal(t, "")
	signup(t, dir, "used@example.com", "laptop")
	out, invErr := mustRun(t, "invite", "x@example.com", "--data", dir)
	x1 := strings.TrimSpace(out)
	if a := parseAuditLine(t, invErr); a.Audit.Action != "invites.create" || strings.Contains(invErr, x1) {
		t.Errorf("invite audit line %q", invErr)
	}
	mustRun(t, "invite", "x@example.com", "--data", dir)
	y, _ := mustRun(t, "invite", "y@example.com", "--ttl", "1d", "--data", dir)
	y = strings.TrimSpace(y)
	if _, err := rawDB(t, dir).Exec(`INSERT INTO registrations (cap_hash, email, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		bytes.Repeat([]byte{0xab}, 32), hostileEmail, time.Now().Unix(), time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	out, _ = mustRun(t, "invites", "ls", "--data", dir)
	assertTerminalSafe(t, "invites ls", out)
	if n := strings.Count(out, "pending"); n != 4 || strings.Contains(out, "used@example.com") || !strings.Contains(out, esc(hostileEmail)) {
		t.Errorf("invites ls:\n%s", out)
	}
	out, _ = mustRun(t, "invites", "ls", "--all", "--json", "--data", dir)
	assertTerminalSafe(t, "invites ls --json", out)
	var ls struct {
		Invites []struct {
			Invite    string    `json:"invite"`
			Email     string    `json:"email"`
			State     string    `json:"state"`
			AccountID *model.ID `json:"account_id"`
			Code      string    `json:"code"`
		} `json:"invites"`
	}
	if err := json.Unmarshal([]byte(out), &ls); err != nil {
		t.Fatal(err)
	}
	// encoding/json turns the invalid byte into U+FFFD; the rest is kept.
	isHostile := func(e string) bool { return strings.HasPrefix(e, "evil\x1b[2J\u202e\nx") }
	states := map[string]string{}
	var hostileID string
	for _, inv := range ls.Invites {
		if isHostile(inv.Email) {
			inv.Email, hostileID = "hostile", inv.Invite
		}
		states[inv.Email] = inv.State
		if inv.Code != "" {
			t.Error("invites ls shows a code")
		}
		if inv.Email == "used@example.com" && inv.AccountID == nil {
			t.Error("the used invite has no account")
		}
	}
	if len(ls.Invites) != 5 || states["used@example.com"] != "used" || states["hostile"] != "pending" {
		t.Errorf("invites ls --all --json: %s", out)
	}

	// --dry-run, a refusal without a terminal, and a "no" on one change
	// nothing at all.
	before := dump(t, dir)
	out, _ = mustRun(t, "invites", "revoke", "x@example.com", "--dry-run", "--data", dir)
	if !strings.Contains(out, "would revoke 2 invites") || !strings.Contains(out, "dry run: nothing changed") {
		t.Errorf("revoke --dry-run:\n%s", out)
	}
	mustRun(t, "invites", "revoke", "x@example.com", "--dry-run", "--json", "--data", dir)
	mustRun(t, "invites", "reissue", "y@example.com", "--dry-run", "--data", dir)
	mustRun(t, "invites", "revoke", "x@example.com", "--dry-run", "--yes", "--data", dir)
	err := run([]string{"invites", "revoke", "x@example.com", "--data", dir}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("revoke without a terminal or --yes: %v", err)
	}
	stubTerminal(t, "n\n")
	var prompt bytes.Buffer
	err = run([]string{"invites", "revoke", "x@example.com", "--data", dir}, io.Discard, &prompt)
	if err == nil || !strings.Contains(err.Error(), "cancelled") || !strings.Contains(prompt.String(), "Revoke 2 invites? [y/N]") {
		t.Errorf("answering no: %v, prompt %q", err, prompt.String())
	}
	if after := dump(t, dir); after != before {
		t.Errorf("a dry run or a refusal changed the database:\n%s\nthen\n%s", before, after)
	}

	// "y" on the terminal revokes.
	stubTerminal(t, "y\n")
	out, stderr := mustRun(t, "invites", "revoke", "x@example.com", "--data", dir)
	if !strings.Contains(out, "revoked 2 invites") {
		t.Errorf("revoke:\n%s", out)
	}
	a := parseAuditLine(t, stderr)
	if a.Audit.Action != "invites.revoke" || a.Audit.Result != "ok" || a.Audit.Actor != "tester (uid 1000)" {
		t.Errorf("revoke audit line %+v", a)
	}
	if c := signupChallenge(t, dir, "x@example.com", x1); c != 401 {
		t.Errorf("a revoked code: %d", c)
	}

	// --yes without a terminal, by invite ID, with JSON.
	stubTerminal(t, "")
	out, stderr = mustRun(t, "invites", "revoke", hostileID[:8], "--yes", "--json", "--data", dir)
	assertTerminalSafe(t, "revoke --json", out+stderr)
	var rv struct {
		Revoked []struct {
			Invite string `json:"invite"`
			State  string `json:"state"`
		} `json:"revoked"`
		Audit int64 `json:"audit_id"`
	}
	if err := json.Unmarshal([]byte(out), &rv); err != nil || len(rv.Revoked) != 1 || rv.Revoked[0].Invite != hostileID ||
		rv.Revoked[0].State != "expired" || rv.Audit != parseAuditLine(t, stderr).Audit.ID {
		t.Errorf("revoke --json: %s, %v", out, err)
	}
	err = run([]string{"invites", "revoke", "x@example.com", "--yes", "--data", dir}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no pending invite") {
		t.Errorf("revoking again: %v", err)
	}

	// reissue: the old code stops working, the new one works, and the
	// code appears on stdout only.
	before = dump(t, dir)
	out, _ = mustRun(t, "invites", "reissue", "y@example.com", "--dry-run", "--json", "--data", dir)
	if !strings.Contains(out, `"dry_run": true`) || dump(t, dir) != before {
		t.Errorf("reissue --dry-run --json changed something or said %s", out)
	}
	out, stderr = mustRun(t, "invites", "reissue", "y@example.com", "--ttl", "2d", "--yes", "--json", "--data", dir)
	var re struct {
		Revoked []struct {
			Invite string `json:"invite"`
		} `json:"revoked"`
		Invite struct {
			Invite string `json:"invite"`
			Code   string `json:"code"`
			State  string `json:"state"`
		} `json:"invite"`
	}
	if err := json.Unmarshal([]byte(out), &re); err != nil || len(re.Revoked) != 1 || re.Invite.Code == "" || re.Invite.State != "pending" {
		t.Fatalf("reissue --json: %s, %v", out, err)
	}
	if strings.Contains(stderr, re.Invite.Code) {
		t.Error("the new code is in the audit line")
	}
	if a := parseAuditLine(t, stderr); a.Audit.Action != "invites.reissue" || !strings.Contains(string(a.Audit.Params), re.Invite.Invite) {
		t.Errorf("reissue audit line %+v", a)
	}
	if c := signupChallenge(t, dir, "y@example.com", y); c != 401 {
		t.Errorf("the reissued invite's old code: %d", c)
	}
	if c := signupChallenge(t, dir, "y@example.com", re.Invite.Code); c != 200 {
		t.Errorf("the new code: %d", c)
	}
	out, _ = mustRun(t, "invites", "reissue", "z@example.com", "--yes", "--data", dir)
	if !strings.Contains(out, "new invite") || strings.Contains(out, "revoked") {
		t.Errorf("reissue with nothing pending:\n%s", out)
	}

	// audit lists every change, human and JSON, and filters by time.
	out, _ = mustRun(t, "audit", "--data", dir)
	assertTerminalSafe(t, "audit", out)
	for _, want := range []string{"invites.create", "invites.revoke", "invites.reissue", "tester (uid 1000)"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit lacks %q:\n%s", want, out)
		}
	}
	out, _ = mustRun(t, "audit", "--json", "--data", dir)
	var log struct {
		Audit []struct {
			Action string          `json:"action"`
			Params json.RawMessage `json:"params"`
		} `json:"audit"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil || len(log.Audit) != 8 {
		t.Errorf("audit --json: %d rows, %v\n%s", len(log.Audit), err, out)
	}
	for _, code := range []string{x1, y, re.Invite.Code} {
		if strings.Contains(out, code) {
			t.Error("the audit trail holds an invite code")
		}
	}
	out, _ = mustRun(t, "audit", "--since", time.Now().Add(time.Hour).Format(time.RFC3339), "--data", dir)
	if strings.TrimSpace(out) != "no audit entries" {
		t.Errorf("audit --since the future:\n%s", out)
	}
	if out, _ = mustRun(t, "audit", "--since", "1d", "--data", dir); !strings.Contains(out, "invites.revoke") {
		t.Errorf("audit --since 1d:\n%s", out)
	}
}

func signupChallenge(t *testing.T, dir, addr, code string) int {
	t.Helper()
	st, err := server.OpenSQLite(filepath.Join(dir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv, err := server.New(context.Background(), server.Config{Origin: testOrigin, Store: st})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	return post(t, srv.Handler(), "/v1/signup/challenge", map[string]string{"email": addr, "registration_code": code}, nil)
}

// quota writes its audit row against the account, and audit --account
// selects it by ID or email.
func TestQuotaAndAuditByAccount(t *testing.T) {
	dir := t.TempDir()
	stubTerminal(t, "")
	acct, _ := signup(t, dir, "alice@example.com", "laptop")
	signup(t, dir, "bob@example.com", "laptop")
	_, stderr := mustRun(t, "quota", "alice@example.com", "1GiB", "--data", dir)
	if a := parseAuditLine(t, stderr); a.Audit.Action != "accounts.quota" || a.Audit.AccountID == nil || *a.Audit.AccountID != acct {
		t.Errorf("quota audit line %q", stderr)
	}
	mustRun(t, "quota", "bob@example.com", "2GiB", "--data", dir)
	var failed bytes.Buffer
	if err := run([]string{"quota", "nobody@example.com", "1GiB", "--data", dir}, io.Discard, &failed); err == nil {
		t.Error("quota for an unknown account")
	}
	if a := parseAuditLine(t, failed.String()); a.Audit.Result != "not_found" {
		t.Errorf("the failed quota's audit line %q", failed.String())
	}
	for _, who := range []string{"alice@example.com", acct.String()} {
		out, _ := mustRun(t, "audit", "--account", who, "--data", dir)
		if strings.Count(out, "accounts.quota") != 1 || !strings.Contains(out, acct.String()) {
			t.Errorf("audit --account %s:\n%s", who, out)
		}
	}
	if err := run([]string{"audit", "--account", "nobody@example.com", "--data", dir}, io.Discard, io.Discard); err == nil {
		t.Error("audit for an unknown email")
	}
	if err := run([]string{"audit", "--since", "yesterday", "--data", dir}, io.Discard, io.Discard); err == nil {
		t.Error("audit --since yesterday")
	}
}
