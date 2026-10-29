package cli

import (
	"context"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/redact"
	"github.com/dalyem/hopkey/internal/resolve"
)

// A hidden name is masked where it stands as a whole host token: next to
// ':', brackets, spaces or a sentence's last '.', but not inside a longer
// name or address, of an allowed host or any other.
func TestMaskerHidesWholeHostTokens(t *testing.T) {
	l := &daemon.ListResult{Hosts: []model.Host{
		{Header: model.Header{ItemID: model.ID{1}}, Name: "db", AgentAccess: "deny", Addresses: []string{"10.0.0.1"}},
		{Header: model.Header{ItemID: model.ID{2}}, Name: "web", AgentAccess: "allow", Aliases: []string{"db.prod.example"}, Addresses: []string{"10.0.0.10"}},
	}}
	m := (&mcpServer{}).masker(l)
	for in, want := range map[string]string{
		"ssh: connect to host db.prod.example port 22": "ssh: connect to host db.prod.example port 22",
		"db:5432 refused":                                "<hidden host>:5432 refused",
		"through the jump host db.":                      "through the jump host <hidden host>.",
		"DB, then db-2 and x.db":                         "<hidden host>, then db-2 and x.db",
		"10.0.0.1:22 and 10.0.0.10:22":                   "<hidden host>:22 and 10.0.0.10:22",
		"[10.0.0.1]:22 is 10.0.0.1.":                     "[<hidden host>]:22 is <hidden host>.",
		"connect to host 10.0.0.1 port 22: refused (db)": "connect to host <hidden host> port 22: refused (<hidden host>)",
	} {
		if got := m.hide(in); got != want {
			t.Errorf("hide(%q) = %q, want %q", in, got, want)
		}
	}
}

// Private key blocks are found before secrets are replaced and names
// hidden: a secret "-" or a hidden host named PRIVATE would otherwise break
// the BEGIN and END lines, and the body would pass.
func TestRedactFindsKeysFirst(t *testing.T) {
	const key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBkZXBsb3kta2V5LWJvZHktZm9yLXRoZS10ZXN0AAAAAAAAAA==\n-----END OPENSSH PRIVATE KEY-----\n"
	const body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ"
	cut := key[len("-----BEGIN OPENSSH PRIVATE KEY-----\n"):] // the tail lost the BEGIN line
	l := &daemon.ListResult{Hosts: []model.Host{{Header: model.Header{ItemID: model.ID{1}}, Name: "PRIVATE", AgentAccess: "deny"}}}
	for _, secrets := range [][]string{{"-"}, {"KEY", "BEGIN", "-----"}, {"OPENSSH PRIVATE"}} {
		s := &mcpServer{secrets: secrets}
		m := s.masker(l)
		for _, text := range []string{key, "out: " + key + "more", cut, cut + key} {
			for name, got := range map[string]string{"redact": s.redact(text), "hide": m.hide(text), "audit": s.auditText(text)} {
				if strings.Contains(got, body) {
					t.Errorf("%s with secrets %q kept the key body: %q", name, secrets, got)
				}
			}
		}
	}
}

// Secrets and key blocks are found over the whole message before text the
// agent typed is set apart from hop's: a secret with a target the agent
// typed inside it, a secret across a typed span's edge, and one that runs
// over a key block's edge each go whole, and nothing of a hidden name or
// a key body is left.
func TestHideRedactsWholeSecretsAcrossTypedTextAndKeyBlocks(t *testing.T) {
	const key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----\n"
	const body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ"
	l := &daemon.ListResult{Hosts: []model.Host{
		{Header: model.Header{ItemID: model.ID{1}}, Name: "vault-secret", AgentAccess: "deny"},
		{Header: model.Header{ItemID: model.ID{2}}, Name: "web-1", AgentAccess: "allow"},
	}}
	for _, c := range []struct {
		secret string
		text   string
		gone   []string
	}{
		// The review's case: the target, web-1, inside a secret.
		{`vault-secret"web-1"PASSWORD`, "ssh said vault-secret" + typedQ("web-1") + "PASSWORD, then no host matches " + typedQ("web-1"), []string{"PASSWORD", "vault-secret"}},
		{`vault-secret"web-1"PASSWORD`, `ssh said vault-secret"web-1"PASSWORD`, []string{"PASSWORD", "vault-secret"}},
		{`"web-1" PASS`, "no host matches " + typedQ("web-1") + " PASS", []string{"PASS"}},
		// Over a key block's start and its end.
		{"tail-PASSWORD-----BEGIN OPENSSH", "out: tail-PASSWORD" + key + "more", []string{"tail-PASSWORD", body}},
		{"KEY-----\nafter-SECRET", "out: " + key[:len(key)-1] + "\nafter-SECRET more", []string{"after-SECRET", body}},
		{"KEY-----\nafter-SECRET", "out: " + key[len("-----BEGIN OPENSSH PRIVATE KEY-----\n"):len(key)-1] + "\nafter-SECRET more", []string{"after-SECRET", body}},
	} {
		s := &mcpServer{secrets: []string{c.secret}}
		m := s.masker(l)
		got := m.hide(c.text)
		for _, g := range c.gone {
			if strings.Contains(got, g) {
				t.Errorf("secret %q: hide(%q) = %q, which keeps %q", c.secret, c.text, got, g)
			}
		}
		if strings.ContainsAny(got, markOpen+markClose) || !strings.Contains(got, redacted) {
			t.Errorf("secret %q: hide(%q) = %q", c.secret, c.text, got)
		}
		for name, got := range map[string]string{"redact": s.redact(c.text), "audit": s.auditText(c.text)} {
			for _, g := range c.gone[:1] {
				if strings.Contains(got, g) {
					t.Errorf("secret %q: %s(%q) = %q, which keeps %q", c.secret, name, c.text, got, g)
				}
			}
		}
	}
	// What the agent typed is kept and the hidden name in hop's text is
	// not; a redaction marker is never masked, nor broken up by a secret.
	s := &mcpServer{secrets: []string{"by"}}
	l.Hosts = append(l.Hosts, model.Host{Header: model.Header{ItemID: model.ID{3}}, Name: "PRIVATE", AgentAccess: "deny"})
	got := s.masker(l).hide("no host matches " + typedQ("vault-secret") + "; vault-secret said " + key)
	if want := `no host matches "vault-secret"; <hidden host> said ` + keyRedacted + "\n"; got != want {
		t.Errorf("hide = %q, want %q", got, want)
	}
}

// A secret is redacted whole where it overlaps itself, and where it holds
// a mark rune, which redact and hide take out of the text before looking.
func TestRedactOverlappingAndMarkedSecrets(t *testing.T) {
	for _, c := range []struct {
		secret, text, want string
	}{
		{"ababa", "out: abababa", "out: " + redacted},
		{"ababa", "ababababa", redacted},
		{"left" + markOpen + "right", "pw leftright end", "pw " + redacted + " end"},
		{"left" + markClose + "right", "pw left" + markClose + "right end", "pw " + redacted + " end"},
	} {
		s := &mcpServer{secrets: []string{c.secret}}
		if got := s.redact(c.text); got != c.want {
			t.Errorf("secret %q: redact(%q) = %q, want %q", c.secret, c.text, got, c.want)
		}
		if got := s.masker(&daemon.ListResult{}).hide(c.text); got != c.want {
			t.Errorf("secret %q: hide(%q) = %q, want %q", c.secret, c.text, got, c.want)
		}
	}
}

// Text the agent typed is marked where hop echoes it, and nowhere else:
// in a message about a target, a user or a tag, in what the resolver says
// matched, and where ssh names the user on its own login to the target,
// but not on a jump host's.
func TestTypedTextIsMarkedWhereItIsEchoed(t *testing.T) {
	m := typedSpans
	kinds := func(text string) string {
		var b strings.Builder
		for _, sp := range m(text) {
			if sp.kind == typedText {
				b.WriteString("[" + sp.text + "]")
			} else {
				b.WriteString(sp.text)
			}
		}
		return b.String()
	}
	hosts := []model.Host{{Header: model.Header{ItemID: model.ID{1}}, Name: "web-1", Addresses: []string{"192.0.2.1"}}}
	for target, want := range map[string]string{
		"web-1":     `alias or name ["web-1"]`,
		"192.0.2.1": `stored address ["192.0.2.1"]`,
	} {
		res, err := resolve.Resolve(context.Background(), resolve.Input{Target: target, Hosts: hosts})
		if err != nil {
			t.Fatal(err)
		}
		if got := kinds(markMatched(res)); got != want {
			t.Errorf("markMatched for %s = %q, want %q", target, got, want)
		}
	}
	res := &resolve.Result{Target: "x:22", Status: resolve.StatusNoMatch}
	if got := kinds(describeUnresolvedAs(res, typedQ)); got != `no host matches ["x:22"]` {
		t.Errorf("describeUnresolvedAs = %q", got)
	}
	rr := &daemon.ResolveResult{Result: &resolve.Result{Status: resolve.StatusMatched, User: "x:"}, Host: &hosts[0], SSHAlias: "hop-web-1",
		Route: &resolve.Route{Address: "192.0.2.1"}}
	if _, err := connectableAs(rr, typedQ); err == nil || kinds(err.Error()) != `user ["x:"] is not usable in an ssh config` {
		t.Errorf("connectableAs = %v", err)
	}
	stderr := "vault-secret@192.0.2.1: Permission denied (publickey).\nvault-secret@192.0.2.9: Permission denied (publickey).\n" + markOpen + "x" + markClose
	if got := kinds(markSSHUser(&target{user: "vault-secret"}, "192.0.2.1", stderr)); got != "[vault-secret]@192.0.2.1: Permission denied (publickey).\nvault-secret@192.0.2.9: Permission denied (publickey).\nx" {
		t.Errorf("markSSHUser = %q", got)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A tool that panics is a tool error, and the panic's value reaches hop
// mcp's stderr redacted and escaped, as an audit log line is.
func TestMCPPanicOnStderrIsRedacted(t *testing.T) {
	const secret = "correct-horse-battery-staple"
	stderr := &syncBuffer{}
	s := &mcpServer{e: &Env{Stderr: stderr}, secrets: []string{secret}}
	srv := mcp.NewServer(&mcp.Implementation{Name: "hop"}, nil)
	addMCPTool(s, srv, &mcp.Tool{Name: "boom"}, func(context.Context, *mcp.CallToolRequest, struct{}) (struct{}, error) {
		panic("it was " + secret + "\x1b[31m")
	})
	ctx := context.Background()
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	ss, err := srv.Connect(ctx, &mcp.IOTransport{Reader: sr, Writer: sw}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, &mcp.IOTransport{Reader: cr, Writer: cw}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "boom", Arguments: map[string]any{}})
	if err != nil || !res.IsError {
		t.Fatalf("boom = %+v, %v", res, err)
	}
	got := stderr.String()
	if strings.Contains(got, secret) || strings.Contains(got, "\x1b") || !strings.Contains(got, "boom panicked: it was [redacted by hop]\\x1b[31m") {
		t.Errorf("stderr = %q", got)
	}
}

// The daemon's hits, the patterns' and hop's own secrets are found in one
// text and replaced in one pass: overlapping ones go as one stretch, named
// for the kind that ranks first, and a hit counts on the text with the
// typed-text marks out, so a secret that runs into a typed echo goes whole
// and the typed text beside one is still not masked.
func TestRedactSpansOnePass(t *testing.T) {
	vault := func(text, v string) []redact.Hit {
		return redact.Literals(text, []redact.Secret{{Kind: redact.KindVaultPassword, Value: v}})
	}
	m := masker{names: []string{"db"}, own: hopMatcher([]string{"2y z"})}
	for _, c := range []struct {
		name, text, want string
		counts           map[string]int
	}{
		// The pattern's value runs past the vault password at both ends,
		// and hop's own secret past the pattern's end.
		{"overlap", "API_KEY=xhunter2y zz", "API_KEY=[redacted by hop: vault-password]z", map[string]int{redact.KindVaultPassword: 1}},
		// A vault password right after a typed echo of a denied name: the
		// echo stays as typed, the name in hop's text is hidden.
		{"beside a mark", typed("db") + "pw:hunter2 db", "dbpw:[redacted by hop: vault-password] <hidden host>", map[string]int{redact.KindVaultPassword: 1}},
		// A vault password that starts inside the typed echo.
		{"across a mark", "x " + typed("hun") + "ter2 y", "x [redacted by hop: vault-password] y", map[string]int{redact.KindVaultPassword: 1}},
		// A token beside a key block: each is its own marker.
		{"token and key", "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8 -----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
			"[redacted by hop: github-token] " + keyRedacted, map[string]int{redact.KindGitHubToken: 1, redact.KindPrivateKey: 1}},
	} {
		ss := typedSpans(c.text)
		joined := joinSpans(ss)
		more := append(vault(joined, "hunter2"), redact.Patterns(joined)...)
		out := redactSpans(ss, m.own, more)
		if got := m.hideSpans(out); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		counts := map[string]int{}
		countMarkers(counts, out)
		if !maps.Equal(counts, c.counts) {
			t.Errorf("%s: counts %v, want %v", c.name, counts, c.counts)
		}
	}
	// A hit past the end of the text, from a confused caller, is cut to it.
	if got := joinSpans(redactSpans([]span{{text: "abc"}}, redact.Matcher{}, []redact.Hit{{Lo: 1, Hi: 99, Kind: redact.KindVaultPassword}})); got != "a[redacted by hop: vault-password]" {
		t.Errorf("clamped hit: %q", got)
	}
}

// Overlapping stretches of kinds that rank the same are named for the
// kind that sorts first, whatever order they were found in, so the same
// output is always attributed the same way.
func TestRedactSpansBreaksRankTiesByKind(t *testing.T) {
	text := "AKIA0123456789ABCDEF"
	a := redact.Hit{Lo: 0, Hi: len(text), Kind: redact.KindGitHubToken}
	b := redact.Hit{Lo: 0, Hi: len(text), Kind: redact.KindAWSAccessKeyID}
	if redact.Rank(a.Kind) != redact.Rank(b.Kind) {
		t.Fatal("the kinds do not rank the same")
	}
	for _, hits := range [][]redact.Hit{{a, b}, {b, a}} {
		out := redactSpans([]span{{text: text}}, redact.Matcher{}, hits)
		if len(out) != 1 || out[0].what != redact.KindAWSAccessKeyID {
			t.Errorf("hits %v: %+v, want one %s marker", hits, out, redact.KindAWSAccessKeyID)
		}
	}
}

// capSpans keeps the last n bytes, moving its cut past a marker, a hidden
// host's placeholder or a character it would split.
func TestCapSpansCutsOnlyBetweenWholes(t *testing.T) {
	mk := span{text: "[redacted by hop: x]", kind: markerText, what: "x"}
	ss := []span{{text: "aé"}, mk, {text: "éé"}} // 3 + 20 + 4 bytes
	for _, c := range []struct {
		n    int
		want string
		cut  bool
	}{
		{27, "aé[redacted by hop: x]éé", false},
		{24, "[redacted by hop: x]éé", true}, // the cut falls on the marker's start
		{25, "[redacted by hop: x]éé", true}, // inside the é before it
		{5, "éé", true},                      // inside the marker
		{3, "é", true},                       // inside the first é of the last two
	} {
		got, cut := capSpans(ss, c.n)
		if s := joinSpans(got); s != c.want || cut != c.cut || len(s) > c.n || !utf8.ValidString(s) {
			t.Errorf("n %d: %q cut %v, want %q cut %v", c.n, s, cut, c.want, c.cut)
		}
	}
	got, _ := capSpans([]span{{text: "x " + hiddenHost + " y"}}, 8)
	if s := joinSpans(got); s != " y" {
		t.Errorf("hidden host: %q, want the text after it", s)
	}
	counts := map[string]int{}
	got, _ = capSpans(ss, 5)
	if countMarkers(counts, got); len(counts) != 0 {
		t.Errorf("a marker cut off is counted: %v", counts)
	}
}

// capFront cuts as capSpans does, and where the cut falls inside a line
// of plain text, drops the rest of that line, unless nothing follows it.
// A cut at a line's start, or past a marker, is kept as it is.
func TestCapFrontDropsTheLineItCutsInto(t *testing.T) {
	mk := span{text: "[redacted by hop: x]", kind: markerText, what: "x"}
	for _, c := range []struct {
		ss   []span
		n    int
		want string
	}{
		// The cut after "ab", after "abc" (the line's newline goes too),
		// and at a line's start.
		{[]span{{text: "abc\ndef\nghi"}}, 9, "def\nghi"},
		{[]span{{text: "abc\ndef\nghi"}}, 8, "def\nghi"},
		{[]span{{text: "abc\ndef\nghi"}}, 7, "def\nghi"},
		// Nothing after the newline.
		{[]span{{text: "abcdef\n"}}, 4, "def\n"},
		// Between two spans of plain text, and past a marker.
		{[]span{{text: "abc"}, {text: "def\ng", kind: typedText}}, 5, "g"},
		{[]span{{text: "ab"}, mk, {text: "cd\nef"}}, 6, "cd\nef"},
	} {
		got, cut := capFront(c.ss, c.n)
		if s := joinSpans(got); s != c.want || !cut {
			t.Errorf("%q, n %d: %q cut %v, want %q", joinSpans(c.ss), c.n, s, cut, c.want)
		}
	}
}

// A disconnect's message, quoted by x/crypto, stands as it is quoted in
// a span of its own, and as the server sent it beside, with where each of
// its bytes was written; one that does not unquote is withheld with the
// rest of its text.
func TestQuotedMsgs(t *testing.T) {
	msg := "ab\"cd\\ef\x00\u00e9!"
	q := strconv.Quote(msg) // "ab\"cd\\ef\x00é!"
	text := "ssh: handshake failed: ssh: disconnect, reason 2: " + q + " (more)"
	ss, msgs := quotedMsgs(text)
	if got := joinSpans(ss); got != text {
		t.Errorf("joined: %q", got)
	}
	if !slices.ContainsFunc(ss, func(sp span) bool { return sp.kind == quotedText && sp.text == q[1:len(q)-1] }) {
		t.Errorf("no span of the server's text as quoted: %+v", ss)
	}
	if len(msgs) != 1 || msgs[0].raw != msg {
		t.Fatalf("messages: %+v", msgs)
	}
	m := msgs[0]
	if text[m.lo:m.hi] != q[1:len(q)-1] {
		t.Errorf("bounds: %q", text[m.lo:m.hi])
	}
	// raw[2:6] stands as \"cd\; \x00 writes one byte; é writes its own two.
	for _, c := range []struct {
		lo, hi int
		want   string
	}{{2, 6, `\"cd\\`}, {8, 9, `\x00`}, {9, 11, "é"}, {9, 10, "\xc3"}} {
		h := m.mapHits([]redact.Hit{{Lo: c.lo, Hi: c.hi, Kind: "k"}})[0]
		if got := text[h.Lo:h.Hi]; got != c.want {
			t.Errorf("raw %d-%d: %q, want %q", c.lo, c.hi, got, c.want)
		}
	}
	for _, bad := range []string{`"unterminated \"`, `'x' and more`, "no quote"} {
		ss, msgs := quotedMsgs("x: ssh: disconnect, reason 2: " + bad)
		if got, want := joinSpans(ss), "x: ssh: disconnect, reason 2: (withheld: hop could not read the server's message)"; got != want || len(msgs) != 0 {
			t.Errorf("%q: %q, want %q", bad, got, want)
		}
	}
	if ss, _ := quotedMsgs("ssh: disconnect, reason x"); joinSpans(ss) != "ssh: disconnect, reason x" {
		t.Errorf("not the format: %q", joinSpans(ss))
	}
}

// A secret found in a message as the server sent it that begins or ends
// inside the bytes one escape writes cannot be put back exactly where it
// stands quoted: the whole message goes.
func TestQuotedMsgWithholdsAnInexactHit(t *testing.T) {
	text := `ssh: disconnect, reason 2: "a\u00e9b"`
	_, msgs := quotedMsgs(text)
	if len(msgs) != 1 || msgs[0].raw != "aéb" {
		t.Fatalf("messages: %+v", msgs)
	}
	for _, h := range []redact.Hit{{Lo: 0, Hi: 2}, {Lo: 2, Hi: 4}} { // "a\xc3", "\xa9b"
		got := msgs[0].mapHits([]redact.Hit{h})[0]
		if text[got.Lo:got.Hi] != `a\u00e9b` {
			t.Errorf("raw %d-%d: %q, want the whole message", h.Lo, h.Hi, text[got.Lo:got.Hi])
		}
	}
}

// The cut in quoted text moves past an escape it would split.
func TestCapSpansKeepsWholeEscapes(t *testing.T) {
	q := `\\` + strings.Repeat(`\x00`, 10)
	for n := 1; n <= len(q); n++ {
		got, _ := capSpans([]span{{text: q, kind: quotedText}}, n)
		s := joinSpans(got)
		if len(s) > n || s != q && s != "" && (!strings.HasPrefix(s, `\x00`) || len(s)%4 != 0) {
			t.Errorf("%d: %q", n, s)
		}
	}
}

// rescan looks again only at a stretch formatting wrote in, and leaves
// the markers hop put in whole, though its secrets stand in them. A
// denied name that a marker it puts in leaves standing on its own is
// hidden after it. (A daemon with no secrets, longest 0, is not asked.)
func TestRescanLooksOnlyAtWhatFormattingWrote(t *testing.T) {
	l := &daemon.ListResult{Hosts: []model.Host{
		{Header: model.Header{ItemID: model.ID{1}}, Name: "db", AgentAccess: "deny"},
	}}
	s := &mcpServer{secrets: []string{"h", "q?x"}}
	m := s.masker(l)
	mk := span{text: "[redacted by hop: x]", kind: markerText, what: "x"}
	in := []span{{text: "db:22 q"}, {text: "?", fresh: true}, {text: "xdb"}, mk, {text: "q?x"}}
	got, err := s.rescan(context.Background(), [][]span{in}, m.own, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	// The last "q?x" stood as it is when it was first scanned, so it is
	// not looked at again.
	want := hiddenHost + ":22 [redacted by hop]" + hiddenHost + "[redacted by hop: x]q?x"
	if s := m.hideSpans(got[0]); s != want {
		t.Errorf("got %q, want %q", s, want)
	}
}

// What rescan does not send the daemon, the fresh text far from the last
// limit bytes and the bytes around it, is early: capSpans keeps none of
// it, however short what is left.
func TestRescanMakesWhatItDidNotCheckEarly(t *testing.T) {
	s := &mcpServer{}
	text := "a" + strings.Repeat("b", 100)
	in := []span{{text: "a"}, {text: "?", fresh: true}, {text: strings.Repeat("b", 100)}}
	got, err := s.rescan(context.Background(), [][]span{in}, redact.Matcher{}, 5, 10, false)
	if err != nil {
		t.Fatal(err) // the daemon was asked: there is none here
	}
	// The daemon would be asked about the bytes from 87 on (102-10-5),
	// and a secret that begins before them ends by 92: the text before 92
	// is early. The one fresh byte is far before, so it is not asked.
	if kept, cut := capSpans(got[0], 10); joinSpans(kept) != text[len(text)-10:] || !cut {
		t.Errorf("limit 10: %q cut %v", joinSpans(kept), cut)
	}
	if kept, cut := capSpans(got[0], 50); joinSpans(kept) != text[len(text)-10:] || !cut {
		t.Errorf("limit 50: %q cut %v, want the 10 bytes after the early text", joinSpans(kept), cut)
	}
}

// A formatter's fresh text is a span of its own; what it leaves as it
// was stays in spans with the kind it had, and the markers stay whole.
func TestRewriteMarksWhatItWrites(t *testing.T) {
	mk := span{text: "[redacted by hop]", kind: markerText, what: redact.KindHopSecret}
	got := validSpans([]span{{text: "a\xffb"}, mk, {text: "é\xfe", kind: typedText}})
	want := []span{{text: "a"}, {text: "\uFFFD", fresh: true}, {text: "b"}, mk, {text: "é", kind: typedText}, {text: "\uFFFD", kind: typedText, fresh: true}}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got := lastLinesSpans([]span{{text: " x\ny\nz \n"}}, 2); !slices.Equal(got, []span{{text: "y"}, {text: "; ", fresh: true}, {text: "z"}}) {
		t.Errorf("lastLinesSpans: %+v", got)
	}
	if in := []span{{text: "ok"}}; !slices.Equal(validSpans(in), in) {
		t.Errorf("valid text changed: %+v", validSpans(in))
	}
}

// applyHits goes over the spans once: many hits in many spans take no
// longer than the spans and hits do.
func TestApplyHitsManySpans(t *testing.T) {
	var ss []span
	var hits []redact.Hit
	for i := range 50000 {
		ss = append(ss, span{text: "ab"}, span{text: "?", fresh: true})
		hits = append(hits, redact.Hit{Lo: 3*i + 1, Hi: 3*i + 3, Kind: redact.KindHopSecret})
	}
	out := applyHits(ss, hits)
	if got := joinSpans(out); got != strings.Repeat("a[redacted by hop]", 50000) {
		t.Errorf("%.60q...", got)
	}
}
