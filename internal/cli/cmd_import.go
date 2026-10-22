package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/sshconfig"
	"github.com/dalyem/hopkey/internal/sshkeys"
)

// ImportEntry is one line of the --json report of hop import ssh-config.
type ImportEntry struct {
	Kind   string `json:"kind"` // host or key
	Name   string `json:"name"`
	Status string `json:"status"` // imported, exists, skipped, failed (or would_import with --dry-run)
	Reason string `json:"reason,omitempty"`
}

// ImportReport is the --json shape of hop import ssh-config.
type ImportReport struct {
	Source   string        `json:"source"`
	DryRun   bool          `json:"dry_run"`
	Entries  []ImportEntry `json:"entries"`
	Warnings []string      `json:"warnings,omitempty"`
}

func runImport(ctx context.Context, e *Env, args []string) error {
	if len(args) == 0 || args[0] != "ssh-config" {
		fmt.Fprintf(e.Stderr, "usage: %s\n", commands["import"].usage)
		return failf("import needs a source: ssh-config")
	}
	fs := newFlags(e, "import ssh-config", commands["import"].usage)
	usage := fs.Usage
	fs.Usage = func() {
		usage()
		fmt.Fprint(e.Stderr, "\nThe import reads the config with ssh -G, as connecting does: that runs any `Match exec` commands in it and may do DNS lookups.\n"+
			"hop lists what its scan found (best effort) and asks first; importing your config carries the same trust as using it.\n")
	}
	withKeys := fs.Bool("with-keys", false, "import the private keys named by IdentityFile (default: only record the reference)")
	dryRun := fs.Bool("dry-run", false, "show what would be imported")
	yes := fs.Bool("yes", false, "agree to read the config with ssh -G without asking (needed when stdin is not a terminal or with --json)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	pos, _, err := parseFlags(fs, args[1:])
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		fs.Usage()
		return failf("expected at most one path")
	}
	// OpenSSH finds ~ in the passwd database, whatever $HOME says. The scan,
	// the default config path and the ssh -G child all use that home, so that
	// hop reads the files ssh reads.
	home, err := e.passwdHome()
	if err != nil {
		return failf("import ssh-config needs your home directory, as OpenSSH finds it (the passwd database): %v", err)
	}
	var warnings []string
	if home != e.Home {
		warnings = append(warnings, fmt.Sprintf("your home directory is %s in the passwd database but %s in $HOME; OpenSSH expands ~ from the passwd entry, so hop reads %s", home, e.Home, home))
	}
	path := filepath.Join(home, ".ssh", "config")
	if len(pos) == 1 {
		path = pos[0]
	}

	sshBin, err := checkSSH(e)
	if err != nil {
		return err
	}
	scan := newConfigScan(home, e.Paths.ConfigDir)
	if err := scan.scan(path); err != nil {
		return failf("%v", err)
	}
	// ssh -G reads the config as a connection would: it runs the commands of
	// `Match exec` lines and may resolve names for canonicalization. The scan
	// above is a best-effort list of what that could involve, not a boundary:
	// the user's consent is the gate.
	if !*asJSON {
		fmt.Fprint(e.Stderr, consentNotice(path, scan))
	}
	if !*yes {
		switch {
		case *asJSON:
			return failf("import ssh-config reads %s with ssh -G, which runs any `Match exec` commands in it; confirmation needed but --json cannot ask; pass --yes", printable(path))
		case !e.StdinTTY:
			return failf("import ssh-config reads %s with ssh -G, which runs any `Match exec` commands in it; confirmation needed but stdin is not a terminal; pass --yes", printable(path))
		}
		ok, err := confirm(e, false, "Read this config with ssh -G?")
		if err != nil {
			return err
		}
		if !ok {
			return failf("not confirmed; nothing was read or imported")
		}
	}
	scanWarns := scanWarnings(scan)
	prober := &sshProber{env: e, bin: sshBin, home: home}
	if err := prober.verifyTrace(ctx); err != nil {
		if isTraceError(err) {
			return failf("%v", err)
		}
		return failf("ssh -G: %v", err)
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	imp := &importer{ctx: ctx, e: e, scan: scan, prober: prober, home: home, config: path, l: l, withKeys: *withKeys, dryRun: *dryRun,
		report: ImportReport{Source: path, DryRun: *dryRun}}
	if err := imp.run(); err != nil {
		return failf("%v", err)
	}
	imp.report.Warnings = slices.Concat(warnings, scanWarns, imp.warnings)
	if *asJSON {
		return printJSON(e, imp.report)
	}
	for _, en := range imp.report.Entries {
		line := fmt.Sprintf("%-12s %s %s", en.Status, en.Kind, en.Name)
		if en.Reason != "" {
			line += ": " + en.Reason
		}
		e.printf("%s\n", line)
	}
	// The scan's findings were printed with the notice.
	for _, w := range slices.Concat(warnings, imp.warnings) {
		fmt.Fprintf(e.Stderr, "hop: warning: %s\n", w)
	}
	if !*dryRun && slices.ContainsFunc(imp.report.Entries, func(en ImportEntry) bool { return en.Kind == "host" && en.Status == "imported" }) {
		fmt.Fprintf(e.Stderr, "hop: imported hosts have no pinned host keys yet; pin each with: hop trust <host>\n")
	}
	return nil
}

// consentNotice says what reading the config with ssh -G involves and lists
// what hop's scan found. The scan is best effort, so an empty list is not a
// promise.
func consentNotice(path string, s *configScan) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "hop import ssh-config evaluates %s and the files it Includes with OpenSSH (ssh -G).\n", printable(path))
	sb.WriteString("That runs any `Match exec` commands in them as you, with your permissions, possibly several\n" +
		"times (once per host), even with --dry-run, and may do DNS lookups (CanonicalizeHostname).\n" +
		"Only continue if you trust this config, especially one you have not used with ssh yourself.\n")
	if len(s.matchExec) == 0 && len(s.unscanned) == 0 {
		sb.WriteString("hop's scan found no `Match exec` lines and no Include it could not inspect; hop's scan is best effort.\n")
		return sb.String()
	}
	sb.WriteString("What hop's scan found (best effort):\n")
	if len(s.matchExec) > 0 {
		sb.WriteString("  Match exec lines, which run these commands:\n")
		for _, m := range s.matchExec {
			fmt.Fprintf(&sb, "    %s: %s\n", printable(m.source), printable(m.text))
		}
	}
	if len(s.unscanned) > 0 {
		sb.WriteString("  Include patterns hop could not inspect (ssh may read them and run what they hold):\n")
		for _, u := range s.unscanned {
			fmt.Fprintf(&sb, "    %s\n", printable(u))
		}
		sb.WriteString("  Host names in the files those Includes name are not enumerated, so they are not imported.\n")
	}
	return sb.String()
}

// scanWarnings is the scan's findings as report warnings.
func scanWarnings(s *configScan) []string {
	var out []string
	for _, m := range s.matchExec {
		out = append(out, fmt.Sprintf("Match exec, run by ssh -G: %s: %s", printable(m.source), printable(m.text)))
	}
	for _, u := range s.unscanned {
		out = append(out, "Include hop could not inspect: "+printable(u))
	}
	if len(s.unscanned) > 0 {
		out = append(out, "Host names in the files those Includes name were not enumerated, so they are not imported (import them with their own path, or hop add)")
	}
	return out
}

// maxShown caps one line of config text echoed back to the user.
const maxShown = 200

// printable makes text from a config file safe to show: control characters,
// which could rewrite what the terminal displays, become '?', and a long line
// is cut.
func printable(s string) string {
	r := []rune(s)
	cut := len(r) > maxShown
	if cut {
		r = r[:maxShown]
	}
	for i, c := range r {
		// C0, DEL, C1 (which covers the ANSI CSI introducer), and Unicode
		// format characters such as bidi overrides, which reorder what the
		// prompt shows.
		if c < ' ' || c == 0x7f || (c >= 0x80 && c < 0xa0) || unicode.Is(unicode.Cf, c) {
			r[i] = '?'
		}
	}
	if cut {
		return string(r) + "..."
	}
	return string(r)
}

// candidate is a host the import is working out: one Host line's worth of
// aliases that ssh -G gave the same settings.
type candidate struct {
	host      model.Host
	source    string
	sig       string
	identity  []string // expanded IdentityFile paths ssh was told about
	jump      string   // ProxyJump, "" for none
	entry     int      // index in the report
	skipped   bool
	jumpTo    *model.Host // set by planJumps: the vault host, or the saved candidate
	jumpToCnd *candidate
	saved     *model.Host
}

type importer struct {
	ctx      context.Context
	e        *Env
	scan     *configScan
	prober   *sshProber
	home     string // the passwd home
	config   string
	l        *daemon.ListResult
	withKeys bool
	dryRun   bool
	report   ImportReport
	warnings []string
}

func (im *importer) add(kind, name, status, reason string) int {
	im.report.Entries = append(im.report.Entries, ImportEntry{Kind: kind, Name: name, Status: status, Reason: reason})
	return len(im.report.Entries) - 1
}

func (im *importer) warnf(format string, args ...any) {
	im.warnings = append(im.warnings, fmt.Sprintf(format, args...))
}

func (im *importer) imported() string {
	if im.dryRun {
		return "would_import"
	}
	return "imported"
}

func (im *importer) taken(name string) (string, bool) {
	for _, h := range im.l.Hosts {
		for _, n := range resolve.Names(h) {
			if strings.EqualFold(n, name) {
				return h.Name, true
			}
		}
	}
	return "", false
}

// skip leaves a host out and says why, in the report and as a warning.
func (im *importer) skip(entry int, name, source, reason string) {
	im.report.Entries[entry].Status, im.report.Entries[entry].Reason = "skipped", reason
	im.warnf("host %s (%s) was not imported: %s", name, source, reason)
}

// run imports every alias the config names, each with the settings ssh -G
// gives it. Whatever ssh would do with the name is what the vault host does:
// hop never evaluates the config itself. It fails, with nothing saved, when
// ssh's trace cannot be read: which Host blocks applied would be a guess.
func (im *importer) run() error {
	var cands []*candidate
	bySource := map[string][]*candidate{}
	for _, a := range im.scan.aliases {
		if owner, ok := im.taken(a.Name); ok {
			im.add("host", a.Name, "exists", fmt.Sprintf("already in the vault as %q", owner))
			continue
		}
		if !sshconfig.ValidAlias(a.Name) {
			im.skip(im.add("host", a.Name, "", ""), a.Name, a.Source,
				fmt.Sprintf("%q is not usable as a host name (letters, digits, '.', '_' and '-')", a.Name))
			continue
		}
		set, err := im.prober.run(im.ctx, im.config, a.Name, true)
		if err != nil {
			if isTraceError(err) {
				return err
			}
			im.skip(im.add("host", a.Name, "", ""), a.Name, a.Source, err.Error())
			continue
		}
		if why := set.traceProblem(); why != "" {
			return &errTraceUnverified{why}
		}
		// What this ssh prints for the name when no config says anything. A
		// value equal to it is a default, not something the config set.
		def, err := im.prober.defaults(im.ctx, a.Name)
		if err != nil {
			if isTraceError(err) {
				return err
			}
			im.skip(im.add("host", a.Name, "", ""), a.Name, a.Source, err.Error())
			continue
		}
		c, why := im.candidateFor(a, set, def)
		if why != "" {
			im.skip(im.add("host", a.Name, "", ""), a.Name, a.Source, why)
			continue
		}
		// Names from one Host line that ssh treats alike are one host.
		if i := slices.IndexFunc(bySource[a.Source], func(o *candidate) bool { return o.sig == c.sig }); i >= 0 {
			o := bySource[a.Source][i]
			o.host.Aliases = append(o.host.Aliases, a.Name)
			continue
		}
		c.entry = im.add("host", a.Name, "", "")
		cands = append(cands, c)
		bySource[a.Source] = append(bySource[a.Source], c)
	}
	im.planJumps(cands)
	im.save(cands)
	return nil
}

// candidateFor turns ssh -G's answer for one alias into a vault host, or says
// why importing it would not behave as ssh does. def is ssh's answer for the
// same name with an empty config.
//
// A User or IdentityFile equal to the default is not stored: ssh falls back to
// the same value without being told, and hop cannot tell the two apart. So an
// explicit value that happens to equal the default is not imported either;
// the host behaves the same, but the vault does not record that the config
// named it.
func (im *importer) candidateFor(a configAlias, set sshSettings, def sshSettings) (*candidate, string) {
	if !slices.ContainsFunc(set.Applied, func(l hostLoc) bool { return im.scan.declares(l.file, l.line, a.Name) }) {
		return nil, "no Host line applies to this name under ssh's rules (it is negated, or its file is only included where a Match does not hold)"
	}
	if pc := set.ProxyCommand; pc != "" && !strings.EqualFold(pc, "none") {
		return nil, fmt.Sprintf("ProxyCommand %q cannot be reproduced; importing it as a direct connection would change where ssh connects", pc)
	}
	addr := set.HostName
	if addr == "" {
		addr = a.Name
	}
	if !sshconfig.ValidHostName(addr) {
		return nil, fmt.Sprintf("HostName %q is not usable", addr)
	}
	port := uint32(22)
	if set.Port != "" {
		n, err := strconv.Atoi(set.Port)
		if err != nil || n <= 0 || n >= 65536 {
			return nil, fmt.Sprintf("Port %q is not usable", set.Port)
		}
		port = uint32(n)
	}
	user := set.User
	if user == def.User {
		user = "" // ssh's own default, not something the config says
	}
	if user != "" && !sshconfig.ValidUser(user) {
		return nil, fmt.Sprintf("User %q is not usable", user)
	}
	c := &candidate{source: a.Source, jump: set.ProxyJump}
	if strings.EqualFold(c.jump, "none") {
		c.jump = ""
	}
	for _, f := range set.IdentityFiles {
		if strings.EqualFold(f, "none") || slices.Contains(def.IdentityFiles, f) {
			continue
		}
		path, ok := im.identityPath(f, a.Name, addr, set.User, port)
		if !ok {
			im.warnf("host %s: IdentityFile %s uses a token hop does not expand; the key is not referenced", a.Name, f)
			continue
		}
		c.identity = append(c.identity, path)
	}
	if set.HostKeyAlias != "" {
		im.warnf("host %s: HostKeyAlias %s is not imported; hop pins host keys under the host's own name", a.Name, set.HostKeyAlias)
	}
	c.host = model.Host{
		Name: a.Name, Addresses: []string{addr}, Port: port, User: user,
		Route: resolve.RouteAuto, AgentAccess: "allow",
		Description: "Imported from " + a.Source,
	}
	c.sig = strings.Join([]string{addr, strconv.Itoa(int(port)), user, c.jump, strings.Join(c.identity, "\x00")}, "\x01")
	return c, ""
}

// identityPath expands the tokens ssh -G leaves in an IdentityFile value:
// ~, %d, %h, %n, %r, %p and %%. Any other token (%l, %u, %C ...) depends on
// something hop does not know, so ok is false.
func (im *importer) identityPath(raw, alias, host, remoteUser string, port uint32) (path string, ok bool) {
	var sb strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '%' {
			sb.WriteByte(raw[i])
			continue
		}
		i++
		if i == len(raw) {
			return "", false
		}
		switch raw[i] {
		case '%':
			sb.WriteByte('%')
		case 'd':
			sb.WriteString(im.home)
		case 'h':
			sb.WriteString(host)
		case 'n':
			sb.WriteString(alias)
		case 'r':
			sb.WriteString(remoteUser)
		case 'p':
			sb.WriteString(strconv.Itoa(int(port)))
		default:
			return "", false
		}
	}
	return normIdentity(im.home, sb.String()), true
}

// save writes the candidates that are still in, attaching their keys when
// asked. A host is written once, with its jump host already set, so no host is
// ever stored without the jump ssh goes through: each jump host is saved
// before the hosts that use it, and a host whose jump host was not saved is
// skipped.
func (im *importer) save(cands []*candidate) {
	const (
		fresh = iota
		busy
		done
	)
	state := map[*candidate]int{}
	var saveOne func(c *candidate)
	saveOne = func(c *candidate) {
		if state[c] != fresh {
			return
		}
		state[c] = busy
		defer func() { state[c] = done }()
		if c.skipped {
			return
		}
		if c.jump != "" {
			target := c.jumpTo
			if c.jumpToCnd != nil {
				saveOne(c.jumpToCnd)
				target = c.jumpToCnd.saved
			}
			if target == nil {
				c.skipped = true
				im.skip(c.entry, c.host.Name, c.source, fmt.Sprintf("its jump host %q was not saved, and without it %s would connect directly where ssh goes through the jump", c.jump, c.host.Name))
				return
			}
			c.host.JumpHostID = target.ItemID
		}
		im.attachKey(c)
		if im.dryRun {
			im.report.Entries[c.entry].Status = im.imported()
			h := c.host
			c.saved = &h
			return
		}
		var saved model.Host
		if err := call(im.ctx, im.e, daemon.OpPutHost, daemon.PutHostParams{Host: c.host}, &saved); err != nil {
			im.report.Entries[c.entry].Status, im.report.Entries[c.entry].Reason = "failed", err.Error()
			c.skipped = true
			return
		}
		im.report.Entries[c.entry].Status = im.imported()
		c.saved = &saved
		im.l.Hosts = append(im.l.Hosts, saved)
	}
	for _, c := range cands {
		saveOne(c)
	}
}

// attachKey imports the first usable key the host's IdentityFile lines name,
// or records the references in its description.
func (im *importer) attachKey(c *candidate) {
	if len(c.identity) == 0 {
		return
	}
	files := strings.Join(c.identity, ", ")
	if !im.withKeys {
		c.host.Description += "; ssh config IdentityFile: " + files + " (not imported; hop key add <path>, then hop edit " + c.host.Name + " --key <name>)"
		return
	}
	for _, f := range c.identity {
		id, note, err := im.importKey(f)
		if err != nil {
			im.warnf("host %s: IdentityFile %s: %v", c.host.Name, f, err)
			continue
		}
		c.host.KeyID = id
		if note != "" {
			c.host.Description += "; " + note
		}
		break
	}
	if c.host.KeyID.IsZero() {
		c.host.Description += "; ssh config IdentityFile: " + files + " (could not be imported)"
	}
}

// importKey makes sure the key in path is in the vault and returns its ID. A
// key already there (same public key) is reused.
func (im *importer) importKey(path string) (model.ID, string, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return model.ID{}, "", errors.New("the file does not exist")
		}
		return model.ID{}, "", err
	}
	pem, key, err := readPrivateKey(im.e, path)
	if err != nil {
		return model.ID{}, "", errors.New(strings.TrimPrefix(err.Error(), path+": "))
	}
	fp := sshkeys.Fingerprint(key.Public)
	for _, k := range im.l.Keys {
		if k.Fingerprint == fp {
			id, err := model.ParseID(k.ID)
			return id, "", err
		}
	}
	name := uniqueKeyName(im.l, filepath.Base(path))
	if im.dryRun {
		im.add("key", name, im.imported(), path)
		im.l.Keys = append(im.l.Keys, daemon.KeyInfo{Name: name, Fingerprint: fp})
		return model.ID{}, "", nil
	}
	var info daemon.KeyInfo
	if err := call(im.ctx, im.e, daemon.OpPutKey, daemon.PutKeyParams{Name: name, PrivateKey: pem}, &info); err != nil {
		im.add("key", name, "failed", err.Error())
		return model.ID{}, "", err
	}
	im.add("key", name, "imported", path)
	im.l.Keys = append(im.l.Keys, info)
	id, err := model.ParseID(info.ID)
	return id, "", err
}

func uniqueKeyName(l *daemon.ListResult, base string) string {
	name := base
	for i := 2; slices.ContainsFunc(l.Keys, func(k daemon.KeyInfo) bool { return strings.EqualFold(k.Name, name) }); i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	return name
}

// jumpSpec is a single ProxyJump hop: [user@]host[:port].
type jumpSpec struct {
	user, host, port string
}

func parseJump(s string) jumpSpec {
	var j jumpSpec
	if i := strings.LastIndex(s, "@"); i >= 0 {
		j.user, s = s[:i], s[i+1:]
	}
	switch {
	case strings.HasPrefix(s, "["):
		// [v6]:port
		if end := strings.Index(s, "]"); end > 0 {
			j.host = s[1:end]
			j.port = strings.TrimPrefix(s[end+1:], ":")
			return j
		}
	case strings.Count(s, ":") == 1:
		s, j.port, _ = strings.Cut(s, ":")
	}
	j.host = s
	return j
}

// jumpHit is a host a ProxyJump could mean: one already in the vault, or one
// this import is about to create.
type jumpHit struct {
	host model.Host
	cand *candidate // nil for a vault host
}

// jumpTarget finds the host a ProxyJump names among the vault's hosts and the
// candidates still in. The first step that matches anything decides, and a
// step that matches several hosts is ambiguous: hop does not pick one.
// Steps: a name or alias, then an address.
func (im *importer) jumpTarget(host string, cands []*candidate) (target *jumpHit, ambiguous []string) {
	var pool []jumpHit
	for _, h := range im.l.Hosts {
		pool = append(pool, jumpHit{host: h})
	}
	for _, c := range cands {
		if !c.skipped {
			pool = append(pool, jumpHit{host: c.host, cand: c})
		}
	}
	steps := []func(h model.Host) bool{
		func(h model.Host) bool {
			return slices.ContainsFunc(resolve.Names(h), func(n string) bool { return strings.EqualFold(n, host) })
		},
		func(h model.Host) bool {
			return slices.ContainsFunc(h.Addresses, func(a string) bool { return strings.EqualFold(a, host) })
		},
	}
	for _, match := range steps {
		var found []jumpHit
		for _, p := range pool {
			if match(p.host) {
				found = append(found, p)
			}
		}
		switch len(found) {
		case 0:
			continue
		case 1:
			return &found[0], nil
		}
		for _, p := range found {
			ambiguous = append(ambiguous, p.host.Name)
		}
		return nil, ambiguous
	}
	return nil, nil
}

// planJumps settles every candidate's ProxyJump before anything is saved.
// Only a single hop that a vault host reproduces exactly can be imported: a
// user or port on the hop that differs from the vault host's own would change
// which account or service the jump connects to. A host whose jump cannot be
// imported is skipped, because a host imported without it would connect
// directly where ssh goes through the jump. Skipping a host can strand
// another that jumps through it, so this repeats until nothing changes. Hosts
// that jump through each other in a ring are all skipped: none could be saved
// first.
func (im *importer) planJumps(cands []*candidate) {
	for changed := true; changed; {
		changed = false
		for _, c := range cands {
			if c.skipped || c.jump == "" {
				continue
			}
			if why := im.jumpProblem(c, cands); why != "" {
				c.skipped, changed = true, true
				im.skip(c.entry, c.host.Name, c.source, why)
			}
		}
		for _, c := range cands {
			if !c.skipped && c.jump != "" && jumpsToItself(c, len(cands)) {
				c.skipped, changed = true, true
				im.skip(c.entry, c.host.Name, c.source, fmt.Sprintf("ProxyJump %q leads back to the host through other imported hosts; hop cannot import a loop of jumps", c.jump))
			}
		}
	}
}

// jumpsToItself reports whether following c's jump hosts among the candidates
// comes back to c.
func jumpsToItself(c *candidate, limit int) bool {
	n := c.jumpToCnd
	for i := 0; i <= limit && n != nil && !n.skipped; i++ {
		if n == c {
			return true
		}
		n = n.jumpToCnd
	}
	return false
}

// jumpProblem says why c's ProxyJump cannot be imported, or "" after setting
// where it goes.
func (im *importer) jumpProblem(c *candidate, cands []*candidate) string {
	name := c.host.Name
	if strings.Contains(c.jump, ",") {
		return fmt.Sprintf("ProxyJump %q has several hops; only a single-hop jump can be imported", c.jump)
	}
	jump := parseJump(c.jump)
	hit, ambiguous := im.jumpTarget(jump.host, cands)
	switch {
	case len(ambiguous) > 0:
		return fmt.Sprintf("ProxyJump host %q matches several hosts (%s); pick one after importing with hop edit %s --jump <host>", jump.host, strings.Join(ambiguous, ", "), name)
	case hit == nil:
		return fmt.Sprintf("ProxyJump host %q is not in the vault; add it, import again, or use hop edit %s --jump <host>", jump.host, name)
	case hit.cand == c:
		return fmt.Sprintf("ProxyJump %q is the host itself", c.jump)
	}
	if why := jumpOverride(jump, hit.host); why != "" {
		return fmt.Sprintf("ProxyJump %q %s; hop cannot import that (hop edit %s --jump %s uses the vault host as it is)", c.jump, why, name, hit.host.Name)
	}
	if hit.cand != nil {
		c.jumpTo, c.jumpToCnd = nil, hit.cand
	} else {
		h := hit.host
		c.jumpTo, c.jumpToCnd = &h, nil
	}
	return ""
}

// jumpOverride says how the hop's own user or port differs from the vault
// host it resolved to, or "" when the vault host already does what the hop
// asks for.
func jumpOverride(j jumpSpec, h model.Host) string {
	var diffs []string
	if j.user != "" && j.user != h.User {
		if h.User == "" {
			diffs = append(diffs, fmt.Sprintf("logs in as %q but the vault host %s has no user", j.user, h.Name))
		} else {
			diffs = append(diffs, fmt.Sprintf("logs in as %q but the vault host %s uses %q", j.user, h.Name, h.User))
		}
	}
	if j.port != "" {
		port := h.Port
		if port == 0 {
			port = 22
		}
		if n, err := strconv.Atoi(j.port); err != nil || uint32(n) != port {
			diffs = append(diffs, fmt.Sprintf("uses port %s but the vault host %s uses %d", j.port, h.Name, port))
		}
	}
	return strings.Join(diffs, " and ")
}
