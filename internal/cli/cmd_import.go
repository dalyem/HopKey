package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

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
	withKeys := fs.Bool("with-keys", false, "import the private keys named by IdentityFile (default: only record the reference)")
	dryRun := fs.Bool("dry-run", false, "show what would be imported")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	pos, _, err := parseFlags(fs, args[1:])
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		fs.Usage()
		return failf("expected at most one path")
	}
	path := filepath.Join(e.Home, ".ssh", "config")
	if len(pos) == 1 {
		path = pos[0]
	}

	parser := newSSHConfigParser(e.Home, e.Paths.ConfigDir)
	if err := parser.parseFile(path, 0); err != nil {
		return failf("%v", err)
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	imp := &importer{ctx: ctx, e: e, parser: parser, l: l, withKeys: *withKeys, dryRun: *dryRun,
		report: ImportReport{Source: path, DryRun: *dryRun}}
	imp.run()
	imp.report.Warnings = append(parser.warnings, imp.warnings...)
	if parser.defaults {
		imp.report.Warnings = append(imp.report.Warnings, "settings under 'Host *' or 'Match' blocks were not imported")
	}
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
	for _, w := range imp.report.Warnings {
		fmt.Fprintf(e.Stderr, "hop: warning: %s\n", w)
	}
	if !*dryRun && len(imp.report.Entries) > 0 {
		fmt.Fprintf(e.Stderr, "hop: imported hosts have no pinned host keys yet; pin each with: hop trust <host>\n")
	}
	return nil
}

type importer struct {
	ctx      context.Context
	e        *Env
	parser   *sshConfigParser
	l        *daemon.ListResult
	withKeys bool
	dryRun   bool
	report   ImportReport
	warnings []string
	saved    map[string]model.Host // by lower-cased name: what was written, for the jump pass
}

func (im *importer) add(kind, name, status, reason string) {
	im.report.Entries = append(im.report.Entries, ImportEntry{Kind: kind, Name: name, Status: status, Reason: reason})
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

func (im *importer) run() {
	im.saved = map[string]model.Host{}
	var blocks []sshBlock // the ones that were imported, for the jump pass
	for _, b := range im.parser.blocks {
		names := b.concrete()
		name := names[0]
		if owner, ok := im.taken(name); ok {
			im.add("host", name, "exists", fmt.Sprintf("already in the vault as %q", owner))
			continue
		}
		h, err := im.hostFor(b, names)
		if err != nil {
			im.add("host", name, "skipped", err.Error())
			continue
		}
		if im.dryRun {
			im.add("host", name, im.imported(), "")
			im.l.Hosts = append(im.l.Hosts, h) // so later blocks see the name as taken
			blocks = append(blocks, b)
			continue
		}
		var saved model.Host
		if err := call(im.ctx, im.e, daemon.OpPutHost, daemon.PutHostParams{Host: h}, &saved); err != nil {
			im.add("host", name, "failed", err.Error())
			continue
		}
		im.add("host", name, im.imported(), "")
		im.l.Hosts = append(im.l.Hosts, saved)
		im.saved[strings.ToLower(saved.Name)] = saved
		blocks = append(blocks, b)
	}
	im.linkJumps(blocks)
}

// hostFor builds the host a block describes, importing its key if asked.
func (im *importer) hostFor(b sshBlock, names []string) (model.Host, error) {
	name := names[0]
	for _, n := range names {
		if !sshconfig.ValidAlias(n) {
			return model.Host{}, fmt.Errorf("%q is not usable as a host name (letters, digits, '.', '_' and '-')", n)
		}
	}
	addr := strings.ReplaceAll(b.HostName, "%h", name)
	if addr == "" {
		addr = name
	}
	if !sshconfig.ValidHostName(addr) {
		return model.Host{}, fmt.Errorf("HostName %q is not usable", addr)
	}
	if b.User != "" && !sshconfig.ValidUser(b.User) {
		return model.Host{}, fmt.Errorf("User %q is not usable", b.User)
	}
	h := model.Host{
		Name: name, Aliases: names[1:], Addresses: []string{addr}, Port: 22, User: b.User,
		Route: resolve.RouteAuto, AgentAccess: "allow",
		Description: "Imported from " + b.Source,
	}
	if b.Port != 0 {
		h.Port = uint32(b.Port)
	}
	if len(b.IdentityFiles) == 0 {
		return h, nil
	}
	if !im.withKeys {
		h.Description += "; ssh config IdentityFile: " + strings.Join(b.IdentityFiles, ", ") + " (not imported; hop key add <path>, then hop edit " + name + " --key <name>)"
		return h, nil
	}
	for _, f := range b.IdentityFiles {
		id, note, err := im.importKey(im.parser.expand(f))
		if err != nil {
			im.warnf("host %s: IdentityFile %s: %v", name, f, err)
			continue
		}
		h.KeyID = id
		if note != "" {
			h.Description += "; " + note
		}
		break
	}
	if h.KeyID.IsZero() {
		h.Description += "; ssh config IdentityFile: " + strings.Join(b.IdentityFiles, ", ") + " (could not be imported)"
	}
	return h, nil
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

// linkJumps sets jump hosts once every host exists. Only a single ProxyJump
// hop is understood.
func (im *importer) linkJumps(blocks []sshBlock) {
	for _, b := range blocks {
		if b.ProxyJump == "" || strings.EqualFold(b.ProxyJump, "none") {
			continue
		}
		name := b.concrete()[0]
		if strings.Contains(b.ProxyJump, ",") {
			im.warnf("host %s: ProxyJump %q has several hops; only single-hop jumps are imported", name, b.ProxyJump)
			continue
		}
		jump := b.ProxyJump
		if i := strings.LastIndex(jump, "@"); i >= 0 {
			jump = jump[i+1:]
		}
		if i := strings.LastIndex(jump, ":"); i >= 0 && !strings.Contains(jump[:i], ":") {
			jump = jump[:i]
		}
		var target *model.Host
		for i := range im.l.Hosts {
			h := &im.l.Hosts[i]
			if slices.ContainsFunc(resolve.Names(*h), func(n string) bool { return strings.EqualFold(n, jump) }) ||
				slices.ContainsFunc(h.Addresses, func(a string) bool { return strings.EqualFold(a, jump) }) {
				target = h
				break
			}
		}
		if target == nil {
			im.warnf("host %s: ProxyJump host %q is not in the vault; add it, then hop edit %s --jump <host>", name, jump, name)
			continue
		}
		saved, ok := im.saved[strings.ToLower(name)]
		if im.dryRun || !ok {
			continue
		}
		saved.JumpHostID = target.ItemID
		var again model.Host
		if err := call(im.ctx, im.e, daemon.OpPutHost, daemon.PutHostParams{Host: saved}, &again); err != nil {
			im.warnf("host %s: setting jump host %s: %v", name, jump, err)
			continue
		}
		im.saved[strings.ToLower(name)] = again
	}
}
