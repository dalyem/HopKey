package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/access"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
)

// hop access check (crypto spec rev 17, §7.8): read-only and lockless. It
// reads the file of every target of every live record, terminal ones
// included, and compares what it finds with the vault state it pulled.

// akCheckScript prints a header, "hop-check 1 USER LOCK N", where LOCK is
// seen or not-seen for the lock directory (not-seen is never "absent": a
// lookup that fails is not-seen too) and N counts ~/.ssh/.hop-s.*
// entries; then the lock's owner line (empty if it can't be read); then
// the file, as the read script does.
const akCheckScript = `d="$HOME/.ssh/` + akLockDir + `"; u=$(id -un) || exit 84; ` +
	`if [ -d "$d" ]; then k=seen; else k=not-seen; fi; ` +
	`n=0; for x in "$HOME"/.ssh/.hop-s.*; do if [ -e "$x" ]; then n=$((n+1)); fi; done; ` +
	`o=; if [ "$k" = seen ]; then o=$(head -n 1 "$d/owner" 2>/dev/null | tr -cd '0-9a-zA-Z:. -'); fi; ` +
	`echo "hop-check 1 $u $k $n"; echo "$o"; ` + akReadScript

// AccessFinding is one finding of hop access check.
type AccessFinding struct {
	Kind        string `json:"kind"`
	Host        string `json:"host"`
	User        string `json:"user,omitempty"`
	Line        int    `json:"line,omitempty"`
	Text        string `json:"text,omitempty"`
	Label       string `json:"label,omitempty"`
	RecordID    string `json:"record_id,omitempty"`
	TargetState string `json:"target_state,omitempty"`
	Message     string `json:"message"`
	Fix         string `json:"fix,omitempty"`
	// Informational findings don't make the exit status 1.
	Informational bool `json:"informational,omitempty"`
	// Unread says the file couldn't be read (exit status 2).
	Unread bool `json:"unread,omitempty"`
}

// The finding kinds.
const (
	findUntracked       = "untracked-line"
	findLineRemoved     = "line-present-removed"
	findLineAbandoned   = "line-present-abandoned"
	findLineMissing     = "line-missing"
	findLineChanged     = "line-changed"
	findTombNotRemoved  = "tombstone-not-removed"
	findTombMissing     = "tombstone-missing"
	findUnfinished      = "unfinished-target"
	findFailed          = "failed-target"
	findMalformed       = "malformed"
	findTombstone       = "tombstone"
	findTombCount       = "tombstone-count"
	findCantRead        = "cant-read"
	findLock            = "lock-or-session-directory"
	findSharedDifferent = "shared-pin-different-files"
)

// checkRead is one file as check read it.
type checkRead struct {
	user    string
	lock    string // seen | not-seen
	owner   string
	dirs    int
	content []byte
	why     string // why it couldn't be read
}

func parseCheckOutput(b []byte) (checkRead, bool) {
	br := bufio.NewReader(bytes.NewReader(b))
	head, err := br.ReadString('\n')
	if err != nil {
		return checkRead{}, false
	}
	f := strings.Fields(head)
	if len(f) != 5 || f[0] != "hop-check" || f[1] != "1" || (f[3] != "seen" && f[3] != "not-seen") {
		return checkRead{}, false
	}
	n, err := strconv.Atoi(f[4])
	if err != nil {
		return checkRead{}, false
	}
	owner, err := br.ReadString('\n')
	if err != nil {
		return checkRead{}, false
	}
	rest, _ := io.ReadAll(br)
	return checkRead{user: f[2], lock: f[3], owner: strings.TrimSpace(owner), dirs: n, content: rest}, true
}

// checkFile reads one file on a connection restricted to pins.
func (e *Env) checkFile(ctx context.Context, h model.Host, l *daemon.ListResult, pins []ssh.PublicKey) checkRead {
	c, why := e.accessConnect(ctx, h, l, pins)
	if why != "" {
		return checkRead{why: why}
	}
	defer c.close()
	out := &capBuffer{max: akMaxSize + 4096}
	res, err := c.ssh.run(ctx, sh(akCheckScript), nil, out)
	r, ok := parseCheckOutput(out.buf.Bytes())
	switch {
	case err != nil || !res.exited || res.ExitCode == sshAuthFailed:
		return checkRead{why: "could not log in (" + sshFailure(res, err) + ")"}
	case !ok:
		return checkRead{why: "could not read " + akFile + " (" + sshFailure(res, err) + ")"}
	case res.ExitCode == akExitSymlink:
		r.why = akFile + " is a symbolic link"
	case res.ExitCode == akExitMissing:
		r.why = akFile + " does not exist"
	case res.ExitCode != 0:
		r.why = "could not read " + akFile + " (" + sshFailure(res, err) + ")"
	case out.over:
		r.why = akFile + " is larger than 1 MiB"
	}
	if c.user != "" && r.user != c.user && r.why == "" {
		r.why = "the host now logs in as " + r.user + ", not " + c.user
	}
	return r
}

type accessCheck struct {
	e        *Env
	ix       hostIndex
	records  []model.Access
	findings []AccessFinding
	read     map[string]bool // files whose own lines were already reported
}

func (k *accessCheck) add(f AccessFinding) { k.findings = append(k.findings, f) }

// recordOf is the live record with record ID rid.
func (k *accessCheck) recordOf(rid string) *model.Access {
	for i := range k.records {
		if k.records[i].RecordID.String() == rid {
			return &k.records[i]
		}
	}
	return nil
}

func tombstoneFix(host, user string, rid string, gen uint64) string {
	return safef("append this line to ~/.ssh/authorized_keys of %s on %s: # hop-access-removed %s %d", user, host, rid, gen)
}

func deleteFix(host, user string, n int, rid string) string {
	return safef("delete line %d of ~/.ssh/authorized_keys of %s on %s (it ends in hop-access:%s)", n, user, host, rid)
}

// fileFindings reports what one file holds that isn't about a particular
// target: untracked lines, malformed tombstone-like lines, markers no
// single record manages, every tombstone-like line, the count, and a lock
// or session directory. key names the file so it is reported once.
func (k *accessCheck) fileFindings(host string, r checkRead, key string) {
	if k.read[key] {
		return
	}
	k.read[key] = true
	lines := access.Lines(r.content)
	ntomb := 0
	for i, l := range lines {
		n := i + 1
		if like, rid, gen := access.ParseTombstone(l); like {
			ntomb++
			if rid == "" {
				k.add(AccessFinding{Kind: findMalformed, Host: host, User: r.user, Line: n, Text: l,
					Message: "a hop access tombstone hop can't read", Fix: safef("fix or delete line %d by hand", n)})
				continue
			}
			f := AccessFinding{Kind: findTombstone, Host: host, User: r.user, Line: n, Text: l, RecordID: rid, Informational: true}
			if a := k.recordOf(rid); a != nil {
				f.Label = a.Label
				f.Message = safef("tombstone for record %s (gen %d)", a.Label, gen)
			} else {
				f.Message = safef("tombstone for a record this vault doesn't have (gen %d); deleting it removes that record's protection on this file", gen)
			}
			k.add(f)
			continue
		}
		kl, ok := access.ParseKeyLine(l)
		if !ok || !kl.Marked {
			continue
		}
		rid := strings.TrimPrefix(kl.Comment, access.MarkerPrefix)
		if kl.CertCA || kl.Marker == "" || kl.Comment != access.MarkerPrefix+rid {
			k.add(AccessFinding{Kind: findMalformed, Host: host, User: r.user, Line: n, Text: l,
				Message: "a hop access marker no single record manages", Fix: safef("fix or delete line %d by hand", n)})
			continue
		}
		if k.recordOf(rid) == nil {
			k.add(AccessFinding{Kind: findUntracked, Host: host, User: r.user, Line: n, Text: l, RecordID: rid,
				Message: "a line managed by a record no live record of this vault names",
				Fix:     "if no other vault of yours has record " + rid + ", " + deleteFix(host, r.user, n, rid)})
		}
	}
	if ntomb >= access.TombstoneWarn {
		k.add(AccessFinding{Kind: findTombCount, Host: host, User: r.user,
			Message: safef("%s holds %d hop access tombstones; at %d, hop access rm can't remove new records there", akFile, ntomb, access.TombstoneBound)})
	}
	if r.lock == "seen" || r.dirs > 0 {
		msg := safef("%d hop session director(ies) ~/.ssh/.hop-s.* present", r.dirs)
		if r.lock == "seen" {
			msg = safef("the lock ~/.ssh/%s is present (owner: %s); %s", akLockDir, orUnknown(r.owner), msg)
		}
		k.add(AccessFinding{Kind: findLock, Host: host, User: r.user, Message: msg,
			Fix: "a hop run is active, was killed, or kept its lock. " + strings.ReplaceAll(akHeldAdvice, "LOCK", "~/.ssh/"+akLockDir)})
	}
}

// targetFindings compares one target with its file (§7.8 table).
func (k *accessCheck) targetFindings(a *model.Access, t model.AccessTarget, host string, r checkRead) {
	f := access.FactsOf(r.content, a)
	rid := a.RecordID.String()
	base := AccessFinding{Host: host, User: t.User, Label: a.Label, RecordID: rid, TargetState: t.State}
	with := func(kind, msg, fix string, line int) {
		x := base
		x.Kind, x.Message, x.Fix, x.Line = kind, msg, fix, line
		k.add(x)
	}
	lineNo := func(i int) int { return i + 1 }
	tombNoLine := len(f.Tb) > 0 && len(f.Mg) == 0
	if len(f.Tb) > 0 && t.State != model.AccessRemoved {
		fix := "hop access check can't fix this from here"
		if !model.AccessTerminal(t.State) {
			fix = "hop access rm " + a.Label + " " + host + " (it records removed without writing)"
		}
		with(findTombNotRemoved, safef("the host says record %s was removed here (gen %d); your vault shows %s (gen %d)", a.Label, f.Tb[0].Gen, t.State, t.Gen), fix, f.Tb[0].Line)
	}
	switch t.State {
	case model.AccessRemoved:
		for _, i := range f.Mg {
			with(findLineRemoved, "line present for a removed target", deleteFix(host, t.User, lineNo(i), rid), lineNo(i))
		}
		if len(f.Tb) == 0 {
			with(findTombMissing, "tombstone missing for a removed target", tombstoneFix(host, t.User, rid, t.Gen), 0)
		}
	case model.AccessAbandoned:
		for _, i := range f.Mg {
			x := base
			x.Kind, x.Line, x.Informational = findLineAbandoned, lineNo(i), true
			x.Message = "line present for an abandoned target: you confirmed that it may remain"
			x.Fix = deleteFix(host, t.User, lineNo(i), rid) + ", if you still reach that machine"
			k.add(x)
		}
	case model.AccessInstalled:
		switch {
		case tombNoLine: // reported above; never offer add over a tombstone
		case len(f.Mg) == 0:
			with(findLineMissing, "line missing for an installed target", "hop access add "+a.Label+" "+host, 0)
		case len(f.Mg) > 1 || !lineMatches(r.content, f, a):
			with(findLineChanged, "the line for an installed target changed (or there is more than one)",
				safef("fix or delete line %d by hand, then hop access add %s %s", lineNo(f.Mg[0]), a.Label, host), lineNo(f.Mg[0]))
		}
	case model.AccessPending, model.AccessRemoving:
		holds := "the file holds no line for it"
		if len(f.Mg) > 0 {
			holds = safef("the file holds its line (line %d)", lineNo(f.Mg[0]))
		}
		if len(f.Tb) > 0 {
			holds += ", and its tombstone"
		}
		fix := "hop access rm " + a.Label + " finishes it"
		if t.State == model.AccessPending && !tombNoLine {
			fix = "hop access add " + a.Label + " finishes it"
		}
		with(findUnfinished, safef("%s target (gen %d): %s", t.State, t.Gen, holds), fix, 0)
	case model.AccessFailed:
		fix := "hop access add " + a.Label + " " + host + " retries"
		if tombNoLine {
			fix = "hop access rm " + a.Label + " " + host
		}
		with(findFailed, safef("failed target (%s)", orUnknown(t.Error)), fix, 0)
	}
}

func lineMatches(content []byte, f access.Facts, a *model.Access) bool {
	l := access.Lines(content)[f.Mg[0]]
	kl, ok := access.ParseKeyLine(l)
	return ok && access.Matches(kl, a)
}

func runAccessCheck(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "access check", commands["access"].usage)
	var hostsFlag stringList
	fs.Var(&hostsFlag, "host", "check only this host (repeatable)")
	allHosts := fs.Bool("all-hosts", false, "also read every pinned host with no target, for lines of records this vault no longer has")
	asJSON := fs.Bool("json", false, "print the findings as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	v := &accessVault{e: e}
	al, err := v.list(ctx)
	if err != nil {
		return err
	}
	if !al.Local {
		if err := v.pull(ctx); err != nil {
			fmt.Fprintln(e.Stderr, "comparing with your local copy of the vault, which may be out of date")
		} else if al, err = v.list(ctx); err != nil {
			return err
		}
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	k := &accessCheck{e: e, ix: hostIndex{l.Hosts}, records: al.Access, read: map[string]bool{}}
	unread := false
	cache := map[string]checkRead{}
	readAs := func(h model.Host, pins []ssh.PublicKey, key string) checkRead {
		if r, ok := cache[key]; ok {
			return r
		}
		r := e.checkFile(ctx, h, l, pins)
		cache[key] = r
		return r
	}
	targeted := map[model.ID]bool{}
	for i := range al.Access {
		a := &al.Access[i]
		if len(pos) > 0 && !slices.Contains(pos, a.Label) {
			continue
		}
		for _, t := range a.Targets {
			targeted[t.HostItemID] = true
			name := k.ix.name(t.HostItemID)
			if len(hostsFlag.vals) > 0 && !slices.Contains(hostsFlag.vals, name) {
				continue
			}
			h, ok := k.ix.byID(t.HostItemID)
			pin := boundPin(h, t.ServerKeyFP)
			if !ok || pin == nil {
				why := unbound(t, a.Label, name)
				if !ok {
					why = "the host was deleted; hop access rm " + a.Label + " --abandon " + t.HostItemID.String()
				}
				if model.AccessTerminal(t.State) {
					continue // nothing to read it through, and nothing left to do
				}
				unread = true
				k.add(AccessFinding{Kind: findCantRead, Host: name, User: t.User, Label: a.Label, TargetState: t.State, Message: why, Unread: true})
				continue
			}
			key := t.HostItemID.String() + " " + t.ServerKeyFP
			r := readAs(h, []ssh.PublicKey{pin}, key)
			if r.why == "" && r.user != t.User {
				r.why = "the host now logs in as " + r.user + ", not " + t.User
			}
			if r.why != "" {
				unread = true
				k.add(AccessFinding{Kind: findCantRead, Host: name, User: t.User, Label: a.Label, TargetState: t.State, Message: r.why, Unread: true,
					Fix: "hop trust " + name + ", hop access migrate " + a.Label + " " + name + " or hop access rm " + a.Label + " --abandon " + name})
				continue
			}
			k.fileFindings(name, r, key)
			k.targetFindings(a, t, name, r)
			// A known shared pin: the same file through every other host
			// record that pins the key (§7.4).
			for _, o := range k.ix.sharedPins(t.ServerKeyFP, t.HostItemID) {
				or := readAs(o, []ssh.PublicKey{pin}, o.ItemID.String()+" "+t.ServerKeyFP)
				if or.why == "" && !bytes.Equal(or.content, r.content) {
					k.add(AccessFinding{Kind: findSharedDifferent, Host: name, User: t.User, Label: a.Label, TargetState: t.State,
						Message: safef("these host records reach different machines or accounts with the same host key: %s and %s", name, o.Name),
						Fix:     "for a removal, hop access rm " + a.Label + " --abandon " + name + ", never --same-machine"})
				}
			}
		}
	}
	if *allHosts {
		for _, h := range l.Hosts {
			if targeted[h.ItemID] || (len(hostsFlag.vals) > 0 && !slices.Contains(hostsFlag.vals, h.Name)) {
				continue
			}
			pins, _ := parsePins(h.HostKeys)
			if len(pins) == 0 {
				continue
			}
			r := readAs(h, pins, h.ItemID.String()+" all")
			if r.why != "" {
				unread = true
				k.add(AccessFinding{Kind: findCantRead, Host: h.Name, Message: r.why, Unread: true})
				continue
			}
			k.fileFindings(h.Name, r, h.ItemID.String()+" all")
		}
	}
	return k.report(e, *asJSON, unread)
}

func (k *accessCheck) report(e *Env, asJSON, unread bool) error {
	findings := k.findings
	if findings == nil {
		findings = []AccessFinding{}
	}
	serious := false
	for _, f := range findings {
		serious = serious || (!f.Informational && !f.Unread)
	}
	if asJSON {
		if err := printJSON(e, findings); err != nil {
			return err
		}
	} else {
		if len(findings) == 0 {
			e.printf("no findings: every file hop read matches the vault state it pulled\n")
		}
		for _, f := range findings {
			e.printf("%s", oneLine(f.Host))
			if f.Line > 0 {
				e.printf(" line %d", f.Line)
			}
			if f.Label != "" {
				e.printf(" [%s]", oneLine(f.Label))
			}
			e.printf(": %s\n", oneLine(f.Message))
			if f.Text != "" {
				e.printf("    %s\n", oneLine(f.Text))
			}
			if f.Fix != "" {
				e.printf("    fix: %s\n", oneLine(f.Fix))
			}
		}
	}
	switch {
	case unread:
		return silent(2)
	case serious:
		return silent(1)
	}
	return nil
}
