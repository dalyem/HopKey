package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/sshkeys"
)

// maxKeyFile bounds how much of a key file hop reads. Private keys are a few
// kilobytes; anything larger is not one.
const maxKeyFile = 64 << 10

func runKey(ctx context.Context, e *Env, args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(e.Stderr, "usage: %s\n", commands["key"].usage)
		return failf("key needs a subcommand: add, ls or rm")
	}
	switch args[0] {
	case "add":
		return runKeyAdd(ctx, e, args[1:])
	case "ls":
		return runKeyLs(ctx, e, args[1:])
	case "rm":
		return runKeyRm(ctx, e, args[1:])
	}
	return failf("unknown key subcommand %q (add, ls, rm)", args[0])
}

// readPrivateKey reads the private key file at path, asking for its
// passphrase if it has one, and returns the key as unencrypted OpenSSH PEM.
// The file is one the user named on the command line.
func readPrivateKey(e *Env, path string) (pem string, key *sshkeys.Private, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, failf("%v", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return "", nil, failf("reading %s: %v", path, err)
	}
	if len(data) > maxKeyFile {
		return "", nil, failf("%s is too large to be a private key", path)
	}

	key, err = sshkeys.Parse(data)
	if errors.Is(err, sshkeys.ErrPassphrase) {
		if e.ReadPassword == nil || !e.StdinTTY {
			return "", nil, failf("%s is passphrase-protected; run this on a terminal so hop can ask for the passphrase", path)
		}
		pass, perr := e.ReadPassword(safef("Passphrase for %s: ", path))
		if perr != nil {
			return "", nil, failf("reading the passphrase: %v", perr)
		}
		key, err = sshkeys.ParseWithPassphrase(data, pass)
		clear(pass)
	}
	if err != nil {
		return "", nil, failf("%s: %v", path, err)
	}
	pem, err = key.MarshalPrivate(filepath.Base(path))
	if err != nil {
		return "", nil, failf("%v", err)
	}
	return pem, key, nil
}

func runKeyAdd(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "key add", "hop key add <path> [--name N] [--json]")
	name := fs.String("name", "", "name for the key (default: the file name)")
	asJSON := fs.Bool("json", false, "print the key as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return failf("expected the path of one private key file")
	}
	pem, _, err := readPrivateKey(e, pos[0])
	if err != nil {
		return err
	}
	if *name == "" {
		*name = filepath.Base(pos[0])
	}
	info, err := putKey(ctx, e, *asJSON, *name, pem)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(e, info)
	}
	e.printf("added key %s (%s %s)\n", oneLine(info.Name), oneLine(info.KeyType), oneLine(info.Fingerprint))
	return nil
}

// putKey saves a key and returns it as the daemon saved it, ID included,
// which the daemon's answer carries even when the ssh config could not be
// written (a warning). An answer without an ID is an error, as for
// putHost.
func putKey(ctx context.Context, e *Env, asJSON bool, name, pem string) (daemon.KeyInfo, error) {
	var info daemon.KeyInfo
	if err := callChange(ctx, e, asJSON, daemon.OpPutKey, daemon.PutKeyParams{Name: name, PrivateKey: pem}, &info); err != nil {
		return daemon.KeyInfo{}, err
	}
	if info.ID == "" {
		return daemon.KeyInfo{}, failf("the daemon saved the key %s but did not say as what, so its ID is unknown; see hop key ls", name)
	}
	return info, nil
}

// KeyView is the --json shape of hop key ls: no private half.
type KeyView struct {
	daemon.KeyInfo
	Hosts []string   `json:"hosts"`          // hosts that log in with it
	Mark  model.Mark `json:"mark,omitempty"` // pending or held, as for hosts
}

func runKeyLs(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "key ls", "hop key ls [--json]")
	asJSON := fs.Bool("json", false, "print the keys as JSON")
	if _, _, err := parseFlags(fs, args); err != nil {
		return err
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	views := make([]KeyView, 0, len(l.Keys))
	for _, k := range l.Keys {
		v := KeyView{KeyInfo: k, Hosts: []string{}, Mark: l.Marks[k.ID]}
		for _, h := range l.Hosts {
			if h.KeyID.String() == k.ID {
				v.Hosts = append(v.Hosts, h.Name)
			}
		}
		slices.Sort(v.Hosts)
		views = append(views, v)
	}
	slices.SortFunc(views, func(a, b KeyView) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	if *asJSON {
		return printJSON(e, views)
	}
	if len(views) == 0 {
		fmt.Fprintln(e.Stderr, "no keys")
		return nil
	}
	marked := slices.ContainsFunc(views, func(v KeyView) bool { return v.Mark != "" })
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	if marked {
		fmt.Fprintln(tw, "NAME\tTYPE\tFINGERPRINT\tHOSTS\tSYNC")
	} else {
		fmt.Fprintln(tw, "NAME\tTYPE\tFINGERPRINT\tHOSTS")
	}
	for _, v := range views {
		// Vault text: no tabs or newlines may break the table.
		row := fmt.Sprintf("%s\t%s\t%s\t%s", oneLine(v.Name), oneLine(v.KeyType), oneLine(v.Fingerprint), dash(joinOne(v.Hosts, ",")))
		if marked {
			row += "\t" + dash(oneLine(string(v.Mark)))
		}
		fmt.Fprintln(tw, row)
	}
	return tw.Flush()
}

func runKeyRm(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "key rm", "hop key rm <name> [--yes] [--json]")
	yes := fs.Bool("yes", false, "do not ask")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return failf("expected exactly one key name")
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	id, err := findKey(l, pos[0])
	if err != nil {
		return err
	}
	var using []string
	for _, h := range l.Hosts {
		if h.KeyID == id {
			using = append(using, h.Name)
		}
	}
	if len(using) > 0 {
		return failf("key %s is used by %s; point those hosts at another key first (hop edit <host> --key <name>)", pos[0], joinOne(using, ", "))
	}
	ok, err := confirm(e, *yes, safef("Remove key %s? This deletes the private key from the vault.", pos[0]))
	if err != nil {
		return err
	}
	if !ok {
		return failf("not removed")
	}
	if err := callChange(ctx, e, *asJSON, daemon.OpDelete, daemon.DeleteParams{ID: id.String()}, nil); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(e, map[string]any{"removed": pos[0], "id": id.String()})
	}
	e.printf("removed key %s\n", oneLine(pos[0]))
	return nil
}
