package cli

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/store"
)

// hop auth is everything about accounts, devices and access (design:
// "Signing in: hop auth"). hop login and hop logout are aliases. Only
// devices works so far; the subcommands that sign in, approve and check
// point are wired to internal/authflow in a later slice. To add one, give
// authCommands an entry: run gets the arguments after the subcommand.

type authCommand struct {
	run   func(ctx context.Context, e *Env, args []string) error
	usage string
}

var authCommands map[string]authCommand

func init() {
	authCommands = map[string]authCommand{
		"devices": {runAuthDevices, "hop auth devices [--json] | hop auth devices revoke <name>"},
		"login":   {notYet("login"), "hop auth login [--server URL] [--email E] [--method approve|password|recovery] [--name DEVICE] [--merge]"},
		"signup":  {notYet("signup"), "hop auth signup [--server URL] [--email E]"},
		"approve": {notYet("approve"), "hop auth approve [CODE]"},
		"logout":  {notYet("logout"), "hop auth logout [--keep-cache] [--discard-pending] [--local-only]"},
		"rotate":  {notYet("rotate"), "hop auth rotate"},
		"passwd":  {notYet("passwd"), "hop auth passwd"},
		"merge":   {notYet("merge"), "hop auth merge --resume | --discard"},
		"status":  {notYet("status"), "hop auth status [--json]"},
	}
}

func authUsage() string {
	names := make([]string, 0, len(authCommands))
	for n := range authCommands {
		names = append(names, n)
	}
	slices.Sort(names)
	var sb strings.Builder
	sb.WriteString("usage:\n")
	for _, n := range names {
		fmt.Fprintf(&sb, "  %s\n", authCommands[n].usage)
	}
	return sb.String()
}

func runAuth(ctx context.Context, e *Env, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(e.Stderr, authUsage())
		return failf("auth needs a subcommand")
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(e.Stdout, authUsage())
		return nil
	}
	sub, ok := authCommands[args[0]]
	if !ok {
		fmt.Fprint(e.Stderr, authUsage())
		return failf("unknown auth subcommand %q", args[0])
	}
	return sub.run(ctx, e, args[1:])
}

// runLogin is hop login, the alias of hop auth login.
func runLogin(ctx context.Context, e *Env, args []string) error {
	return runAuth(ctx, e, append([]string{"login"}, args...))
}

// runLogout is hop logout, the alias of hop auth logout.
func runLogout(ctx context.Context, e *Env, args []string) error {
	return runAuth(ctx, e, append([]string{"logout"}, args...))
}

// notYet is a subcommand this build does not have yet.
func notYet(name string) func(context.Context, *Env, []string) error {
	return func(context.Context, *Env, []string) error {
		return failf("hop auth %s is not available yet in this version of hop", name)
	}
}

func runAuthDevices(ctx context.Context, e *Env, args []string) error {
	if len(args) > 0 && args[0] == "revoke" {
		return failf("hop auth devices revoke is not available yet in this version of hop")
	}
	fs := newFlags(e, "auth devices", authCommands["devices"].usage)
	asJSON := fs.Bool("json", false, "print the devices as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		fs.Usage()
		return failf("unknown devices subcommand %q (revoke)", pos[0])
	}
	var res daemon.DevicesResult
	if err := call(ctx, e, daemon.OpDevicesList, nil, &res); err != nil {
		if daemon.IsCode(err, daemon.CodeLocalOnly) {
			return failf("%v: this vault is local-only, so it has no devices to list", err)
		}
		if daemon.IsCode(err, daemon.CodeLocked) {
			return failf("%v; run hop unlock first", err)
		}
		return err
	}
	if res.Devices == nil {
		res.Devices = []store.DeviceListing{}
	}
	if *asJSON {
		return printJSON(e, res)
	}
	if len(res.Devices) == 0 {
		fmt.Fprintln(e.Stderr, "no devices")
		return nil
	}
	// Device names come from other devices through the server: oneLine
	// keeps them from breaking the table.
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tID\tADDED BY\tADDED\tLAST SEEN\tNOTES")
	for _, d := range res.Devices {
		seen := "-"
		if d.LastSeen != nil {
			seen = e.when(*d.LastSeen)
		}
		var notes []string
		if d.This {
			notes = append(notes, "this device")
		}
		if d.Stale {
			notes = append(notes, "stale: its key was replaced here; hop passwd revokes it")
		}
		if d.Undelivered {
			notes = append(notes, "undelivered: never received the vault; revoke it")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", dash(oneLine(d.Name)), oneLine(d.ID.String()), dash(oneLine(d.How)), e.when(d.AddedAt), seen, dash(strings.Join(notes, "; ")))
	}
	return tw.Flush()
}
