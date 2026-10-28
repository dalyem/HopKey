package cli

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/shellcmd"
)

// Snippets are saved commands with {{name}} parameters. hop snippet keeps
// them; hop mcp runs them (run_snippet), passing each parameter's value in
// a shell variable (shellcmd.Render).

func runSnippet(ctx context.Context, e *Env, args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(e.Stderr, "usage: %s\n", commands["snippet"].usage)
		return failf("snippet needs a subcommand: add, ls or rm")
	}
	switch args[0] {
	case "add":
		return runSnippetAdd(ctx, e, args[1:])
	case "ls":
		return runSnippetLs(ctx, e, args[1:])
	case "rm":
		return runSnippetRm(ctx, e, args[1:])
	}
	return failf("unknown snippet subcommand %q (add, ls, rm)", args[0])
}

// SnippetView is the --json shape of hop snippet ls and hop snippet add.
type SnippetView struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Command     string     `json:"command"`
	Params      []string   `json:"params"`
	Description string     `json:"description"`
	Mark        model.Mark `json:"mark,omitempty"` // pending or held, as for hosts
}

func snippetView(s model.Snippet, marks map[string]model.Mark) SnippetView {
	return SnippetView{
		ID: s.ItemID.String(), Name: s.Name, Command: s.Command, Params: nonNil(s.Params),
		Description: s.Description, Mark: marks[s.ItemID.String()],
	}
}

func runSnippetAdd(ctx context.Context, e *Env, args []string) error {
	const usage = "hop snippet add <name> [--description D] [--json] -- <command...>"
	fs := newFlags(e, "snippet add", usage)
	desc := fs.String("description", "", "what the snippet does, for people and agents")
	asJSON := fs.Bool("json", false, "print the saved snippet as JSON")
	helpNote(e, fs, "\nOne word after -- is a shell command line, as with ssh: hop snippet add df -- 'df -h {{path}}'.\n"+
		"Several words are quoted one by one. A {{name}} placeholder (letters, digits and _) is filled from a shell variable\n"+
		"when the snippet runs, so its value never becomes shell source text; write it bare, outside quotes. A snippet that\n"+
		"evaluates a value itself (eval, sh -c, arithmetic, indirect expansion) can still run it; hop refuses the common cases.\n")
	pos, rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || len(rest) == 0 {
		fs.Usage()
		return failf("expected a snippet name, then -- and the command")
	}
	command := shellcmd.Join(rest)
	// The daemon checks the same; asking here first gives the error before
	// the daemon starts.
	if _, err := shellcmd.Placeholders(command); err != nil {
		return failf("%v", err)
	}
	var saved model.Snippet
	sn := model.Snippet{Name: pos[0], Command: command, Description: *desc}
	if err := callChange(ctx, e, *asJSON, daemon.OpPutSnippet, daemon.PutSnippetParams{Snippet: sn}, &saved); err != nil {
		return err
	}
	if saved.ItemID.IsZero() {
		return failf("the daemon saved the snippet %s but did not say as what; see hop snippet ls", pos[0])
	}
	if *asJSON {
		return printJSON(e, snippetView(saved, nil))
	}
	e.printf("added snippet %s: %s\n", oneLine(saved.Name), oneLine(saved.Command))
	if len(saved.Params) > 0 {
		e.printf("parameters: %s\n", joinOne(saved.Params, ", "))
	}
	return nil
}

func runSnippetLs(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "snippet ls", "hop snippet ls [--json]")
	asJSON := fs.Bool("json", false, "print the snippets as JSON")
	if _, _, err := parseFlags(fs, args); err != nil {
		return err
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	views := make([]SnippetView, 0, len(l.Snippets))
	for _, s := range l.Snippets {
		views = append(views, snippetView(s, l.Marks))
	}
	slices.SortFunc(views, func(a, b SnippetView) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	if *asJSON {
		return printJSON(e, views)
	}
	if len(views) == 0 {
		fmt.Fprintln(e.Stderr, "no snippets; add one with hop snippet add <name> -- <command>")
		return nil
	}
	marked := slices.ContainsFunc(views, func(v SnippetView) bool { return v.Mark != "" })
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	header := "NAME\tPARAMS\tCOMMAND\tDESCRIPTION"
	if marked {
		header += "\tSYNC"
	}
	fmt.Fprintln(tw, header)
	for _, v := range views {
		// Vault text: no tabs or newlines may break the table.
		row := fmt.Sprintf("%s\t%s\t%s\t%s", oneLine(v.Name), dash(joinOne(v.Params, ",")), printable(v.Command), dash(printable(v.Description)))
		if marked {
			row += "\t" + dash(oneLine(string(v.Mark)))
		}
		fmt.Fprintln(tw, row)
	}
	return tw.Flush()
}

func runSnippetRm(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "snippet rm", "hop snippet rm <name> [--yes] [--json]")
	yes := fs.Bool("yes", false, "do not ask")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return failf("expected exactly one snippet name")
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	sn, err := findSnippet(l.Snippets, pos[0])
	if err != nil {
		return err
	}
	ok, err := confirm(e, *yes, safef("Remove snippet %s?", sn.Name))
	if err != nil {
		return err
	}
	if !ok {
		return failf("not removed")
	}
	if err := callChange(ctx, e, *asJSON, daemon.OpDelete, daemon.DeleteParams{ID: sn.ItemID.String()}, nil); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(e, map[string]any{"removed": sn.Name, "id": sn.ItemID.String()})
	}
	e.printf("removed snippet %s\n", oneLine(sn.Name))
	return nil
}

// findSnippet finds a snippet by name, ignoring case, or by ID.
func findSnippet(snippets []model.Snippet, ref string) (model.Snippet, error) {
	for _, s := range snippets {
		if strings.EqualFold(s.Name, ref) || s.ItemID.String() == ref {
			return s, nil
		}
	}
	var names []string
	for _, s := range snippets {
		names = append(names, s.Name)
	}
	if len(names) == 0 {
		return model.Snippet{}, failf("no snippet named %q; there are none yet (hop snippet add <name> -- <command>)", ref)
	}
	return model.Snippet{}, failf("no snippet named %q; snippets: %s", ref, joinOne(names, ", "))
}
