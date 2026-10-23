package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/dalyem/hopkey/internal/authflow"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

// termUI is authflow.UI on the terminal (design: "Signing in: hop auth").
//
// On a terminal (stdin and stdout both, and no --json) it asks: secrets
// through Env.ReadPassword, without echo, and everything else as a line on
// stdin, with the question on stderr. Anywhere else nothing is asked:
// every answer comes from a flag or, for a secret, from an environment
// variable, and a prompt with no answer fails with an error that names
// the flag or the variable. A secret is never taken from a flag, which
// other users can read in the process list.
//
// No error it returns holds a secret: the messages are constant text and
// display-safe names.
type termUI struct {
	e           *Env
	interactive bool
	asJSON      bool
	role        string // roleLogin, roleApprove or "" (prompts word the SAS by it)

	// Answers from flags.
	yes     bool     // --yes: the destructive confirmations (never the check code)
	sas     string   // --sas: the code the new device shows, for hop auth approve
	keep    []string // --keep
	keepSet bool
	exclude []string // --exclude, for the devices a password change finds
	code    string   // --code: a registration code for when the first one is refused
	kitFile string   // --kit-file

	// passwordStdin reads the current master password from stdin once
	// (--password-stdin).
	passwordStdin bool

	// used marks each one-shot answer (an environment variable, stdin,
	// --code) once it has been given, so a refused answer is not given
	// again and again.
	used map[string]bool
	// kit is the last kit shown, and wroteKit the --kit-file it went to.
	kit      *store.Kit
	wroteKit string
}

const (
	roleLogin   = "login"
	roleApprove = "approve"
)

// The environment variables that answer secret prompts without a
// terminal.
const (
	envPassword    = "HOP_PASSWORD"     // the current master password
	envNewPassword = "HOP_NEW_PASSWORD" // a new master password
	envSecretKey   = "HOP_SECRET_KEY"   // the Secret Key from the Emergency Kit
	envRecoveryKey = "HOP_RECOVERY_KEY" // the Recovery Key from the Emergency Kit
	// envKitConfirm is the type-back of a kit shown earlier: the last
	// group of its Secret Key and of its Recovery Key, separated by a
	// space or a comma.
	envKitConfirm = "HOP_KIT_CONFIRM"
)

// errApproveNeedsTerminal is why the new device can't sign in by
// approval without a terminal, and what it can do instead.
const errApproveNeedsTerminal = "signing in by approval needs a terminal on this device, to compare the check code with the approving device " +
	"(this run has none: --json, or stdin or stdout is not a terminal; --yes does not confirm it). " +
	"Run hop login in a terminal (an SSH session to a headless machine has one), " +
	"or sign in with --method password (HOP_PASSWORD and HOP_SECRET_KEY) or --method recovery (HOP_RECOVERY_KEY)"

// uiError is a prompt that could not be answered. A flow interrupted by
// one is not resumed on its own: asking again would fail the same way.
type uiError struct{ msg string }

func (u *uiError) Error() string { return u.msg }

func uiErrorf(format string, args ...any) error { return &uiError{msg: safef(format, args...)} }

func isUIError(err error) bool {
	var u *uiError
	return errors.As(err, &u)
}

func newTermUI(e *Env, asJSON bool) *termUI {
	return &termUI{
		e: e, asJSON: asJSON, used: map[string]bool{},
		interactive: e.StdinTTY && e.StdoutTTY && !asJSON && e.ReadPassword != nil,
	}
}

var _ authflow.UI = (*termUI)(nil)

// say writes a line for the user to stderr, which keeps stdout for the
// result (and for --json, its one shape).
func (u *termUI) say(format string, args ...any) {
	fmt.Fprintf(u.e.Stderr, format, args...)
}

// once returns the value of an environment variable the first time it is
// asked for, and "" after that or when it is unset.
func (u *termUI) once(name string) (string, bool) {
	if u.used[name] {
		return "", false
	}
	v := u.e.Getenv(name)
	if v == "" {
		return "", false
	}
	u.used[name] = true
	return v, true
}

// refused says an answer given without a terminal was not accepted.
func (u *termUI) refused(what, source string) error {
	return uiErrorf("the %s from %s was not accepted", what, source)
}

func (u *termUI) readSecret(prompt string) ([]byte, error) {
	b, err := u.e.ReadPassword(prompt)
	if err != nil {
		return nil, uiErrorf("reading the answer: %v", err)
	}
	return b, nil
}

// readAnswer asks a question on stderr and reads one line from stdin.
func (u *termUI) readAnswer(prompt string) (string, error) {
	u.say("%s", prompt)
	line, err := readLine(u.e.Stdin)
	if err != nil && line == "" {
		if errors.Is(err, io.EOF) {
			return "", uiErrorf("no answer: stdin ended")
		}
		return "", uiErrorf("reading the answer: %v", err)
	}
	return strings.TrimSpace(line), nil
}

func (u *termUI) Password(ctx context.Context, r authflow.Reason) ([]byte, error) {
	if v, ok := u.once(envPassword); ok {
		return []byte(v), nil
	} else if u.used[envPassword] {
		return nil, u.refused("master password", envPassword)
	}
	if u.passwordStdin {
		if u.used["stdin"] {
			return nil, u.refused("master password", "--password-stdin")
		}
		u.used["stdin"] = true
		line, err := readLine(u.e.Stdin)
		line = strings.TrimSuffix(line, "\r")
		if err != nil && line == "" {
			return nil, uiErrorf("--password-stdin: no password on stdin")
		}
		return []byte(line), nil
	}
	if !u.interactive {
		return nil, uiErrorf("the master password is needed and there is no terminal to ask on: set %s or pass --password-stdin", envPassword)
	}
	prompt := "Current master password: "
	if r == authflow.ReasonLogin {
		prompt = "Master password: "
	}
	pw, err := u.readSecret(prompt)
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		return nil, uiErrorf("no master password given")
	}
	return pw, nil
}

func (u *termUI) NewPassword(ctx context.Context, r authflow.Reason) ([]byte, error) {
	if v, ok := u.once(envNewPassword); ok {
		return []byte(v), nil
	} else if u.used[envNewPassword] {
		return nil, u.refused("new master password", envNewPassword)
	}
	if !u.interactive {
		return nil, uiErrorf("a new master password is needed and there is no terminal to ask on: set %s", envNewPassword)
	}
	switch r {
	case authflow.ReasonRecovery:
		u.say("Choose a new master password to finish the recovery.\n")
	case authflow.ReasonSignup:
		u.say("Choose the master password of the new account.\n")
	}
	pw, err := readNewPassword(u.e, "New master password: ")
	if err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			return nil, &uiError{msg: ee.msg}
		}
		return nil, err
	}
	return pw, nil
}

func (u *termUI) SecretKey(ctx context.Context, r authflow.Reason, stale bool) (string, error) {
	if v, ok := u.once(envSecretKey); ok {
		return v, nil
	} else if u.used[envSecretKey] {
		return "", u.refused("Secret Key", envSecretKey)
	}
	if !u.interactive {
		if stale {
			return "", uiErrorf("the Secret Key stored on this device is out of date, and there is no terminal to ask on: set %s to the Secret Key from your newest Emergency Kit", envSecretKey)
		}
		return "", uiErrorf("the Secret Key is needed and there is no terminal to ask on: set %s to the Secret Key from your Emergency Kit", envSecretKey)
	}
	prompt := "Secret Key (from your Emergency Kit): "
	if stale {
		u.say("The Secret Key stored on this device is out of date: a later change replaced it.\n")
		prompt = "Secret Key (from your newest Emergency Kit): "
	}
	b, err := u.readSecret(prompt)
	if err != nil {
		return "", err
	}
	defer clear(b)
	return strings.TrimSpace(string(b)), nil
}

func (u *termUI) RecoveryKey(ctx context.Context) (string, error) {
	if v, ok := u.once(envRecoveryKey); ok {
		return v, nil
	} else if u.used[envRecoveryKey] {
		return "", u.refused("Recovery Key", envRecoveryKey)
	}
	if !u.interactive {
		return "", uiErrorf("the Recovery Key is needed and there is no terminal to ask on: set %s to the Recovery Key from your Emergency Kit", envRecoveryKey)
	}
	b, err := u.readSecret("Recovery Key (from your Emergency Kit): ")
	if err != nil {
		return "", err
	}
	defer clear(b)
	return strings.TrimSpace(string(b)), nil
}

func (u *termUI) RegistrationCode(ctx context.Context) (string, error) {
	if u.code != "" && !u.used["code"] {
		u.used["code"] = true
		return u.code, nil
	}
	if !u.interactive {
		return "", uiErrorf("the server refused the registration code: run hop auth signup again with another --code (hop-server invite makes one)")
	}
	u.say("The server refused that registration code (it is unknown, used or expired). Nothing was published.\n")
	code, err := u.readAnswer("Another registration code (from hop-server invite): ")
	if err != nil {
		return "", err
	}
	if code == "" {
		return "", uiErrorf("no registration code given")
	}
	return code, nil
}

// groupCode shows a routing code in two halves for reading aloud; the
// approving side ignores the hyphen.
func groupCode(code string) string {
	if len(code) == 10 {
		return code[:5] + "-" + code[5:]
	}
	return code
}

func (u *termUI) ShowRoutingCode(ctx context.Context, code string) error {
	code = oneLine(code)
	if u.asJSON {
		u.jsonLine(map[string]string{"routing_code": code})
		return nil
	}
	u.say("\nTo approve this device, run this on a device that is already signed in:\n\n")
	u.say("    hop auth approve %s\n\n", groupCode(code))
	u.say("Waiting for the approval...\n")
	return nil
}

// jsonLine writes one JSON object as a line on stderr, for what a script
// needs while a --json command still runs (the routing code, say).
func (u *termUI) jsonLine(v any) {
	if b, err := json.Marshal(v); err == nil {
		fmt.Fprintln(u.e.Stderr, string(escapeJSONControls(b)))
	}
}

// notice tells the user what a command does next: a line on stderr, or
// with --json a {"notice": ...} line there, so stderr stays JSON lines.
// msg is constant text.
func (u *termUI) notice(msg string) {
	if u.asJSON {
		u.jsonLine(map[string]string{"notice": msg})
		return
	}
	u.say("%s\n", msg)
}

// groupSAS shows the 8-digit check code as two groups of four.
func groupSAS(sas string) string {
	if len(sas) == 8 {
		return sas[:4] + " " + sas[4:]
	}
	return sas
}

// normalizeDigits drops the spaces and hyphens a user types into a code.
func normalizeDigits(s string) string {
	return strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(strings.TrimSpace(s))
}

// ConfirmSAS shows the check code big and clear. On a terminal it needs
// an explicit yes; anything but yes or no asks again.
//
// Without a terminal, hop auth approve compares the code against --sas,
// which the user copies from the new device's screen: the approving
// device never prints its own code there, so a script can't approve by
// echoing it back.
//
// The new device never confirms without a terminal (§7: the SAS is
// confirmed on both devices). A flag that said "the codes match" would
// be given before the codes exist, so it would confirm whatever approver
// the relay put in the middle; and the mailbox token lives only in
// memory, so a later run can't confirm what an earlier one showed.
// runAuthLogin refuses first; this is the backstop.
func (u *termUI) ConfirmSAS(ctx context.Context, sas, deviceName string) (bool, error) {
	sas, deviceName = oneLine(sas), oneLine(deviceName)
	if !u.interactive {
		if u.role == roleApprove {
			if u.sas == "" {
				return false, uiErrorf("hop auth approve compares the 8-digit check code the new device shows, and there is no terminal to ask on: "+
					"run hop auth approve again with the same code and --sas DIGITS, the digits the new device %q shows", deviceName)
			}
			return normalizeDigits(u.sas) == sas, nil
		}
		return false, &uiError{msg: errApproveNeedsTerminal}
	}
	other := "the approving device"
	if u.role == roleApprove {
		other = "the new device"
	}
	u.say("\n")
	u.say("    Check code:   %s\n", groupSAS(sas))
	u.say("    Device:       %s\n", deviceName)
	u.say("\n")
	u.say("Compare it with the code %s shows. Only say yes if every digit matches.\n", other)
	for range 3 {
		a, err := u.readAnswer("Do the codes match? Type yes or no: ")
		if err != nil {
			return false, err
		}
		switch strings.ToLower(a) {
		case "yes":
			return true, nil
		case "no":
			return false, nil
		}
		u.say("Type yes if the codes match, or no if they do not.\n")
	}
	return false, uiErrorf("no yes or no answer to the check code")
}

// printDevices lists devices as the survivor choice shows them: name, ID,
// how and when added, last seen.
func (u *termUI) printDevices(devices []store.DeviceListing, targets []model.ID) {
	tw := tabwriter.NewWriter(u.e.Stderr, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  NAME\tID\tADDED BY\tADDED\tLAST SEEN\tNOTES")
	for _, d := range devices {
		seen := "-"
		if d.LastSeen != nil {
			seen = u.e.when(*d.LastSeen)
		}
		var notes []string
		if d.This {
			notes = append(notes, "this device (always kept)")
		}
		if slices.Contains(targets, d.ID) {
			notes = append(notes, "to revoke")
		}
		if d.Stale {
			notes = append(notes, "stale")
		}
		if d.Undelivered {
			notes = append(notes, "undelivered")
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n", dash(oneLine(d.Name)), oneLine(d.ID.String()), dash(oneLine(d.How)), u.e.when(d.AddedAt), seen, dash(strings.Join(notes, "; ")))
	}
	tw.Flush()
}

func (u *termUI) ShowDevices(ctx context.Context, devices []store.DeviceListing) error {
	if u.asJSON {
		return nil
	}
	u.say("A password change keeps every device signed in:\n")
	u.printDevices(devices, nil)
	return nil
}

// splitRefs splits device references given as a comma list, and as
// repeated flags.
func splitRefs(vals []string) []string {
	var out []string
	for _, v := range vals {
		for _, r := range strings.Split(v, ",") {
			if r = strings.TrimSpace(r); r != "" {
				out = append(out, r)
			}
		}
	}
	return out
}

// resolveRefs resolves references the way authflow does, to show what a
// choice does before it is confirmed: a listed device's ID, or a name
// exactly one listed device has. ok is false when one does not resolve;
// authflow then refuses the choice with its own error.
func resolveRefs(devices []store.DeviceListing, refs []string) (ids []model.ID, ok bool) {
	for _, ref := range refs {
		var found []model.ID
		for _, d := range devices {
			if d.ID.String() == ref || d.Name == ref {
				found = append(found, d.ID)
			}
		}
		if len(found) != 1 {
			return nil, false
		}
		if !slices.Contains(ids, found[0]) {
			ids = append(ids, found[0])
		}
	}
	return ids, true
}

func kindText(kind string) string {
	switch kind {
	case store.CheckpointRevoke:
		return "the revocation"
	case store.CheckpointRecovery:
		return "the recovery"
	}
	return "the rotation"
}

// ChooseSurvivors lists every active device and asks which to keep
// besides this one. Only this device is kept by default. The choice is
// confirmed before anything changes; without a terminal, --keep gives it
// and --yes confirms it.
func (u *termUI) ChooseSurvivors(ctx context.Context, c authflow.SurvivorChoice) ([]string, error) {
	if !u.asJSON {
		u.say("The devices of the account:\n")
		u.printDevices(c.Devices, c.Targets)
		u.say("%s revokes every device you do not keep, and replaces every key, the Secret Key and the Recovery Key.\n",
			upperFirst(kindText(c.Kind)))
	}
	refs := splitRefs(u.keep)
	if !u.keepSet && u.interactive {
		a, err := u.readAnswer("Devices to keep besides this one (IDs or unique names, comma-separated; Enter keeps only this device): ")
		if err != nil {
			return nil, err
		}
		refs = splitRefs([]string{a})
	}
	if !u.interactive && !u.yes {
		return nil, uiErrorf("%s revokes every device not kept (--keep names them; only this device is kept by default), and there is no terminal to confirm on: pass --yes", kindText(c.Kind))
	}
	keep, ok := resolveRefs(c.Devices, refs)
	if !ok {
		// authflow refuses it with the reason.
		return refs, nil
	}
	var gone []string
	for _, d := range c.Devices {
		if !d.This && !slices.Contains(keep, d.ID) {
			gone = append(gone, fmt.Sprintf("%s (%s)", dash(oneLine(d.Name)), d.ID))
		}
	}
	if u.interactive {
		q := "Revoke no other device and replace every key?"
		if len(gone) > 0 {
			q = fmt.Sprintf("Revoke %s, and replace every key?", strings.Join(gone, ", "))
		}
		if ok, err := confirm(u.e, false, q); err != nil {
			return nil, err
		} else if !ok {
			return nil, uiErrorf("cancelled; nothing changed")
		}
	}
	return refs, nil
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ConfirmNewDevices asks about the devices that joined while a password
// change ran: each one kept or revoked. Without a terminal every one must
// be named by --keep or --exclude.
func (u *termUI) ConfirmNewDevices(ctx context.Context, devices []store.DeviceListing) ([]model.ID, error) {
	if !u.asJSON {
		u.say("These devices joined the account while the password was being changed:\n")
		u.printDevices(devices, nil)
	}
	keep, okK := resolveRefs(devices, splitRefs(u.keep))
	excl, okE := resolveRefs(devices, splitRefs(u.exclude))
	if !u.interactive {
		if !okK || !okE {
			return nil, uiErrorf("--keep and --exclude must name the devices listed, by ID or by a name only one of them has")
		}
		for _, d := range devices {
			if !slices.Contains(keep, d.ID) && !slices.Contains(excl, d.ID) {
				return nil, uiErrorf("device %q (%s) joined during the password change: pass --keep %s to keep it or --exclude %s to revoke it", d.Name, d.ID, d.ID, d.ID)
			}
		}
		return keep, nil
	}
	for {
		a, err := u.readAnswer("Devices to keep (IDs or unique names, comma-separated; Enter revokes all of them): ")
		if err != nil {
			return nil, err
		}
		ids, ok := resolveRefs(devices, splitRefs([]string{a}))
		if ok {
			return ids, nil
		}
		u.say("Name the devices listed, by ID or by a name only one of them has.\n")
	}
}

func (u *termUI) ShowKit(ctx context.Context, kit store.Kit) error {
	k := kit
	u.kit = &k
	if u.kitFile != "" {
		if err := writeKitFile(u.kitFile, []byte(kit.Text())); err != nil {
			return uiErrorf("writing the kit: %v", err)
		}
		// One file per kit: a later kit in this run is not written over it.
		u.wroteKit, u.kitFile = u.kitFile, ""
	}
	// The kit goes to the terminal as hop init shows it. With --json,
	// stdout keeps its one shape and the kit is a JSON line on stderr.
	if u.asJSON {
		u.jsonLine(map[string]any{"emergency_kit": kit})
		return nil
	}
	fmt.Fprintf(u.e.Stdout, "\nYour new Emergency Kit:\n\n%s\n", kit.Text())
	if u.wroteKit != "" {
		fmt.Fprintf(u.e.Stdout, "The kit was also written to %s.\n", oneLine(u.wroteKit))
	}
	return nil
}

// ConfirmKit has the user type back the last group of each key. On a
// terminal that is a prompt each; without one it is HOP_KIT_CONFIRM, for a
// kit an earlier run showed (hop auth resume).
func (u *termUI) ConfirmKit(ctx context.Context, attempt int) (authflow.KitTypeBack, error) {
	if v, ok := u.once(envKitConfirm); ok {
		f := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
		if len(f) != 2 {
			return authflow.KitTypeBack{}, uiErrorf("%s must hold the last group of the Secret Key and of the Recovery Key, separated by a space", envKitConfirm)
		}
		return authflow.KitTypeBack{SecretKey: f[0], RecoveryKey: f[1]}, nil
	} else if u.used[envKitConfirm] {
		return authflow.KitTypeBack{}, uiErrorf("%s does not match the Emergency Kit shown; it stays pending: run hop auth resume with the groups of this kit", envKitConfirm)
	}
	if !u.interactive {
		return authflow.KitTypeBack{}, uiErrorf("the new Emergency Kit must be typed back, and there is no terminal to ask on. "+
			"It stays pending: run hop auth resume with %s set to the last group of its Secret Key and of its Recovery Key", envKitConfirm)
	}
	if attempt > 1 {
		u.say("Those are not the last groups of the kit's two keys. Try again.\n")
	}
	sk, err := u.readSecret("Type the last group of your Secret Key: ")
	if err != nil {
		return authflow.KitTypeBack{}, err
	}
	defer clear(sk)
	rk, err := u.readSecret("Type the last group of your Recovery Key: ")
	if err != nil {
		return authflow.KitTypeBack{}, err
	}
	defer clear(rk)
	return authflow.KitTypeBack{SecretKey: string(sk), RecoveryKey: string(rk)}, nil
}
