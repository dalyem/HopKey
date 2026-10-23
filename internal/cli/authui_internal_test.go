package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/authflow"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

// uiFixture is a termUI over scripted streams.
type uiFixture struct {
	u       *termUI
	stdout  bytes.Buffer
	stderr  bytes.Buffer
	secrets []string // ReadPassword's answers, in order
	prompts []string
}

func newUIFixture(t *testing.T, interactive bool, stdin string, env map[string]string) *uiFixture {
	f := &uiFixture{}
	e := &Env{
		Stdin: strings.NewReader(stdin), Stdout: &f.stdout, Stderr: &f.stderr,
		Getenv:   func(k string) string { return env[k] },
		StdinTTY: interactive, StdoutTTY: interactive,
		Now: func() time.Time { return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC) },
		ReadPassword: func(p string) ([]byte, error) {
			f.prompts = append(f.prompts, p)
			if len(f.secrets) == 0 {
				t.Errorf("unexpected secret prompt %q", p)
				return nil, errors.New("no answer")
			}
			a := f.secrets[0]
			f.secrets = f.secrets[1:]
			return []byte(a), nil
		},
	}
	f.u = newTermUI(e, false)
	return f
}

const testSAS = "12345678"

func TestSASNeedsAnExplicitYes(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		stdin string
		match bool
		fails bool
	}{
		{"yes\n", true, false},
		{"YES\n", true, false},
		{"no\n", false, false},
		// Neither y nor an empty line is a yes: it asks again.
		{"y\n\nyes\n", true, false},
		{"y\nok\nsure\n", false, true},
		{"", false, true},
	} {
		f := newUIFixture(t, true, c.stdin, nil)
		match, err := f.u.ConfirmSAS(ctx, testSAS, "laptop")
		if match != c.match || (err != nil) != c.fails {
			t.Errorf("%q: match %v, err %v", c.stdin, match, err)
		}
		if err != nil && !isUIError(err) {
			t.Errorf("%q: the error is not a UI error, so a flow would resume and ask again: %v", c.stdin, err)
		}
		if !strings.Contains(f.stderr.String(), "1234 5678") || !strings.Contains(f.stderr.String(), "laptop") {
			t.Errorf("the code is not shown: %q", f.stderr.String())
		}
	}
}

func TestSASWithoutATerminal(t *testing.T) {
	ctx := context.Background()
	// The approving device needs --sas, and never prints its own code: a
	// script could otherwise approve by echoing it back.
	f := newUIFixture(t, false, "", nil)
	f.u.role = roleApprove
	match, err := f.u.ConfirmSAS(ctx, testSAS, "laptop")
	if match || err == nil || !strings.Contains(err.Error(), "--sas") {
		t.Errorf("approve without --sas: %v, %v", match, err)
	}
	if strings.Contains(err.Error()+f.stderr.String()+f.stdout.String(), "1234") {
		t.Errorf("the approving device showed its own check code without a terminal: %q %q", err, f.stderr.String())
	}
	for sas, want := range map[string]bool{"12345678": true, "1234 5678": true, "1234-5678": true, "12345679": false, "": false} {
		if sas == "" {
			continue
		}
		f.u.sas = sas
		if match, err := f.u.ConfirmSAS(ctx, testSAS, "laptop"); match != want || err != nil {
			t.Errorf("--sas %q: %v, %v", sas, match, err)
		}
	}

	// The new device shows its code to carry over, and accepts only with
	// --yes.
	f = newUIFixture(t, false, "yes\n", nil)
	f.u.role = roleLogin
	if match, err := f.u.ConfirmSAS(ctx, testSAS, "laptop"); match || err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("login without --yes: %v, %v", match, err)
	}
	if !strings.Contains(f.stderr.String(), "1234 5678") {
		t.Errorf("the new device does not show its code: %q", f.stderr.String())
	}
	f.u.yes = true
	if match, err := f.u.ConfirmSAS(ctx, testSAS, "laptop"); !match || err != nil {
		t.Errorf("login with --yes: %v, %v", match, err)
	}
}

func TestKitTypeBack(t *testing.T) {
	ctx := context.Background()
	kit := store.Kit{AccountID: "acct", SecretKey: "A3-AAAAAA-BBBBB-CCCCC", RecoveryKey: "R1-DDDDD-EEEEE-FFFFF"}

	f := newUIFixture(t, true, "", nil)
	f.secrets = []string{"ccccc", "fffff"}
	if err := f.u.ShowKit(ctx, kit); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.stdout.String(), kit.SecretKey) || !strings.Contains(f.stdout.String(), kit.RecoveryKey) {
		t.Errorf("the kit is not shown: %q", f.stdout.String())
	}
	tb, err := f.u.ConfirmKit(ctx, 1)
	if err != nil || tb.SecretKey != "ccccc" || tb.RecoveryKey != "fffff" {
		t.Errorf("type-back: %+v, %v", tb, err)
	}
	if len(f.prompts) != 2 || !strings.Contains(f.prompts[0], "Secret Key") || !strings.Contains(f.prompts[1], "Recovery Key") {
		t.Errorf("prompts: %q", f.prompts)
	}

	// Without a terminal: HOP_KIT_CONFIRM once, and an error naming it
	// otherwise. The error never quotes the kit or the groups.
	f = newUIFixture(t, false, "", nil)
	if err := f.u.ShowKit(ctx, kit); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		if _, err := f.u.ConfirmKit(ctx, attempt); err == nil || !strings.Contains(err.Error(), envKitConfirm) || !strings.Contains(err.Error(), "hop auth resume") {
			t.Errorf("no type-back, attempt %d: %v", attempt, err)
		} else if strings.Contains(err.Error(), "CCCCC") || strings.Contains(err.Error(), "FFFFF") {
			t.Errorf("the error quotes the kit: %v", err)
		}
	}
	f = newUIFixture(t, false, "", map[string]string{envKitConfirm: "ccccc fffff"})
	if tb, err := f.u.ConfirmKit(ctx, 1); err != nil || tb.SecretKey != "ccccc" || tb.RecoveryKey != "fffff" {
		t.Errorf("HOP_KIT_CONFIRM: %+v, %v", tb, err)
	}
	if _, err := f.u.ConfirmKit(ctx, 2); err == nil || strings.Contains(err.Error(), "ccccc") {
		t.Errorf("a second attempt reused HOP_KIT_CONFIRM, or quoted it: %v", err)
	}
	f = newUIFixture(t, false, "", map[string]string{envKitConfirm: "onlyone"})
	if _, err := f.u.ConfirmKit(ctx, 1); err == nil || strings.Contains(err.Error(), "onlyone") {
		t.Errorf("a malformed HOP_KIT_CONFIRM: %v", err)
	}
}

// Secrets come from the environment once, never twice, and no error
// quotes one.
func TestSecretsWithoutATerminal(t *testing.T) {
	ctx := context.Background()
	const secret = "s3cret-value"
	env := map[string]string{envPassword: secret, envNewPassword: secret, envSecretKey: secret, envRecoveryKey: secret}
	f := newUIFixture(t, false, "", env)
	asks := []func() (string, error){
		func() (string, error) { b, err := f.u.Password(ctx, authflow.ReasonLogin); return string(b), err },
		func() (string, error) { b, err := f.u.NewPassword(ctx, authflow.ReasonRecovery); return string(b), err },
		func() (string, error) { return f.u.SecretKey(ctx, authflow.ReasonLogin, false) },
		func() (string, error) { return f.u.RecoveryKey(ctx) },
	}
	for i, ask := range asks {
		if v, err := ask(); v != secret || err != nil {
			t.Errorf("%d: first ask: %q, %v", i, v, err)
		}
		v, err := ask()
		if v != "" || err == nil {
			t.Errorf("%d: second ask gave the same secret again: %q", i, v)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%d: the error quotes the secret: %v", i, err)
		}
	}

	f = newUIFixture(t, false, "", nil)
	for i, c := range []struct {
		ask  func() error
		want string
	}{
		{func() error { _, err := f.u.Password(ctx, authflow.ReasonRotate); return err }, envPassword},
		{func() error { _, err := f.u.NewPassword(ctx, authflow.ReasonPasswd); return err }, envNewPassword},
		{func() error { _, err := f.u.SecretKey(ctx, authflow.ReasonPasswd, true); return err }, "newest Emergency Kit"},
		{func() error { _, err := f.u.RecoveryKey(ctx); return err }, envRecoveryKey},
		{func() error { _, err := f.u.RegistrationCode(ctx); return err }, "--code"},
	} {
		if err := c.ask(); err == nil || !strings.Contains(err.Error(), c.want) || !isUIError(err) {
			t.Errorf("%d: %v; want an error naming %s", i, err, c.want)
		}
	}

	// --password-stdin: the first line, once.
	f = newUIFixture(t, false, secret+"\nmore\n", nil)
	f.u.passwordStdin = true
	if b, err := f.u.Password(ctx, authflow.ReasonLogin); string(b) != secret || err != nil {
		t.Errorf("--password-stdin: %q, %v", b, err)
	}
	if _, err := f.u.Password(ctx, authflow.ReasonLogin); err == nil {
		t.Errorf("--password-stdin gave a second password")
	}
}

func devicesFixture() []store.DeviceListing {
	added := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return []store.DeviceListing{
		{ID: model.ID{1}, Name: "desk", How: store.AddedBySignup, AddedAt: added, This: true},
		{ID: model.ID{2}, Name: "laptop" + "\x1b[2J", How: store.AddedByApproval, AddedAt: added},
		{ID: model.ID{3}, Name: "twin", How: store.AddedByBootstrap, AddedAt: added},
		{ID: model.ID{4}, Name: "twin", How: store.AddedByBootstrap, AddedAt: added},
	}
}

func TestSurvivorsNeedYesWithoutATerminal(t *testing.T) {
	ctx := context.Background()
	c := authflow.SurvivorChoice{Kind: store.CheckpointRotate, Devices: devicesFixture()}
	f := newUIFixture(t, false, "", nil)
	if _, err := f.u.ChooseSurvivors(ctx, c); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("rotate without --yes: %v", err)
	}
	f.u.keep, f.u.keepSet = []string{"twin"}, true
	if _, err := f.u.ChooseSurvivors(ctx, c); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("rotate with --keep but no --yes: %v", err)
	}
	f.u.yes = true
	f.u.keep = []string{model.ID{3}.String() + "," + model.ID{2}.String()}
	refs, err := f.u.ChooseSurvivors(ctx, c)
	if err != nil || len(refs) != 2 {
		t.Errorf("--keep --yes: %q, %v", refs, err)
	}
	out := f.stderr.String()
	for _, want := range []string{"NAME", "ADDED BY", "LAST SEEN", "this device", model.ID{4}.String(), "approval"} {
		if !strings.Contains(out, want) {
			t.Errorf("the list lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("a device name reached the terminal raw: %q", out)
	}
}

func TestSurvivorsOnATerminal(t *testing.T) {
	ctx := context.Background()
	c := authflow.SurvivorChoice{Kind: store.CheckpointRevoke, Devices: devicesFixture(), Targets: []model.ID{{2}}}
	// Enter keeps only this device, and the confirmation names what goes.
	f := newUIFixture(t, true, "\ny\n", nil)
	refs, err := f.u.ChooseSurvivors(ctx, c)
	if err != nil || len(refs) != 0 {
		t.Errorf("Enter: %q, %v", refs, err)
	}
	if !strings.Contains(f.stderr.String(), "to revoke") || !strings.Contains(f.stderr.String(), "Revoke laptop") {
		t.Errorf("confirmation: %q", f.stderr.String())
	}
	// A no changes nothing.
	f = newUIFixture(t, true, model.ID{3}.String()+"\nn\n", nil)
	if _, err := f.u.ChooseSurvivors(ctx, c); err == nil || !strings.Contains(err.Error(), "nothing changed") {
		t.Errorf("declined: %v", err)
	}
	// An ambiguous name goes to authflow, which refuses it.
	f = newUIFixture(t, true, "twin\n", nil)
	if refs, err := f.u.ChooseSurvivors(ctx, c); err != nil || len(refs) != 1 || refs[0] != "twin" {
		t.Errorf("ambiguous: %q, %v", refs, err)
	}
}

func TestNewDevicesWithoutATerminal(t *testing.T) {
	ctx := context.Background()
	devices := devicesFixture()[1:3]
	f := newUIFixture(t, false, "", nil)
	f.u.keep = []string{model.ID{2}.String()}
	if _, err := f.u.ConfirmNewDevices(ctx, devices); err == nil || !strings.Contains(err.Error(), "--exclude "+model.ID{3}.String()) {
		t.Errorf("an unanswered device: %v", err)
	}
	f.u.exclude = []string{"twin"}
	ids, err := f.u.ConfirmNewDevices(ctx, devices)
	if err != nil || len(ids) != 1 || ids[0] != (model.ID{2}) {
		t.Errorf("answered: %v, %v", ids, err)
	}
}
