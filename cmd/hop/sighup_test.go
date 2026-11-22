package main

import (
	"bufio"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"syscall"
	"testing"
	"time"
)

// TestMain lets a test run this binary as the helper of
// TestNohupKeepsHopAliveOnHangup.
func TestMain(m *testing.M) {
	if os.Getenv("HOP_TEST_SIGHUP_HELPER") == "1" {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, stopSignals(signal.Ignored(syscall.SIGHUP))...)
		os.Stdout.WriteString("ready\n")
		select {
		case <-sigs:
			os.Stdout.WriteString("caught\n")
		case <-time.After(time.Second):
			os.Stdout.WriteString("ignored\n")
		}
		return
	}
	os.Exit(m.Run())
}

// A hop started under nohup has SIGHUP ignored, and hop keeps it that way:
// closing the terminal must not stop a login or an approval the user left
// running on purpose.
func TestNohupKeepsHopAliveOnHangup(t *testing.T) {
	signal.Ignore(syscall.SIGHUP) // the child inherits an ignored signal, as under nohup
	t.Cleanup(func() { signal.Reset(syscall.SIGHUP) })

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "HOP_TEST_SIGHUP_HELPER=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	lines := bufio.NewScanner(out)
	if !lines.Scan() || lines.Text() != "ready" {
		t.Fatalf("helper said %q, want ready", lines.Text())
	}
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	if !lines.Scan() {
		t.Fatalf("the helper died on SIGHUP: %v", cmd.Wait())
	}
	if got := lines.Text(); got != "ignored" {
		t.Errorf("helper said %q after SIGHUP, want ignored: hop caught a signal nohup had ignored", got)
	}
	if err := cmd.Wait(); err != nil {
		t.Errorf("helper: %v", err)
	}
}

// Without nohup, SIGHUP stops hop like SIGINT does; with SIGHUP ignored it
// does not, and the other signals still stop it.
func TestStopSignals(t *testing.T) {
	hup := os.Signal(syscall.SIGHUP)
	if got := stopSignals(false); !slices.Contains(got, hup) {
		t.Errorf("stopSignals(false) = %v: no SIGHUP", got)
	}
	got := stopSignals(true)
	if slices.Contains(got, hup) {
		t.Errorf("stopSignals(true) = %v: SIGHUP is ignored and must stay so", got)
	}
	for _, want := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		if !slices.Contains(got, want) {
			t.Errorf("stopSignals(true) = %v: no %v", got, want)
		}
	}
}
