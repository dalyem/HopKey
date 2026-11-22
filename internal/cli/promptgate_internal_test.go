package cli

import (
	"errors"
	"testing"
)

// A prompt whose answer comes in as Run's watcher halts prompts goes one
// way only: back to the command, which the watcher then does not count as
// waiting at a prompt, or held, which the watcher counts. The watcher
// halting right after the gate decided must not find the prompt both
// counted and answered: it would close what the command goes on using.
func TestPromptGateDecidesOnce(t *testing.T) {
	e := &Env{}
	var atPrompt bool
	e.promptDecided = func() { atPrompt = e.haltPrompts() }
	err := e.prompt(func() error { return nil })
	e.resumePrompts()
	if atPrompt && err == nil {
		t.Fatal("the watcher found the command waiting at a prompt, and the prompt's answer went back to it")
	}
}

// Prompts halted before the answer is in: the command does not get it.
func TestPromptHaltedBeforeTheAnswerIsHeld(t *testing.T) {
	e := &Env{}
	var atPrompt bool
	err := e.prompt(func() error {
		atPrompt = e.haltPrompts()
		go e.resumePrompts()
		return nil
	})
	if !atPrompt || !errors.Is(err, errHalted) {
		t.Fatalf("at a prompt %v, err %v; want true and errHalted", atPrompt, err)
	}
}
