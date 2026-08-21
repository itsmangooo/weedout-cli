package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/itsmangooo/weedout-cli/internal/ui"
)

// ---------------------------------------------------------------------------
// The menu
// ---------------------------------------------------------------------------

func TestTheMenuRunsWhatWasChosen(t *testing.T) {
	// "8" is Help, which is the one entry that touches neither the network nor
	// the filesystem, so this tests the routing rather than a command.
	var out bytes.Buffer
	printer := ui.New(&out).WithInput(strings.NewReader("8\n"))

	code := runMenu(printer, &out, &out)

	if code != ExitOK {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(out.String(), "weedout scan [path]") {
		t.Errorf("the chosen command did not run:\n%s", out.String())
	}
}

func TestBackingOutOfTheMenuIsNotAFailure(t *testing.T) {
	// Pressing q in a menu is a normal way to leave. Exiting non-zero would
	// make `weedout` look broken to any script that checks the status.
	var out bytes.Buffer
	printer := ui.New(&out).WithInput(strings.NewReader("q\n"))

	if code := runMenu(printer, &out, &out); code != ExitOK {
		t.Errorf("cancelling exited %d, want %d", code, ExitOK)
	}
}

func TestEveryMenuEntryNamesARealCommand(t *testing.T) {
	// A menu entry whose value is not a command would print "Unknown command"
	// at somebody who picked it from a list this program drew.
	known := map[string]bool{
		"scan": true, "init": true, "status": true, "findings": true,
		"history": true, "supply-chain": true, "rules": true,
		"update": true, "help": true, "version": true,
	}
	for _, choice := range menuChoices {
		if !known[choice.Value] {
			t.Errorf("menu entry %q routes to %q, which is not a command",
				choice.Label, choice.Value)
		}
	}
}

func TestTheMenuOffersNothingThatChangesRulesWithoutArguments(t *testing.T) {
	// `rules` lists; `rules ignore` changes what this project will report in
	// future. The second needs a reason typed out and must not be two
	// keypresses away.
	for _, choice := range menuChoices {
		if strings.Contains(choice.Value, "ignore") {
			t.Errorf("menu entry %q would change rules with no reason given", choice.Label)
		}
	}
}

// ---------------------------------------------------------------------------
// The setting
// ---------------------------------------------------------------------------

func TestInteractiveStatusReportsWithoutChangingAnything(t *testing.T) {
	var out bytes.Buffer
	printer := ui.New(&out)

	code := runInteractiveSetting([]string{"status"}, printer, &out)

	if code != ExitOK {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(out.String(), "Interactive mode is") {
		t.Errorf("no report:\n%s", out.String())
	}
}

func TestAnUnknownInteractiveArgumentIsRefused(t *testing.T) {
	var out bytes.Buffer

	code := runInteractiveSetting([]string{"maybe"}, ui.New(&out), &out)

	if code != ExitError {
		t.Errorf("exit %d, want %d", code, ExitError)
	}
	if !strings.Contains(out.String(), "on, off, or status") {
		t.Errorf("the message did not list the options:\n%s", out.String())
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestADevelopmentBuildIsNotOfferedAnUpdate(t *testing.T) {
	// Version is "dev" in a test binary. Somebody running a build they made
	// themselves has a reason to be running it, and this must not go to the
	// network or offer to replace it.
	var out bytes.Buffer

	code := runUpdate([]string{"--check"}, ui.New(&out), &out)

	if code != ExitOK {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(out.String(), "development build") {
		t.Errorf("a dev build was not recognised:\n%s", out.String())
	}
}

func TestTheUpdateNoticeStaysOutOfMachineReadableOutput(t *testing.T) {
	// --json has to stay parseable and --quiet means the exit code is the
	// whole answer. A notice in either would break a caller.
	for _, mode := range []struct {
		name          string
		quiet, asJSON bool
	}{
		{"quiet", true, false},
		{"json", false, true},
	} {
		var out bytes.Buffer
		noticeIfUpdateAvailable(ui.New(&out), mode.quiet, mode.asJSON)

		if out.Len() != 0 {
			t.Errorf("%s mode printed a notice: %q", mode.name, out.String())
		}
	}
}
