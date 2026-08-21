package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/itsmangooo/weedout-cli/internal/settings"
	"github.com/itsmangooo/weedout-cli/internal/ui"
)

// Interactive mode: a menu instead of a memorised command.
//
// Off by default and enabled per installation, because the first thing many
// people do with this tool is put it in a pipeline, and a binary that waits
// for a keypress there hangs a build. Turning it on is a deliberate act, and
// even then the menu never appears when there is no human to read it -- see
// ui.CanPrompt, which refuses in CI and when either stream is a pipe.
//
// The menu offers the commands that are safe to run with no arguments. Adding
// an ignore rule is not one of them: it changes what this project will report
// in future, and something with that much consequence should be typed out with
// its reason rather than reachable by pressing Enter twice.

// runInteractiveSetting handles `weedout --interactive`.
func runInteractiveSetting(argv []string, printer *ui.Printer, stderr io.Writer) int {
	current := settings.Load()

	wanted := true
	if len(argv) > 0 {
		switch strings.ToLower(argv[0]) {
		case "on", "yes", "true", "enable":
			wanted = true
		case "off", "no", "false", "disable":
			wanted = false
		case "status":
			reportInteractive(printer, current)
			return ExitOK
		default:
			fmt.Fprintf(stderr, "Unknown option %q: use on, off, or status.\n", argv[0])
			return ExitError
		}
	}

	current.Interactive = wanted
	if err := current.Save(); err != nil {
		printer.Line(printer.Red("Could not save the setting."))
		printer.Line(printer.Dim("  " + err.Error()))
		// Said plainly rather than left as a puzzle: the usual cause is a
		// binary installed somewhere the user cannot write, and the fix is to
		// move it or run the command with the rights to write there.
		printer.Line(printer.Dim(
			"  Settings live beside the executable, and that directory is not writable."))
		return ExitError
	}

	if wanted {
		printer.Line(printer.Green("Interactive mode is on."))
		printer.Line(printer.Dim("  Run `weedout` with no command to get the menu."))
	} else {
		printer.Line(printer.Green("Interactive mode is off."))
	}
	printer.Line(printer.Dim("  Saved to " + current.Path()))
	if !current.BesideExecutable() {
		// Worth saying. Somebody who asked for the setting to live next to the
		// binary should find out here that it could not, rather than when a
		// second copy of the tool does not share it.
		printer.Line(printer.Dim(
			"  The directory holding the executable is read-only, so this is the fallback location."))
	}
	return ExitOK
}

func reportInteractive(printer *ui.Printer, current settings.Settings) {
	if current.Interactive {
		printer.Line("Interactive mode is on.")
	} else {
		printer.Line("Interactive mode is off.")
	}
	printer.Line(printer.Dim("  Settings file: " + current.Path()))
	if !ui.CanPrompt() {
		printer.Line(printer.Dim(
			"  The menu would not appear here anyway: this is not an interactive terminal."))
	}
}

// menuChoices are the commands reachable from the menu.
var menuChoices = []ui.Choice{
	{Label: "Scan this project", Hint: "check dependencies now", Value: "scan"},
	{Label: "Status", Hint: "counts and when it was last checked", Value: "status"},
	{Label: "Findings", Hint: "what is open, and the fixes", Value: "findings"},
	{Label: "History", Hint: "recent scans and the trend", Value: "history"},
	{Label: "Supply chain", Hint: "signals about the packages", Value: "supply-chain"},
	{Label: "Rules", Hint: "what is reported, and what is not", Value: "rules"},
	{Label: "Check for updates", Hint: "", Value: "update"},
	{Label: "Help", Hint: "", Value: "help"},
}

// runMenu shows the menu and runs what was chosen.
func runMenu(printer *ui.Printer, stdout, stderr io.Writer) int {
	chosen, err := printer.Select("What would you like to do?", menuChoices)
	if err != nil {
		// Backing out is a normal way to leave a menu, not a failure. Exiting
		// non-zero here would make `weedout` in a shell script look broken
		// because somebody pressed Escape.
		printer.Line(printer.Dim("Nothing to do."))
		return ExitOK
	}

	// Routed back through Run rather than calling each handler directly, so
	// the menu can never drift from what the commands actually do.
	return Run([]string{chosen}, stdout, stderr)
}
