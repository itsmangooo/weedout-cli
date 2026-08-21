package cli

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/itsmangooo/weedout-cli/internal/selfupdate"
	"github.com/itsmangooo/weedout-cli/internal/settings"
	"github.com/itsmangooo/weedout-cli/internal/ui"
)

// Updating the binary.
//
// Two entry points with deliberately different manners. `weedout update` is
// somebody asking, and it may replace the binary. The passive notice is the
// tool volunteering, and it may only print one line -- it never downloads
// anything and never asks a question, because the moment a scan starts
// prompting about unrelated things is the moment people stop reading what it
// says.

const (
	// updateTimeout bounds the whole exchange. Generous, because it covers a
	// multi-megabyte download on a poor connection.
	updateTimeout = 120 * time.Second

	// checkTimeout bounds the passive check, which is one small API call and
	// must never be the reason a scan feels slow.
	checkTimeout = 5 * time.Second

	// checkInterval is how often the passive check goes to the network.
	// Daily: often enough that nobody runs months behind, rare enough that it
	// is not a request per invocation.
	checkInterval = 24 * time.Hour
)

func runUpdate(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	checkOnly := fs.Bool("check", false, "report whether an update exists, install nothing")
	assumeYes := fs.Bool("yes", false, "install without asking")
	fs.BoolVar(assumeYes, "y", false, "install without asking")
	if err := fs.Parse(argv); err != nil {
		return ExitError
	}

	current := settings.Load()

	printer.Line(printer.Dim("Checking for updates…"))
	update, available, err := selfupdate.Check(Version, checkTimeout)
	if err != nil {
		printer.Line(printer.Red("Could not check for updates."))
		printer.Line(printer.Dim("  " + err.Error()))
		return ExitError
	}

	// Remember what was seen either way, so the passive notice has something
	// to print without going to the network.
	current.LastUpdateCheck = time.Now()
	current.LatestSeen = update.Latest.String()
	_ = current.Save() // Unwritable settings must not fail an update.

	if !available {
		if update.Current.Development() {
			printer.Line("This is a development build (" + Version + ").")
			printer.Line(printer.Dim(
				"  Built from source rather than installed from a release, so there is " +
					"nothing to update it to."))
			return ExitOK
		}
		printer.Line(printer.Green("Already up to date (" + Version + ")."))
		return ExitOK
	}

	printer.Line()
	printer.Line("  ", printer.Bold(update.Current.String()+" "+printer.Symbol("arrow")+" "+update.Latest.String()))
	if update.NotesURL() != "" {
		printer.Line(printer.Dim("  Release notes: " + update.NotesURL()))
	}
	printer.Line()

	if *checkOnly {
		printer.Line(printer.Dim("  Run `weedout update` to install it."))
		return ExitOK
	}

	if !*assumeYes {
		if !ui.CanPrompt() {
			// Reached by a script or a pipeline. Refusing rather than assuming
			// consent: replacing a binary is not something to do because
			// nobody was there to object.
			printer.Line(printer.Yellow("  Not installing: there is nobody here to confirm it."))
			printer.Line(printer.Dim("  Pass --yes to install without asking."))
			return ExitOK
		}
		if !printer.Confirm(fmt.Sprintf("Replace this binary with %s?", update.Latest)) {
			printer.Line(printer.Dim("  Left alone."))
			return ExitOK
		}
	}

	if ui.InCI() {
		// Allowed with --yes, because somebody may genuinely be scripting an
		// upgrade step, but said out loud. A pipeline that silently changes
		// its scanner version between runs is no longer reproducible, and a
		// pinned version is almost always what a build actually wants.
		printer.Line(printer.Yellow(
			"  Updating inside CI. Pin a version instead if you want reproducible builds."))
	}

	printer.Line(printer.Dim("  Downloading " + update.AssetName + "…"))
	if err := update.Install(updateTimeout); err != nil {
		printer.Line(printer.Red("The update failed."))
		printer.Line(printer.Dim("  " + err.Error()))
		return ExitError
	}

	printer.Line(printer.Green("Updated to " + update.Latest.String() + "."))
	return ExitOK
}

// noticeIfUpdateAvailable prints at most one dim line about a newer release.
//
// Called after a command has finished printing its own output, so it can never
// delay or bury the answer somebody actually asked for. Every condition below
// is a reason not to speak up, and there are more of them than there are
// reasons to.
func noticeIfUpdateAvailable(printer *ui.Printer, quiet, asJSON bool) {
	if quiet || asJSON {
		// --json output must stay parseable, and --quiet means the exit code
		// is the whole answer.
		return
	}
	if !ui.CanPrompt() {
		// Not a terminal, or CI. Nobody is going to act on this, and in a
		// build log it is noise that makes the real output harder to find.
		return
	}

	current := settings.Load()
	if !current.UpdateChecks {
		return
	}

	running, ok := selfupdate.ParseVersion(Version)
	if !ok {
		return // A development build has nothing to be behind.
	}

	if time.Since(current.LastUpdateCheck) > checkInterval {
		// Due a look. Failure is silent: an update check is not worth a word
		// of a scan's output, let alone an error.
		update, available, err := selfupdate.Check(Version, checkTimeout)
		if err == nil {
			current.LastUpdateCheck = time.Now()
			if available {
				current.LatestSeen = update.Latest.String()
			} else if update.Latest.Raw != "" {
				current.LatestSeen = update.Latest.String()
			}
			_ = current.Save()
		}
	}

	latest, ok := selfupdate.ParseVersion(current.LatestSeen)
	if !ok || !latest.NewerThan(running) {
		return
	}

	printer.Line()
	printer.Line(printer.Dim(fmt.Sprintf(
		"  %s is available (you have %s). Run `weedout update`.",
		latest.String(), running.String())))
}
