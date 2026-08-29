package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/itsmangooo/weedout-cli/internal/api"
	"github.com/itsmangooo/weedout-cli/internal/ui"
)

// The account's rule profiles, and which one this project runs under.
//
// A profile is a named set of scan rules kept on the account, so a team with
// eight services sets its standard once instead of configuring eight projects
// identically and watching them drift.
//
// This command exists mainly to answer two questions a pipeline author has:
// what may I pass to --profile, and what am I running under right now. Both are
// otherwise only visible in the dashboard, which is the wrong place to look
// when you are writing a CI file.
//
// Read scope, not manage. Knowing which rule sets exist is part of
// understanding a result; changing them is not.

func runProfiles(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("profiles", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := addCommonFlags(fs)
	if err := fs.Parse(argv); err != nil {
		return flagErrorExit(err)
	}

	cfg, ok := flags.resolve(printer)
	if !ok {
		return ExitError
	}

	profiles, err := api.GetProfiles(cfg.BaseURL, cfg.APIKey, flags.wait())
	if err != nil {
		return fail(printer, err)
	}

	if *flags.asJSON {
		if err := emit(printer.Writer(), profiles); err != nil {
			fmt.Fprintf(stderr, "Could not encode the result: %v\n", err)
			return ExitError
		}
		return ExitOK
	}

	printProfiles(printer, profiles)
	return ExitOK
}

func printProfiles(printer *ui.Printer, profiles api.Profiles) {
	printer.Line()
	printer.Line("  ", printer.Bold("Rule profiles"))

	if len(profiles.Profiles) == 0 {
		printer.Line("    ", printer.Dim(
			"None yet. Create one in Settings to share one set of rules across projects."))
		printer.Line()
		return
	}

	for _, profile := range profiles.Profiles {
		// Three things can be true of one profile and they mean different
		// things: it is the account default, this project chose it, and it is
		// what a scan here would use. Said separately rather than collapsed
		// into one marker, because "we did not choose, we inherited" is the
		// state most projects are in and the one people misread.
		marks := ""
		if profile.IsDefault {
			marks += "  " + printer.Dim("account default")
		}
		if profile.InUseHere {
			marks += "  " + printer.Green("chosen here")
		}
		printer.Line("    ", printer.Bold(profile.Slug), marks)
		if profile.Description != "" {
			printer.Line("      ", printer.Dim(truncate(profile.Description, 64)))
		}
	}
	printer.Line()

	switch {
	case profiles.AppliesHere == "":
		printer.Line("  ", printer.Dim(
			"This project has no profile, and there is no account default, so scans "+
				"run on the built-in rules."))
	default:
		printer.Line("  ", printer.Dim(fmt.Sprintf(
			"A scan here runs under %s. Pass --profile NAME to use another one.",
			profiles.AppliesHere)))
	}
	printer.Line()
}
