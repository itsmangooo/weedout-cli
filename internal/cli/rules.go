package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/itsmangooo/weedout-cli/internal/api"
	"github.com/itsmangooo/weedout-cli/internal/ui"
)

// Scan rules from the terminal.
//
// These need a key with manage scope, which a CI key does not have. That is the
// point of the split: a key that can add an ignore rule can switch off the
// alert for whatever is about to be exploited, so it must not be the key that
// sits in a build environment where anyone reading a log can take it.
//
// A rule that lives in the repo as .weedout.yml is usually the better answer,
// because it is reviewed like code and travels with the branch. These commands
// report what that file says alongside the rules stored on the server, so the
// two are never mistaken for each other.

func runRules(argv []string, printer *ui.Printer, stderr io.Writer) int {
	if len(argv) == 0 {
		return runRulesList(argv, printer, stderr)
	}

	switch argv[0] {
	case "list":
		return runRulesList(argv[1:], printer, stderr)
	case "ignore", "add":
		return runRulesIgnore(argv[1:], printer, stderr)
	case "unignore", "remove", "rm":
		return runRulesUnignore(argv[1:], printer, stderr)
	default:
		// No subcommand given, so this is flags for the listing.
		if strings.HasPrefix(argv[0], "-") {
			return runRulesList(argv, printer, stderr)
		}
		fmt.Fprintf(stderr, "Unknown rules command %q.\n\n", argv[0])
		rulesUsage(stderr)
		return ExitError
	}
}

func rulesUsage(out io.Writer) {
	fmt.Fprint(out, `weedout rules — what this project reports, and what it does not.

  weedout rules                       list the rules in force
  weedout rules ignore ID --reason R  stop reporting one advisory
  weedout rules unignore ID           report it again

Needs a key with manage access. A CI key cannot change rules.
`)
}

// ---------------------------------------------------------------------------
// rules list
// ---------------------------------------------------------------------------

func runRulesList(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := addCommonFlags(fs)
	if err := fs.Parse(argv); err != nil {
		return ExitError
	}

	cfg, ok := flags.resolve(printer)
	if !ok {
		return ExitError
	}

	rules, err := api.GetRules(cfg.BaseURL, cfg.APIKey, flags.wait())
	if err != nil {
		return fail(printer, err)
	}

	if *flags.asJSON {
		if err := emit(printer.Writer(), rules); err != nil {
			fmt.Fprintf(stderr, "Could not encode the result: %v\n", err)
			return ExitError
		}
		return ExitOK
	}

	printRules(printer, rules)
	return ExitOK
}

func printRules(printer *ui.Printer, rules api.Rules) {
	printer.Line()
	printer.Line("  ", printer.Bold("Alert when"))

	direct := rules.Thresholds.Direct
	if direct == "" {
		direct = "using the default"
	}
	transitive := rules.Thresholds.Transitive
	if transitive == "" {
		transitive = "using the default"
	}
	printer.Line("    ", pad("direct dependency", 24), printer.Dim(direct))
	printer.Line("    ", pad("further down the tree", 24), printer.Dim(transitive))
	if rules.Thresholds.EPSS != nil {
		printer.Line("    ", pad("exploit likelihood", 24), printer.Dim(fmt.Sprintf(
			"at or above %.0f%%", *rules.Thresholds.EPSS)))
	}
	printer.Line()

	printer.Line("  ", printer.Bold("Ignored"))
	if len(rules.Ignores) == 0 {
		printer.Line("    ", printer.Dim("Nothing. Every advisory that matches is reported."))
	}
	for _, ignore := range rules.Ignores {
		printer.Line("    ", printer.Bold(ignore.Identifier), "  ",
			printer.Dim(truncate(ignore.Reason, 56)))

		detail := ignore.CreatedBy
		if detail != "" && ignore.CreatedAt != "" {
			detail += ", " + relative(ignore.CreatedAt)
		}
		if detail != "" {
			printer.Line("      ", printer.Dim(detail))
		}

		if ignore.OverriddenAt != "" {
			// The one case where a rule is not doing what its author expected.
			// Silence they asked for that they are not getting is exactly the
			// thing a listing has to say out loud.
			printer.Line("      ", printer.Yellow(
				"Being reported anyway: this is on the known-exploited list."))
		}
	}
	printer.Line()

	printPolicyFile(printer, rules.PolicyFile)
}

func printPolicyFile(printer *ui.Printer, policy api.PolicyFile) {
	printer.Line("  ", printer.Bold("From the repo"))

	if !policy.Present {
		printer.Line("    ", printer.Dim("No .weedout.yml. Run `weedout init` to write one."))
		printer.Line()
		return
	}

	if policy.Error != "" {
		// A broken file is discarded whole and can only ever produce more
		// alerts, never fewer. Saying so matters: the alternative reading is
		// that half a config took effect, and nobody could tell which half.
		printer.Line("    ", printer.Red("The file could not be read: "+policy.Error))
		printer.Line("    ", printer.Dim(
			"It is being ignored entirely, so nothing in it is filtering anything."))
		printer.Line()
		return
	}

	printer.Line("    ", printer.Dim(fmt.Sprintf(
		".weedout.yml, %d ignore rule(s), read %s",
		len(policy.Ignores), relative(policy.UpdatedAt))))
	for _, id := range policy.Ignores {
		printer.Line("      ", printer.Dim(id))
	}
	printer.Line()
}

// ---------------------------------------------------------------------------
// rules ignore / unignore
// ---------------------------------------------------------------------------

func runRulesIgnore(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules ignore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := addCommonFlags(fs)
	reason := fs.String("reason", "", "why this is being ignored (required)")

	identifier, err := parseWithPath(fs, argv)
	if err != nil {
		return ExitError
	}
	if identifier == "" {
		printer.Line(printer.Red("Which advisory? Pass one, like CVE-2021-23337."))
		return ExitError
	}

	if strings.TrimSpace(*reason) == "" {
		// Required here as well as on the server, so the refusal arrives
		// before the network call and reads like a prompt rather than an
		// error. A rule with no reason is indistinguishable from a mistake
		// when somebody reads it back in six months.
		printer.Line(printer.Red("A reason is required."))
		printer.Line(printer.Dim(fmt.Sprintf(
			"  weedout rules ignore %s --reason \"not reachable from our code\"", identifier)))
		return ExitError
	}

	cfg, ok := flags.resolve(printer)
	if !ok {
		return ExitError
	}

	if err := api.AddIgnore(cfg.BaseURL, cfg.APIKey, identifier, *reason, flags.wait()); err != nil {
		return fail(printer, err)
	}

	printer.Line(printer.Green(identifier + " will no longer be reported for this project."))
	printer.Line(printer.Dim(
		"If it turns up on the known-exploited list, it will be reported again anyway."))
	return ExitOK
}

func runRulesUnignore(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules unignore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := addCommonFlags(fs)

	identifier, err := parseWithPath(fs, argv)
	if err != nil {
		return ExitError
	}
	if identifier == "" {
		printer.Line(printer.Red("Which advisory? Pass one, like CVE-2021-23337."))
		return ExitError
	}

	cfg, ok := flags.resolve(printer)
	if !ok {
		return ExitError
	}

	if err := api.RemoveIgnore(cfg.BaseURL, cfg.APIKey, identifier, flags.wait()); err != nil {
		return fail(printer, err)
	}

	printer.Line(printer.Green(identifier + " is being reported again."))
	return ExitOK
}
