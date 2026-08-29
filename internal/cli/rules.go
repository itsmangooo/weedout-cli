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

  weedout rules                             list the rules in force
  weedout rules ignore ID --reason R        stop reporting one advisory
  weedout rules ignore --package P --reason R
                                            stop reporting a family of packages
  weedout rules unignore ID                 report it again

A package rule takes a glob: --package "@acme/*" covers every advisory written
about anything in that scope, including ones published after you write it. Quote
it, or your shell will expand it against the working directory.

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
		return flagErrorExit(err)
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
		suffix := ""
		if ignore.Kind == "package" {
			// Said out loud, because the two read very differently. An id
			// names one advisory; a glob names a family of packages and every
			// advisory that will ever be written about them.
			suffix = "  " + printer.Dim("(every advisory)")
		}
		printer.Line("    ", printer.Bold(ignore.Identifier), suffix, "  ",
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
		// Not `weedout init` -- that writes .weedout, which holds the key.
		// Pointing somebody at the wrong file here is how a credential ends up
		// committed.
		printer.Line("    ", printer.Dim(
			"No .weedout.yml. Write one beside your lockfile and commit it; "+
				"the next scan sends it."))
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
		len(policy.Ignores)+len(policy.IgnoredPackages), relative(policy.UpdatedAt))))
	for _, id := range policy.Ignores {
		printer.Line("      ", printer.Dim(id))
	}
	for _, pattern := range policy.IgnoredPackages {
		printer.Line("      ", printer.Dim(pattern+"  (every advisory)"))
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
	pkg := fs.String("package", "", "a package name or glob, instead of an advisory id")

	positional, err := parseWithPath(fs, argv)
	if err != nil {
		return ExitError
	}

	identifier, kind, ok := ignoreSubject(positional, *pkg, printer)
	if !ok {
		return ExitError
	}

	if strings.TrimSpace(*reason) == "" {
		// Required here as well as on the server, so the refusal arrives
		// before the network call and reads like a prompt rather than an
		// error. A rule with no reason is indistinguishable from a mistake
		// when somebody reads it back in six months.
		printer.Line(printer.Red("A reason is required."))
		printer.Line(printer.Dim(ignoreExample(identifier, kind)))
		return ExitError
	}

	cfg, ok := flags.resolve(printer)
	if !ok {
		return ExitError
	}

	err = api.AddIgnore(cfg.BaseURL, cfg.APIKey, identifier, kind, *reason, flags.wait())
	if err != nil {
		return fail(printer, err)
	}

	if kind == "package" {
		printer.Line(printer.Green(
			"Advisories about " + identifier + " will no longer be reported for this project."))
	} else {
		printer.Line(printer.Green(identifier + " will no longer be reported for this project."))
	}
	printer.Line(printer.Dim(
		"Anything on the known-exploited list, or flagged as malware, is reported anyway."))
	return ExitOK
}

// ignoreSubject decides what this rule is about, and refuses the ambiguous case.
//
// Passing both an id and --package has no single reading, and guessing would
// silence something the caller did not ask to silence.
func ignoreSubject(positional, pkg string, printer *ui.Printer) (string, string, bool) {
	pattern := strings.TrimSpace(pkg)

	switch {
	case positional != "" && pattern != "":
		printer.Line(printer.Red("Pass an advisory id or --package, not both."))
		return "", "", false
	case pattern != "":
		return pattern, "package", true
	case positional != "":
		return positional, "advisory", true
	default:
		printer.Line(printer.Red("Which advisory? Pass one, like CVE-2021-23337."))
		printer.Line(printer.Dim(
			"  Or --package \"@acme/*\" to cover a family of packages."))
		return "", "", false
	}
}

func ignoreExample(identifier, kind string) string {
	if kind == "package" {
		return fmt.Sprintf(
			"  weedout rules ignore --package %q --reason \"internal mirror of a public name\"",
			identifier)
	}
	return fmt.Sprintf(
		"  weedout rules ignore %s --reason \"not reachable from our code\"", identifier)
}

func runRulesUnignore(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules unignore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := addCommonFlags(fs)
	pkg := fs.String("package", "", "a package name or glob, instead of an advisory id")

	positional, err := parseWithPath(fs, argv)
	if err != nil {
		return ExitError
	}

	// The server removes a rule by what it names, whichever kind it is, so
	// --package is accepted here only for symmetry with `ignore`.
	identifier, _, ok := ignoreSubject(positional, *pkg, printer)
	if !ok {
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
