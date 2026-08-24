// Package cli wires the commands together.
//
// Exit codes are the contract with CI, and there are three of them:
//
//	0  the scan ran and nothing is blocking
//	1  the scan ran and found something blocking (--ci only)
//	2  the scan did not run — bad key, unreachable service, no file
//
// The separation between 1 and 2 is the important one. A pipeline that treats
// every non-zero exit as "vulnerabilities found" will eventually treat an
// expired API key as a security finding, and someone will "fix" it by removing
// the step. Without --ci a finding is reported but does not fail the command,
// so adding the tool to a pipeline is never the thing that breaks the build
// first.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/itsmangooo/weedout-cli/internal/api"
	"github.com/itsmangooo/weedout-cli/internal/config"
	"github.com/itsmangooo/weedout-cli/internal/detect"
	"github.com/itsmangooo/weedout-cli/internal/settings"
	"github.com/itsmangooo/weedout-cli/internal/ui"
)

// Exit codes.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitError    = 2
)

// Version is stamped at build time with -ldflags. The fallback marks a binary
// built straight from source, so a bug report can say which it was.
var Version = "dev"

// Run executes one invocation and returns the process exit code.
func Run(argv []string, stdout, stderr io.Writer) int {
	printer := ui.New(stdout)

	if len(argv) == 0 {
		// A bare `weedout` shows the menu only if this installation asked for
		// it and there is somebody there to use it. Both halves matter: the
		// setting alone would hang a pipeline, and a terminal alone would
		// surprise everyone who never opted in.
		if settings.Load().Interactive && ui.CanPrompt() {
			return runMenu(printer, stdout, stderr)
		}
		usage(stdout)
		return ExitError
	}

	switch argv[0] {
	case "scan":
		return runScan(argv[1:], printer, stderr)
	case "init":
		return runInit(argv[1:], printer, stderr)
	case "status":
		return runStatus(argv[1:], printer, stderr)
	case "findings":
		return runFindings(argv[1:], printer, stderr)
	case "history":
		return runHistory(argv[1:], printer, stderr)
	case "supply-chain", "signals":
		return runSupplyChain(argv[1:], printer, stderr)
	case "auth", "login":
		return runAuth(argv[1:], printer, stderr)
	case "logout":
		return runLogout(argv[1:], printer, stderr)
	case "whoami":
		return runWhoami(argv[1:], printer, stderr)
	case "link":
		return runLink(argv[1:], printer, stderr)
	case "create":
		return runCreate(argv[1:], printer, stderr)
	case "unlink":
		return runUnlink(argv[1:], printer, stderr)
	case "key", "keys":
		return runKey(argv[1:], printer, stderr)
	case "profiles", "profile":
		return runProfiles(argv[1:], printer, stderr)
	case "rules":
		return runRules(argv[1:], printer, stderr)
	case "--interactive", "-i", "interactive":
		return runInteractiveSetting(argv[1:], printer, stderr)
	case "update", "upgrade", "self-update":
		return runUpdate(argv[1:], printer, stderr)
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "weedout %s\n", Version)
		return ExitOK
	case "help", "--help", "-h":
		usage(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "Unknown command %q.\n\n", argv[0])
		usage(stderr)
		return ExitError
	}
}

func usage(out io.Writer) {
	fmt.Fprint(out, `weedout — scan your dependencies for the CVEs that actually matter.

  weedout auth             sign this machine in, by confirming in a browser
  weedout create [name]    make a project here and save a key for it
  weedout link             connect this directory to a project you already have
  weedout scan [path]      scan a project (default: current directory)
  weedout whoami           which account, and what this directory is linked to
  weedout version          print the version
  weedout --interactive    turn the menu on for this installation
  weedout update           install the newest release

Managing this machine:
  weedout logout           forget the credential here (--all drops project keys)
  weedout unlink           forget which project this directory belongs to
  weedout key regenerate   replace this directory's key with a fresh one
  weedout init [path]      write a `+config.Filename+` file, for CI or a shared box

Read your project without scanning it (needs a key with read access):
  weedout status           counts, last check, next check
  weedout findings         what is open, with fixes and how it got in
  weedout history          recent scans and how the count has moved
  weedout supply-chain     signals about the packages themselves
  weedout profiles         the account's rule profiles, and which applies here

Change what gets reported (needs a key with manage access):
  weedout rules                        list the rules in force
  weedout rules ignore ID --reason R   stop reporting one advisory
  weedout rules ignore --package P --reason R
                                       stop reporting a family of packages
  weedout rules unignore ID            report it again

Scan flags:
  --ci                     exit 1 if anything at or above --fail-on is found
  --fail-on LEVEL          critical (default) or high
  --json                   print the result as JSON instead of prose
  -q, --quiet              print nothing; the exit code is the answer
  --api-key KEY            overrides $`+config.EnvAPIKey+`
  --url URL                API base URL (default: `+config.DefaultBaseURL+`)
  --timeout SECONDS        how long to wait (default: 120)
  --profile NAME           scan under one of the account's rule profiles
  -v, --verbose            show what was chosen and why

Flags shared by the reading commands:
  --json                   print JSON instead of prose
  --api-key KEY            overrides $`+config.EnvAPIKey+`
  --url URL                API base URL
  --timeout SECONDS        how long to wait (default: 30)

Exit codes:
  0  ran, nothing blocking
  1  ran, found something blocking (--ci only)
  2  did not run — bad key, unreachable service, or no manifest
`)
}

func runScan(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ci := fs.Bool("ci", false, "exit 1 on findings at or above --fail-on")
	failOn := fs.String("fail-on", "critical", "severity floor for --ci: critical or high")
	asJSON := fs.Bool("json", false, "print the result as JSON instead of prose")
	quiet := fs.Bool("quiet", false, "print nothing; the exit code is the answer")
	fs.BoolVar(quiet, "q", false, "print nothing; the exit code is the answer")
	apiKey := fs.String("api-key", "", "API key")
	baseURL := fs.String("url", "", "API base URL")
	timeout := fs.Int("timeout", 120, "seconds to wait")
	verbose := fs.Bool("verbose", false, "explain what was chosen")
	fs.BoolVar(verbose, "v", false, "explain what was chosen")
	profile := fs.String("profile", "", "which rule profile to scan under")

	// Flags may come before or after the path, which is what people expect.
	path, err := parseWithPath(fs, argv)
	if err != nil {
		return ExitError
	}
	if path == "" {
		path = "."
	}

	// Checked before the scan rather than after. A typo in --fail-on must not
	// cost a minute of CI and then report a threshold nobody asked for.
	threshold, err := api.ParseThreshold(*failOn)
	if err != nil {
		printer.Line(printer.Red(err.Error()))
		return ExitError
	}

	root, err := filepath.Abs(path)
	if err != nil {
		printer.Line(printer.Red(fmt.Sprintf("Bad path: %v", err)))
		return ExitError
	}
	info, err := os.Stat(root)
	if err != nil {
		printer.Line(printer.Red(fmt.Sprintf("No such path: %s", root)))
		return ExitError
	}

	var manifest string
	searchRoot := root
	if info.IsDir() {
		match, found, err := detect.Find(root)
		if err != nil {
			printer.Line(printer.Red(fmt.Sprintf("Could not search %s: %v", root, err)))
			return ExitError
		}
		if !found {
			reportNothingFound(printer, root)
			return ExitError
		}
		manifest = match.Path
	} else {
		manifest = root
		searchRoot = filepath.Dir(root)
	}

	cfg := config.Resolve(searchRoot, *apiKey, *baseURL, nil)
	if cfg.APIKey == "" {
		printer.Line(printer.Red("No API key."))
		printer.Line(printer.Dim(fmt.Sprintf(
			"Set %s, run `weedout init`, or pass --api-key. Create a key in Settings on your dashboard.",
			config.EnvAPIKey)))
		return ExitError
	}

	// Rules that live in the repository, sent with the scan. The server never
	// sees the checkout, so a .weedout.yml nobody uploads is a file that does
	// nothing -- which is what it was until this looked for one.
	policyPath, hasPolicy := config.FindPolicyFile(searchRoot)

	if *verbose {
		printer.Line(printer.Dim("Scanning " + manifest))
		printer.Line(printer.Dim("Key from " + cfg.KeySource))
		printer.Line(printer.Dim("Endpoint " + cfg.BaseURL))
		if hasPolicy {
			printer.Line(printer.Dim("Rules from " + policyPath))
		} else {
			printer.Line(printer.Dim("No " + config.PolicyFilename + " found"))
		}
		if *profile != "" {
			printer.Line(printer.Dim("Profile " + *profile))
		}
	}

	result, err := api.PostScanRequest(cfg.BaseURL, cfg.APIKey, api.ScanRequest{
		ManifestPath: manifest,
		PolicyPath:   policyPath,
		Profile:      *profile,
	}, time.Duration(*timeout)*time.Second)
	if err != nil {
		printer.Line(printer.Red(err.Error()))
		// Always 2. A scan that could not run is not a scan that found nothing,
		// and a pipeline has to be able to tell those apart.
		return ExitError
	}

	blocking := result.BlockingAt(threshold)

	// --quiet means the exit code is the whole answer. Useful in a pipeline
	// step that only gates, and in a pre-commit hook where the scan is not the
	// thing the developer is looking at. Errors still go to stderr: silencing
	// "your key was rejected" would turn a broken setup into a passing build.
	if *quiet {
		if *ci && blocking > 0 {
			return ExitFindings
		}
		return ExitOK
	}

	if *asJSON {
		// The whole result, plus what this invocation decided about it. A
		// caller parsing this should not have to re-implement the threshold
		// rule to find out whether the build is failing.
		if err := writeJSON(printer.Writer(), result, threshold, blocking, *ci); err != nil {
			fmt.Fprintf(stderr, "Could not encode the result: %v\n", err)
			return ExitError
		}
	} else {
		report(printer, result, manifest, threshold)
	}

	if *ci && blocking > 0 {
		if !*asJSON {
			printer.Line(printer.Red(fmt.Sprintf(
				"Failing: %d finding(s) %s.", blocking, thresholdPhrase(threshold))))
			noticeIfUpdateAvailable(printer, *quiet, *asJSON)
		}
		return ExitFindings
	}

	noticeIfUpdateAvailable(printer, *quiet, *asJSON)
	return ExitOK
}

// thresholdPhrase names what was failed on, in words rather than a flag value.
func thresholdPhrase(t api.Threshold) string {
	if t == api.ThresholdHigh {
		return "at high severity or above, or confirmed exploited"
	}
	return "at critical severity or confirmed exploitation"
}

// jsonReport is the machine-readable shape.
//
// A wrapper around the server's result rather than the result itself: the
// decision (`failing`, `blocking`, `fail_on`) belongs to this invocation, not
// to the scan, and flattening the two would make it impossible to tell a
// server field from a client one.
type jsonReport struct {
	api.Result
	FailOn   string `json:"fail_on"`
	Blocking int    `json:"blocking"`
	Failing  bool   `json:"failing"`
}

func writeJSON(out io.Writer, result api.Result, t api.Threshold, blocking int, ci bool) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(jsonReport{
		Result:   result,
		FailOn:   string(t),
		Blocking: blocking,
		// Only --ci turns findings into a failure, so this reports what the
		// exit code is about to be rather than what it might have been.
		Failing: ci && blocking > 0,
	})
}

// reportNothingFound names any lockfile that is present but unreadable by the
// API, rather than leaving the user to guess why their yarn project found
// nothing.
func reportNothingFound(printer *ui.Printer, root string) {
	printer.Line(printer.Red(fmt.Sprintf("No manifest found in %s.", root)))

	if present := detect.FindUnsupported(root); len(present) > 0 {
		names := make([]string, 0, len(present))
		for name := range present {
			names = append(names, name)
		}
		sort.Strings(names)
		printer.Line()
		for _, name := range names {
			printer.Line(printer.Yellow(fmt.Sprintf(
				"  Found %s, which Weedout cannot read yet. Point it at %s instead.",
				name, present[name])))
		}
	}

	printer.Line(printer.Dim("Looked for: " + detect.SupportedNames()))
}

func runInit(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apiKey := fs.String("api-key", "", "API key")
	baseURL := fs.String("url", "", "API base URL")
	force := fs.Bool("force", false, "overwrite an existing file")

	path, err := parseWithPath(fs, argv)
	if err != nil {
		return ExitError
	}
	if path == "" {
		path = "."
	}

	root, err := filepath.Abs(path)
	if err != nil {
		printer.Line(printer.Red(fmt.Sprintf("Bad path: %v", err)))
		return ExitError
	}
	target := filepath.Join(root, config.Filename)

	if _, err := os.Stat(target); err == nil && !*force {
		printer.Line(printer.Yellow(target + " already exists. Pass --force to overwrite."))
		return ExitError
	}

	key := *apiKey
	if key == "" {
		key = os.Getenv(config.EnvAPIKey)
	}
	if key == "" {
		key = prompt(printer, "API key: ")
	}
	if key == "" {
		printer.Line(printer.Red("No API key to write."))
		printer.Line(printer.Dim(fmt.Sprintf(
			"Pass --api-key, or set %s and run this again.", config.EnvAPIKey)))
		return ExitError
	}

	if err := config.Write(target, key, *baseURL); err != nil {
		printer.Line(printer.Red(fmt.Sprintf("Could not write %s: %v", target, err)))
		return ExitError
	}
	printer.Line("Wrote " + target)

	if match, found, _ := detect.Find(root); found {
		if rel, err := filepath.Rel(root, match.Path); err == nil {
			printer.Line(printer.Dim("Will scan " + rel))
		}
	} else {
		printer.Line(printer.Yellow("No manifest found here yet. Looked for: " + detect.SupportedNames()))
	}

	printer.Line()
	printer.Line(printer.Yellow("This file contains a credential. Add it to .gitignore."))
	return ExitOK
}

// prompt reads one line from the terminal.
//
// Deliberately not hidden input: an API key is not a password, it is pasted
// from a dashboard, and hiding it means people cannot see they pasted the
// wrong thing. The warning about .gitignore is the control that matters.
func prompt(printer *ui.Printer, label string) string {
	fmt.Print(label)
	var line string
	if _, err := fmt.Fscanln(os.Stdin, &line); err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

// parseWithPath parses flags that may appear either side of the path.
//
// Go's flag package stops at the first non-flag argument, so `weedout scan
// ./app --ci` would leave --ci unparsed. Calling Parse repeatedly over what is
// left is the standard way to allow interspersed arguments.
//
// This replaced a hand-written splitter that kept a list of which flags take a
// value. That list was a standing bug: adding a flag and forgetting to list it
// meant its value was silently taken as the path, and `weedout scan --fail-on
// high` would have scanned a directory called "high". The flag set already
// knows which flags take values, so asking it is both shorter and impossible
// to get out of step.
func parseWithPath(fs *flag.FlagSet, argv []string) (string, error) {
	var path string
	rest := argv

	for {
		if err := fs.Parse(rest); err != nil {
			return "", err
		}
		if fs.NArg() == 0 {
			return path, nil
		}
		if path == "" {
			path = fs.Arg(0)
		}
		rest = fs.Args()[1:]
	}
}

// report prints the result: counts first, then the findings worth acting on,
// then the link.
//
// The suppressed count is shown deliberately. The number this product is proud
// of is not how much it found, it is how much it decided not to interrupt
// anyone about.
func report(printer *ui.Printer, result api.Result, manifest string, threshold api.Threshold) {
	name := result.Project
	if name == "" {
		name = filepath.Base(manifest)
	}

	printer.Line()
	printer.Line(printer.Bold(name), "  ", printer.Dim(manifest))
	printer.Line(printer.Dim(fmt.Sprintf(
		"%d dependencies scanned %s %d filtered out as noise",
		result.DependenciesScanned, printer.Symbol("sep"), result.Suppressed)))
	printer.Line()

	if result.Actionable == 0 {
		printer.Line(printer.Green("  Nothing to act on."))
	} else {
		var parts []string
		if n := result.Malicious(); n > 0 {
			parts = append(parts, printer.Red(fmt.Sprintf("%d malicious", n)))
		}
		if n := result.Exploited(); n > 0 {
			parts = append(parts, printer.Red(fmt.Sprintf("%d exploited", n)))
		}
		if n := result.Critical(); n > 0 {
			parts = append(parts, printer.Red(fmt.Sprintf("%d critical", n)))
		}
		for _, label := range []string{"high", "medium", "low"} {
			if n := result.Counts[label]; n > 0 {
				parts = append(parts, printer.Yellow(fmt.Sprintf("%d %s", n, label)))
			}
		}
		printer.Line("  " + strings.Join(parts, "  "+printer.Symbol("sep")+"  "))
	}

	if len(result.Findings) > 0 {
		printer.Line()
		for _, f := range result.Findings {
			marker := printer.Yellow(printer.Symbol("bullet"))
			if f.Exploited || f.Malicious {
				marker = printer.Red(printer.Symbol("alert"))
			}
			fix := printer.Dim("no fix yet")
			if f.Malicious {
				// Never "upgrade": a later release of a malicious package is
				// just newer malware.
				fix = printer.Red("remove it")
			} else if f.FixedIn != "" {
				fix = printer.Green(printer.Symbol("arrow") + " " + f.FixedIn)
			}
			printer.Line(fmt.Sprintf("  %s %s@%s  %s  %s",
				marker, f.Package, f.Version, printer.Dim(f.CVE), fix))
		}
	}

	for _, warning := range result.Warnings {
		printer.Line()
		printer.Line(printer.Yellow("  Note: " + warning))
	}

	if result.DashboardURL != "" {
		printer.Line()
		printer.Line(printer.Dim("  " + result.DashboardURL))
	}
	printer.Line()
}
