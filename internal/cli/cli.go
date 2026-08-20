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
		usage(stdout)
		return ExitError
	}

	switch argv[0] {
	case "scan":
		return runScan(argv[1:], printer, stderr)
	case "init":
		return runInit(argv[1:], printer, stderr)
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

  weedout scan [path]      scan a project (default: current directory)
  weedout init [path]      write a `+config.Filename+` config file
  weedout version          print the version

Scan flags:
  --ci                     exit 1 if anything at or above --fail-on is found
  --fail-on LEVEL          critical (default) or high
  --json                   print the result as JSON instead of prose
  --api-key KEY            overrides $`+config.EnvAPIKey+`
  --url URL                API base URL (default: `+config.DefaultBaseURL+`)
  --timeout SECONDS        how long to wait (default: 120)
  -v, --verbose            show what was chosen and why

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
	apiKey := fs.String("api-key", "", "API key")
	baseURL := fs.String("url", "", "API base URL")
	timeout := fs.Int("timeout", 120, "seconds to wait")
	verbose := fs.Bool("verbose", false, "explain what was chosen")
	fs.BoolVar(verbose, "v", false, "explain what was chosen")

	// Flags may come before or after the path, which is what people expect.
	path, rest := splitPath(argv)
	if err := fs.Parse(rest); err != nil {
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

	if *verbose {
		printer.Line(printer.Dim("Scanning " + manifest))
		printer.Line(printer.Dim("Key from " + cfg.KeySource))
		printer.Line(printer.Dim("Endpoint " + cfg.BaseURL))
	}

	result, err := api.PostScan(cfg.BaseURL, cfg.APIKey, manifest, time.Duration(*timeout)*time.Second)
	if err != nil {
		printer.Line(printer.Red(err.Error()))
		// Always 2. A scan that could not run is not a scan that found nothing,
		// and a pipeline has to be able to tell those apart.
		return ExitError
	}

	blocking := result.BlockingAt(threshold)

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
		}
		return ExitFindings
	}
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

	path, rest := splitPath(argv)
	if err := fs.Parse(rest); err != nil {
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

// splitPath separates a leading positional argument from the flags, so that
// both `weedout scan ./app --ci` and `weedout scan --ci ./app` work.
func splitPath(argv []string) (string, []string) {
	var path string
	rest := make([]string, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if strings.HasPrefix(arg, "-") {
			rest = append(rest, arg)
			// Flags that take a value, when written as `--flag value`.
			if !strings.Contains(arg, "=") && takesValue(arg) && i+1 < len(argv) {
				i++
				rest = append(rest, argv[i])
			}
			continue
		}
		if path == "" {
			path = arg
			continue
		}
		rest = append(rest, arg)
	}
	return path, rest
}

func takesValue(flagArg string) bool {
	switch strings.TrimLeft(flagArg, "-") {
	case "api-key", "url", "timeout", "fail-on":
		return true
	}
	return false
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
			if f.Exploited {
				marker = printer.Red(printer.Symbol("alert"))
			}
			fix := printer.Dim("no fix yet")
			if f.FixedIn != "" {
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
