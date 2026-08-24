package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/itsmangooo/weedout-cli/internal/api"
	"github.com/itsmangooo/weedout-cli/internal/config"
	"github.com/itsmangooo/weedout-cli/internal/ui"
)

// The commands that read a project without scanning it.
//
// These exist so the dashboard is optional rather than required. Somebody who
// lives in a terminal should be able to answer "what is wrong with this
// project", "what changed", and "why is that not being reported" without
// opening a browser, and get the same answers.
//
// They all need a key with read scope. A CI key cannot make these calls, which
// is deliberate: the key in a pipeline is the one most likely to leak, so it
// can push a scan and learn nothing else.

// common holds the flags every read command shares.
type common struct {
	apiKey  *string
	baseURL *string
	timeout *int
	asJSON  *bool
}

func addCommonFlags(fs *flag.FlagSet) common {
	return common{
		apiKey:  fs.String("api-key", "", "API key"),
		baseURL: fs.String("url", "", "API base URL"),
		timeout: fs.Int("timeout", 30, "seconds to wait"),
		asJSON:  fs.Bool("json", false, "print JSON instead of prose"),
	}
}

// resolve finds the key and endpoint, or explains what is missing.
//
// The message names the read scope specifically. Somebody trying these
// commands for the first time most likely has a CI key to hand, and telling
// them only "no API key" would send them to paste the one that cannot work.
func (c common) resolve(printer *ui.Printer) (config.Config, bool) {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	cfg := config.Resolve(cwd, *c.apiKey, *c.baseURL, nil)
	if cfg.APIKey == "" {
		printer.Line(printer.Red("No API key."))
		printer.Line(printer.Dim(fmt.Sprintf(
			"Set %s, run `weedout init`, or pass --api-key.", config.EnvAPIKey)))
		printer.Line(printer.Dim(
			"This command needs a key with read access; a CI key can only push scans."))
		return cfg, false
	}
	return cfg, true
}

func (c common) wait() time.Duration { return time.Duration(*c.timeout) * time.Second }

// emit writes a value as indented JSON.
func emit(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// fail prints an API error and returns the exit code for "did not run".
func fail(printer *ui.Printer, err error) int {
	printer.Line(printer.Red(err.Error()))
	return ExitError
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

func runStatus(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := addCommonFlags(fs)
	if err := fs.Parse(argv); err != nil {
		return ExitError
	}

	cfg, ok := flags.resolve(printer)
	if !ok {
		return ExitError
	}

	status, err := api.GetStatus(cfg.BaseURL, cfg.APIKey, flags.wait())
	if err != nil {
		return fail(printer, err)
	}

	if *flags.asJSON {
		if err := emit(printer.Writer(), status); err != nil {
			fmt.Fprintf(stderr, "Could not encode the result: %v\n", err)
			return ExitError
		}
		return ExitOK
	}

	announcePlan(printer, status.Plan, false, false)
	printStatus(printer, status)
	return ExitOK
}

func printStatus(printer *ui.Printer, status api.Status) {
	sep := printer.Symbol("sep")

	printer.Line()
	printer.Line("  ", printer.Bold(status.Project), "  ", printer.Dim(fmt.Sprintf(
		"%s %s %d dependencies", status.Ecosystem, sep, status.Dependencies)))
	printer.Line()

	if status.LastError != "" {
		// Put first. Every number below it was produced by an older scan, and
		// reading them as current would be the wrong conclusion.
		printer.Line("  ", printer.Red("The last check failed: "+status.LastError))
		printer.Line(printer.Dim("  The counts below are from the last scan that finished."))
		printer.Line()
	}

	if status.Open == 0 {
		printer.Line("  ", printer.Green("Nothing to act on."))
	} else {
		printer.Line("  ", printer.Bold(fmt.Sprintf("%d open", status.Open)))
		printer.Line()
		printer.Bars(severityBars(printer, status.Counts))
	}
	printer.Line()

	printer.Line(printer.Dim(fmt.Sprintf(
		"  %d filtered out as noise %s %d dismissed %s %d resolved",
		status.Filtered, sep, status.Dismissed, sep, status.Resolved)))

	if status.UnreachedByDepth > 0 {
		// Said plainly rather than folded into the numbers. These packages were
		// not examined, which is not the same as being examined and found
		// clean, and only one of those is worth reassurance.
		printer.Line(printer.Yellow(fmt.Sprintf(
			"  %d dependencies were not reached at your plan's depth.",
			status.UnreachedByDepth)))
	}

	printer.Line()
	if status.LastScanned != "" {
		printer.Line(printer.Dim("  Last checked  " + relative(status.LastScanned)))
	}
	if status.NextScan != "" {
		printer.Line(printer.Dim("  Next check    " + due(status.NextScan)))
	}
	if status.DashboardURL != "" {
		printer.Line()
		printer.Line(printer.Dim("  " + status.DashboardURL))
	}
	printer.Line()
}

// severityOrder is fixed, so a row never moves because a count changed.
var severityOrder = []string{"malicious", "critical", "high", "medium", "low"}

func severityBars(printer *ui.Printer, counts map[string]int) []ui.Bar {
	colours := map[string]func(string) string{
		"malicious": printer.Red,
		"critical":  printer.Red,
		"high":      printer.Yellow,
		"medium":    printer.Dim,
		"low":       printer.Dim,
	}

	// Every row is drawn, including the empty ones. An absent row would make
	// the reader work out which severities are missing, and "malicious: 0" is
	// the answer to a question worth answering rather than a wasted line.
	var bars []ui.Bar
	for _, name := range severityOrder {
		bars = append(bars, ui.Bar{Label: name, Value: counts[name], Colour: colours[name]})
	}
	return bars
}

// ---------------------------------------------------------------------------
// findings
// ---------------------------------------------------------------------------

func runFindings(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := addCommonFlags(fs)
	show := fs.String("show", "open", "open, filtered, dismissed or resolved")
	limit := fs.Int("limit", 50, "how many to list")
	if err := fs.Parse(argv); err != nil {
		return ExitError
	}

	if !validShow(*show) {
		printer.Line(printer.Red(fmt.Sprintf(
			"Unknown --show value %q: use open, filtered, dismissed or resolved.", *show)))
		return ExitError
	}

	cfg, ok := flags.resolve(printer)
	if !ok {
		return ExitError
	}

	found, err := api.GetFindings(cfg.BaseURL, cfg.APIKey, *show, *limit, flags.wait())
	if err != nil {
		return fail(printer, err)
	}

	if *flags.asJSON {
		if err := emit(printer.Writer(), found); err != nil {
			fmt.Fprintf(stderr, "Could not encode the result: %v\n", err)
			return ExitError
		}
		return ExitOK
	}

	announcePlan(printer, found.Plan, false, false)
	printFindings(printer, found)
	return ExitOK
}

func validShow(show string) bool {
	switch show {
	case "open", "filtered", "dismissed", "resolved":
		return true
	}
	return false
}

func printFindings(printer *ui.Printer, found api.Findings) {
	printer.Line()
	if found.Count == 0 {
		printer.Line("  ", printer.Dim(emptyFor(found.Show)))
		printer.Line()
		return
	}

	for _, finding := range found.Findings {
		printer.Line("  ", printer.Bold(finding.Package+"@"+finding.Version), "  ",
			printer.Dim(finding.CVE))

		var tags []string
		if finding.Malicious {
			tags = append(tags, printer.Red("malicious package"))
		} else {
			tags = append(tags, severityWord(printer, finding.Severity))
		}
		if finding.Exploited {
			tags = append(tags, printer.Red("exploited in the wild"))
		}
		if finding.EPSS != nil {
			tags = append(tags, printer.Dim(fmt.Sprintf("%.0f%% exploit likelihood", *finding.EPSS*100)))
		}
		printer.Line("    ", strings.Join(tags, printer.Dim("  "+printer.Symbol("sep")+"  ")))

		if finding.Summary != "" {
			printer.Line("    ", printer.Dim(truncate(finding.Summary, 72)))
		}
		if finding.Depth > 0 {
			printer.Line("    ", printer.Dim(finding.Chain()))
		}
		if finding.FixedIn != "" {
			printer.Line("    ", printer.Green("Fixed in "+finding.FixedIn))
		} else {
			printer.Line("    ", printer.Dim("No fixed version yet."))
		}
		if finding.Reason != "" && found.Show != "open" {
			printer.Line("    ", printer.Dim("Why it is here: "+finding.Reason))
		}
		printer.Line()
	}

	printer.Line(printer.Dim(fmt.Sprintf("  %d shown.", found.Count)))
	printer.Line()
}

// emptyFor says what an empty tab means, which differs per tab.
func emptyFor(show string) string {
	switch show {
	case "filtered":
		return "Nothing was filtered out. Every advisory that matched was worth reporting."
	case "dismissed":
		return "Nothing dismissed."
	case "resolved":
		return "Nothing resolved yet."
	default:
		return "Nothing to act on."
	}
}

func severityWord(printer *ui.Printer, severity string) string {
	switch severity {
	case "critical":
		return printer.Red("critical")
	case "high":
		return printer.Yellow("high")
	case "unknown":
		return printer.Dim("severity not scored")
	default:
		return printer.Dim(severity)
	}
}

func truncate(text string, width int) string {
	text = strings.Join(strings.Fields(text), " ")
	if len(text) <= width {
		return text
	}
	return text[:width-1] + "…"
}

// ---------------------------------------------------------------------------
// history
// ---------------------------------------------------------------------------

func runHistory(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := addCommonFlags(fs)
	limit := fs.Int("limit", 20, "how many scans to show")
	if err := fs.Parse(argv); err != nil {
		return ExitError
	}

	cfg, ok := flags.resolve(printer)
	if !ok {
		return ExitError
	}

	history, err := api.GetHistory(cfg.BaseURL, cfg.APIKey, *limit, flags.wait())
	if err != nil {
		return fail(printer, err)
	}

	if *flags.asJSON {
		if err := emit(printer.Writer(), history); err != nil {
			fmt.Fprintf(stderr, "Could not encode the result: %v\n", err)
			return ExitError
		}
		return ExitOK
	}

	printHistory(printer, history)
	return ExitOK
}

func printHistory(printer *ui.Printer, history api.History) {
	printer.Line()
	if len(history.Runs) == 0 {
		printer.Line("  ", printer.Dim("No scans yet."))
		printer.Line()
		return
	}

	// The API returns newest first, which is right for a list and wrong for a
	// chart: a series has to read left to right in time order or the shape is
	// backwards.
	//
	// Failed runs are left out entirely rather than plotted at their reported
	// zero. A scan that did not finish found nothing because it did not look,
	// and drawing that as a trough says the opposite -- it reads as the week
	// everything got fixed. They are counted and mentioned below instead.
	series := make([]int, 0, len(history.Runs))
	skipped := 0
	for i := len(history.Runs) - 1; i >= 0; i-- {
		if run := history.Runs[i]; run.Error != "" || run.Status == "failed" {
			skipped++
			continue
		}
		series = append(series, history.Runs[i].Actionable)
	}

	if spark := printer.Spark(series); spark != "" {
		printer.Line("  ", printer.Bold("Open findings per scan"), "   ",
			printer.Dim("oldest to newest, "+ui.Range(series)))
		printer.Line("  ", spark)
		if skipped > 0 {
			printer.Line("  ", printer.Dim(fmt.Sprintf(
				"%s not charted: %d scan(s) did not finish.", printer.Symbol("sep"), skipped)))
		}
		printer.Line()
	}

	for _, run := range history.Runs {
		when := relative(run.StartedAt)

		if run.Error != "" {
			printer.Line("  ", printer.Red("failed"), "  ", printer.Dim(when))
			printer.Line("    ", printer.Dim(truncate(run.Error, 72)))
			continue
		}

		line := fmt.Sprintf("%d open, %d filtered out", run.Actionable, run.Suppressed)
		var changes []string
		if run.New > 0 {
			changes = append(changes, printer.Yellow(fmt.Sprintf("+%d new", run.New)))
		}
		if run.Resolved > 0 {
			changes = append(changes, printer.Green(fmt.Sprintf("-%d resolved", run.Resolved)))
		}

		row := "  " + printer.Dim(pad(when, 18)) + line
		if len(changes) > 0 {
			row += "  " + strings.Join(changes, " ")
		}
		printer.Line(row)
	}
	printer.Line()
}

func pad(text string, width int) string {
	if len(text) >= width {
		return text
	}
	return text + strings.Repeat(" ", width-len(text))
}

// ---------------------------------------------------------------------------
// supply-chain
// ---------------------------------------------------------------------------

func runSupplyChain(argv []string, printer *ui.Printer, stderr io.Writer) int {
	fs := flag.NewFlagSet("supply-chain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := addCommonFlags(fs)
	if err := fs.Parse(argv); err != nil {
		return ExitError
	}

	cfg, ok := flags.resolve(printer)
	if !ok {
		return ExitError
	}

	chain, err := api.GetSupplyChain(cfg.BaseURL, cfg.APIKey, flags.wait())
	if err != nil {
		return fail(printer, err)
	}

	if *flags.asJSON {
		if err := emit(printer.Writer(), chain); err != nil {
			fmt.Fprintf(stderr, "Could not encode the result: %v\n", err)
			return ExitError
		}
		return ExitOK
	}

	printSupplyChain(printer, chain)
	return ExitOK
}

// levelRank orders signals by how much attention they deserve. The words are
// deliberately not severity words: none of these is a vulnerability, and
// borrowing "critical" for "one maintainer" would cheapen the real ones.
var levelRank = map[string]int{"concerning": 0, "notable": 1, "informational": 2}

func printSupplyChain(printer *ui.Printer, chain api.SupplyChain) {
	printer.Line()
	if len(chain.Signals) == 0 {
		printer.Line("  ", printer.Dim("No signals. Nothing stood out about these packages."))
		printer.Line()
		return
	}

	signals := append([]api.Signal{}, chain.Signals...)
	sort.SliceStable(signals, func(i, j int) bool {
		return levelRank[signals[i].Level] < levelRank[signals[j].Level]
	})

	for _, signal := range signals {
		name := signal.Package
		if signal.Version != "" {
			name += "@" + signal.Version
		}

		label := signal.Label
		switch signal.Level {
		case "concerning":
			label = printer.Red(label)
		case "notable":
			label = printer.Yellow(label)
		default:
			label = printer.Dim(label)
		}

		printer.Line("  ", printer.Bold(name), "  ", label)
		if signal.Detail != "" {
			printer.Line("    ", printer.Dim(truncate(signal.Detail, 72)))
		}
	}

	printer.Line()
	printer.Line(printer.Dim(
		"  These are context, not vulnerabilities. Nothing here is a reason to act on its own."))
	printer.Line()
}

// ---------------------------------------------------------------------------
// Time, said the way a person would
// ---------------------------------------------------------------------------

// relative turns an ISO timestamp into a phrase.
//
// Both directions matter: this renders "last checked" and "next check" from the
// same helper, and a next check rendered as "3 hours ago" would be a bug the
// reader has to work out rather than notice.
func relative(iso string) string {
	when, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		return iso
	}

	delta := time.Since(when)
	future := delta < 0
	if future {
		delta = -delta
	}

	phrase := ""
	switch {
	case delta < time.Minute:
		return "just now"
	case delta < time.Hour:
		phrase = plural(int(delta.Minutes()), "minute")
	case delta < 24*time.Hour:
		phrase = plural(int(delta.Hours()), "hour")
	default:
		phrase = plural(int(delta.Hours()/24), "day")
	}

	if future {
		return "in " + phrase
	}
	return phrase + " ago"
}

// due renders when the next check is expected.
//
// Separate from relative() because a scheduled time that has already passed is
// not "8 hours ago" -- that reads as a check that happened. It means the check
// is late, which is a different thing and worth naming, since a project whose
// scans have quietly stopped looks identical to one with nothing to report.
func due(iso string) string {
	when, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		return iso
	}
	if overdue := time.Since(when); overdue > 0 {
		if overdue < time.Hour {
			return "due now"
		}
		return "overdue by " + strings.TrimSuffix(relative(iso), " ago")
	}
	return relative(iso)
}

func plural(count int, unit string) string {
	if count == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", count, unit)
}
