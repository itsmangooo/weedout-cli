package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/itsmangooo/weedout-cli/internal/ui"
)

// serveJSON stands up a fake API that answers one path.
//
// Records whether it was called at all, because several of the properties here
// are about *not* making a request: a bad --show value and a missing --reason
// must both fail before the network, so somebody typing at a prompt is
// corrected immediately rather than after a round trip.
type recorder struct {
	server *httptest.Server
	hits   int32
	method string
	body   string
}

func (r *recorder) called() bool { return atomic.LoadInt32(&r.hits) > 0 }

func serveJSON(t *testing.T, path string, status int, payload any) *recorder {
	t.Helper()
	rec := &recorder{}
	rec.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&rec.hits, 1)
		rec.method = r.Method
		if r.Body != nil {
			buf := make([]byte, 4096)
			n, _ := r.Body.Read(buf)
			rec.body = string(buf[:n])
		}
		if !strings.HasPrefix(r.URL.Path, path) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)
	}))
	t.Cleanup(rec.server.Close)
	return rec
}

// inTempDir runs the rest of the test from an empty directory.
//
// The reading commands resolve their key from the working directory upwards,
// which is what somebody at a terminal wants and what makes a test that checks
// for a *missing* key depend on whether the developer happens to have a
// .weedout file above the package. Isolating it here means the test asserts on
// the code rather than on the machine it runs on.
func inTempDir(t *testing.T) {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

func statusPayload() map[string]any {
	return map[string]any{
		"project":       "demo-app",
		"ecosystem":     "npm",
		"dependencies":  128,
		"counts":        map[string]int{"critical": 3, "high": 2, "medium": 1, "low": 0},
		"open":          6,
		"filtered":      41,
		"dismissed":     2,
		"resolved":      9,
		"dashboard_url": "https://weedout.dev/targets/1",
	}
}

func TestStatusPrintsTheCountsAndAChart(t *testing.T) {
	rec := serveJSON(t, "/api/v1/project", 200, statusPayload())

	code, out := run(t, "status", "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	for _, want := range []string{"demo-app", "128 dependencies", "6 open", "critical", "41 filtered out"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestStatusScaleIsStatedSoTheBarsMeanSomething(t *testing.T) {
	rec := serveJSON(t, "/api/v1/project", 200, statusPayload())

	_, out := run(t, "status", "--api-key", "wo_x", "--url", rec.server.URL)

	if !strings.Contains(out, "full bar = 3") {
		t.Errorf("a bar chart without its scale is decoration:\n%s", out)
	}
}

func TestStatusSaysWhenDependenciesWereNeverLookedAt(t *testing.T) {
	payload := statusPayload()
	payload["unreached_by_depth"] = 14

	rec := serveJSON(t, "/api/v1/project", 200, payload)
	_, out := run(t, "status", "--api-key", "wo_x", "--url", rec.server.URL)

	// The distinction the product lives on: not examined is not the same as
	// examined and clean, and only one of those deserves reassurance.
	if !strings.Contains(out, "not reached") {
		t.Errorf("unreached dependencies were not mentioned:\n%s", out)
	}
}

func TestStatusLeadsWithAFailedCheck(t *testing.T) {
	payload := statusPayload()
	payload["last_error"] = "The lockfile could not be parsed"

	rec := serveJSON(t, "/api/v1/project", 200, payload)
	_, out := run(t, "status", "--api-key", "wo_x", "--url", rec.server.URL)

	errorAt := strings.Index(out, "could not be parsed")
	countsAt := strings.Index(out, "6 open")
	if errorAt < 0 {
		t.Fatalf("the failure was not reported:\n%s", out)
	}
	// Every number below it came from an older scan, so reading the counts as
	// current would be the wrong conclusion.
	if countsAt >= 0 && errorAt > countsAt {
		t.Errorf("stale counts were printed above the failure:\n%s", out)
	}
}

func TestStatusJSONIsJustJSON(t *testing.T) {
	rec := serveJSON(t, "/api/v1/project", 200, statusPayload())

	_, out := run(t, "status", "--json", "--api-key", "wo_x", "--url", rec.server.URL)

	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("not parseable as JSON: %v\n%s", err, out)
	}
	if parsed["project"] != "demo-app" {
		t.Errorf("wrong project: %v", parsed["project"])
	}
}

// ---------------------------------------------------------------------------
// findings
// ---------------------------------------------------------------------------

func TestFindingsShowsTheFixAndHowItGotIn(t *testing.T) {
	rec := serveJSON(t, "/api/v1/findings", 200, map[string]any{
		"show":  "open",
		"count": 1,
		"findings": []map[string]any{{
			"package": "minimist", "version": "0.0.8", "cve": "CVE-2020-7598",
			"severity": "critical", "fixed_in": "1.2.6", "depth": 2,
			"via": []string{"webpack", "yargs"}, "summary": "Prototype pollution",
		}},
	})

	_, out := run(t, "findings", "--api-key", "wo_x", "--url", rec.server.URL)

	for _, want := range []string{"minimist@0.0.8", "CVE-2020-7598", "Fixed in 1.2.6", "webpack > yargs > minimist"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestFindingsSaysWhenThereIsNoFixYet(t *testing.T) {
	rec := serveJSON(t, "/api/v1/findings", 200, map[string]any{
		"show": "open", "count": 1,
		"findings": []map[string]any{{"package": "x", "version": "1.0.0", "severity": "high"}},
	})

	_, out := run(t, "findings", "--api-key", "wo_x", "--url", rec.server.URL)

	// Blank space where a fix would go reads as "no data". Saying it outright
	// is the difference between "upgrade" and "there is nothing to upgrade to".
	if !strings.Contains(out, "No fixed version yet") {
		t.Errorf("missing the no-fix line:\n%s", out)
	}
}

func TestFindingsNamesMalwareAsMalwareNotAsASeverity(t *testing.T) {
	rec := serveJSON(t, "/api/v1/findings", 200, map[string]any{
		"show": "open", "count": 1,
		"findings": []map[string]any{{
			"package": "noblox.js-proxy", "version": "1.0.0",
			"advisory": "MAL-2023-8489", "severity": "unknown", "malicious": true,
		}},
	})

	_, out := run(t, "findings", "--api-key", "wo_x", "--url", rec.server.URL)

	if !strings.Contains(out, "malicious package") {
		t.Errorf("malware was not named as malware:\n%s", out)
	}
	// Malware carries no CVSS score, and printing "severity not scored" beside
	// it would read as "we do not know how bad this is".
	if strings.Contains(out, "severity not scored") {
		t.Errorf("malware rendered as an unscored vulnerability:\n%s", out)
	}
}

func TestFindingsRejectsAnUnknownTabBeforeCallingTheServer(t *testing.T) {
	rec := serveJSON(t, "/api/v1/findings", 200, map[string]any{})

	code, out := run(t, "findings", "--show", "everything",
		"--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if rec.called() {
		t.Error("a typo should be caught before a round trip")
	}
	if !strings.Contains(out, "open, filtered, dismissed or resolved") {
		t.Errorf("the message did not list the options:\n%s", out)
	}
}

func TestAnEmptyTabSaysWhatItMeans(t *testing.T) {
	rec := serveJSON(t, "/api/v1/findings", 200, map[string]any{
		"show": "filtered", "count": 0, "findings": []map[string]any{},
	})

	_, out := run(t, "findings", "--show", "filtered",
		"--api-key", "wo_x", "--url", rec.server.URL)

	// "Nothing here" is ambiguous on the filtered tab: it could mean the
	// filtering is not working. Saying what an empty tab means removes that.
	if !strings.Contains(out, "worth reporting") {
		t.Errorf("empty filtered tab was not explained:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// history
// ---------------------------------------------------------------------------

func TestHistoryChartsOldestToNewest(t *testing.T) {
	// The API answers newest first, which is right for a list and backwards
	// for a chart. If this is not reversed the trend reads inverted, which is
	// worse than having no chart at all.
	rec := serveJSON(t, "/api/v1/history", 200, map[string]any{
		"runs": []map[string]any{
			{"started_at": "2026-08-20T10:00:00+00:00", "actionable": 9},
			{"started_at": "2026-08-19T10:00:00+00:00", "actionable": 5},
			{"started_at": "2026-08-18T10:00:00+00:00", "actionable": 0},
		},
	})

	_, out := run(t, "history", "--api-key", "wo_x", "--url", rec.server.URL)

	if !strings.Contains(out, "0 to 9") {
		t.Errorf("the range was not stated:\n%s", out)
	}

	printer := ui.New(nilWriter{})
	spark := printer.Spark([]int{0, 5, 9})
	if spark != "" && !strings.Contains(out, spark) {
		t.Errorf("expected the series drawn oldest-first as %q:\n%s", spark, out)
	}
}

func TestHistoryShowsWhatChanged(t *testing.T) {
	rec := serveJSON(t, "/api/v1/history", 200, map[string]any{
		"runs": []map[string]any{{
			"started_at": "2026-08-20T10:00:00+00:00",
			"actionable": 4, "suppressed": 30, "new": 2, "resolved": 1,
		}},
	})

	_, out := run(t, "history", "--api-key", "wo_x", "--url", rec.server.URL)

	for _, want := range []string{"4 open", "30 filtered out", "+2 new", "-1 resolved"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestHistoryReportsAFailedRunAsFailedNotAsZero(t *testing.T) {
	rec := serveJSON(t, "/api/v1/history", 200, map[string]any{
		"runs": []map[string]any{{
			"started_at": "2026-08-20T10:00:00+00:00",
			"status":     "failed", "actionable": 0,
			"error": "The registry timed out",
		}},
	})

	_, out := run(t, "history", "--api-key", "wo_x", "--url", rec.server.URL)

	// A run that did not happen showing "0 open" is the single most dangerous
	// thing this tool could print.
	if !strings.Contains(out, "failed") || !strings.Contains(out, "timed out") {
		t.Errorf("a failed run was not reported as failed:\n%s", out)
	}
	if strings.Contains(out, "0 open") {
		t.Errorf("a failed run was reported as a clean one:\n%s", out)
	}
}

type nilWriter struct{}

func (nilWriter) Write(p []byte) (int, error) { return len(p), nil }

// ---------------------------------------------------------------------------
// supply-chain
// ---------------------------------------------------------------------------

func TestSupplyChainPutsTheConcerningOnesFirst(t *testing.T) {
	rec := serveJSON(t, "/api/v1/supply-chain", 200, map[string]any{
		"signals": []map[string]any{
			{"package": "a", "kind": "single_maintainer", "label": "One maintainer",
				"level": "informational"},
			{"package": "b", "kind": "typosquat", "label": "Looks like a typosquat",
				"level": "concerning"},
		},
	})

	_, out := run(t, "supply-chain", "--api-key", "wo_x", "--url", rec.server.URL)

	typo := strings.Index(out, "typosquat")
	single := strings.Index(out, "One maintainer")
	if typo < 0 || single < 0 {
		t.Fatalf("signals missing:\n%s", out)
	}
	if typo > single {
		t.Errorf("informational signal printed above a concerning one:\n%s", out)
	}
}

func TestSupplyChainSaysTheseAreNotVulnerabilities(t *testing.T) {
	rec := serveJSON(t, "/api/v1/supply-chain", 200, map[string]any{
		"signals": []map[string]any{
			{"package": "a", "label": "One maintainer", "level": "informational"},
		},
	})

	_, out := run(t, "supply-chain", "--api-key", "wo_x", "--url", rec.server.URL)

	// Without this the list reads as a second findings page, and a package
	// having one maintainer is not a reason to do anything.
	if !strings.Contains(out, "not vulnerabilities") {
		t.Errorf("the framing line is missing:\n%s", out)
	}
}

func TestSignalsIsAnAliasForSupplyChain(t *testing.T) {
	rec := serveJSON(t, "/api/v1/supply-chain", 200, map[string]any{"signals": []any{}})

	code, _ := run(t, "signals", "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK || !rec.called() {
		t.Error("the alias did not reach the same endpoint")
	}
}

// ---------------------------------------------------------------------------
// The scope refusal
// ---------------------------------------------------------------------------

func TestAScanKeyIsToldWhichKeyWouldWork(t *testing.T) {
	rec := serveJSON(t, "/api/v1/findings", http.StatusForbidden, map[string]any{
		"error": "insufficient_scope",
		"message": "This key can push scans. That endpoint needs a key with " +
			"read access. Create one in Settings.",
	})

	code, out := run(t, "findings", "--api-key", "wo_ci", "--url", rec.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	// The server's message is specific enough to print as-is; replacing it
	// with a generic "forbidden" would send somebody to make a broader key.
	if !strings.Contains(out, "read access") {
		t.Errorf("the refusal did not say which key would work:\n%s", out)
	}
}

func TestMissingKeyNamesTheScopeNeeded(t *testing.T) {
	inTempDir(t)
	t.Setenv("WEEDOUT_API_KEY", "")

	code, out := run(t, "status", "--url", "http://127.0.0.1:1")

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if !strings.Contains(out, "read access") {
		t.Errorf("did not say a CI key is the wrong one:\n%s", out)
	}
}

func TestAFailedRunIsNotChartedAsZeroFindings(t *testing.T) {
	// Found by running this against real data, where a run that aborted on a
	// stale advisory feed reported zero and drew a trough. A gap in the data
	// rendered as good news is the worst failure mode a chart has.
	rec := serveJSON(t, "/api/v1/history", 200, map[string]any{
		"runs": []map[string]any{
			{"started_at": "2026-08-20T10:00:00+00:00", "actionable": 13},
			{"started_at": "2026-08-19T10:00:00+00:00", "actionable": 0,
				"status": "failed", "error": "Advisory data is stale"},
			{"started_at": "2026-08-18T10:00:00+00:00", "actionable": 16},
		},
	})

	_, out := run(t, "history", "--api-key", "wo_x", "--url", rec.server.URL)

	if !strings.Contains(out, "13 to 16") {
		t.Errorf("the failed run dragged the range down to zero:\n%s", out)
	}
	if !strings.Contains(out, "did not finish") {
		t.Errorf("scans left out of the chart were not accounted for:\n%s", out)
	}
}

func TestAllFailedRunsDrawNoChartRatherThanAFlatZero(t *testing.T) {
	rec := serveJSON(t, "/api/v1/history", 200, map[string]any{
		"runs": []map[string]any{
			{"started_at": "2026-08-20T10:00:00+00:00", "status": "failed", "error": "timed out"},
			{"started_at": "2026-08-19T10:00:00+00:00", "status": "failed", "error": "timed out"},
		},
	})

	_, out := run(t, "history", "--api-key", "wo_x", "--url", rec.server.URL)

	// Nothing succeeded, so there is no trend. A flat line at zero would be a
	// confident claim about a project nobody has managed to scan.
	if strings.Contains(out, "Open findings per scan") {
		t.Errorf("a chart was drawn with no successful scans in it:\n%s", out)
	}
	if !strings.Contains(out, "timed out") {
		t.Errorf("the failures were not listed:\n%s", out)
	}
}

func TestAnOverdueCheckIsNotRenderedAsAPastEvent(t *testing.T) {
	// Also found against real data: a next check in the past printed as
	// "8 hours ago", which reads as a check that happened.
	payload := statusPayload()
	payload["next_scan_at"] = "2026-01-01T00:00:00+00:00"

	rec := serveJSON(t, "/api/v1/project", 200, payload)
	_, out := run(t, "status", "--api-key", "wo_x", "--url", rec.server.URL)

	next := out[strings.Index(out, "Next check"):]
	if strings.Contains(next[:40], "ago") && !strings.Contains(next[:40], "overdue") {
		t.Errorf("an overdue check read as one that already ran:\n%s", next[:40])
	}
	if !strings.Contains(out, "overdue") {
		t.Errorf("lateness was not named:\n%s", out)
	}
}
