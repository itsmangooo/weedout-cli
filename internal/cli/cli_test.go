package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itsmangooo/weedout-cli/internal/api"
	"github.com/itsmangooo/weedout-cli/internal/globalconfig"
	"time"
)

// serve stands up a fake scan API returning the given payload.
func serve(t *testing.T, status int, payload any) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/scan" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)
	}))
	t.Cleanup(server.Close)
	return server
}

// project makes a temp directory containing a scannable manifest.
func project(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "package.json")
	if err := os.WriteFile(path, []byte(`{"dependencies":{"left-pad":"1.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// isolateConfig points the global config at a temporary directory.
//
// Every test in this package gets it, through TestMain. Without it a test run
// would read whatever `weedout auth` left on the developer's own machine --
// which means a suite that passes on a laptop and fails in CI, or worse, one
// that quietly authenticates against somebody's real account.
func isolateConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(globalconfig.EnvConfigHome, dir)
	return dir
}

func TestMain(m *testing.M) {
	// Set for the whole run, not per test, because `config.Resolve` reads it
	// from any goroutine and t.Setenv cannot cover code reached before a test
	// starts.
	home, err := os.MkdirTemp("", "weedout-test-config-")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv(globalconfig.EnvConfigHome, home)

	code := m.Run()

	_ = os.RemoveAll(home)
	os.Exit(code)
}

func run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := Run(args, &out, &out)
	return code, out.String()
}

// ---------------------------------------------------------------------------
// Exit codes — the contract with CI
// ---------------------------------------------------------------------------

func TestCleanScanExitsZero(t *testing.T) {
	server := serve(t, 200, map[string]any{
		"project": "demo", "dependencies_scanned": 12, "actionable": 0,
		"suppressed": 4, "counts": map[string]int{}, "findings": []any{},
	})
	code, out := run(t, "scan", project(t), "--api-key", "k", "--url", server.URL)
	if code != ExitOK {
		t.Fatalf("exit %d, want %d\n%s", code, ExitOK, out)
	}
	if !strings.Contains(out, "Nothing to act on") {
		t.Errorf("expected a clean-result line, got:\n%s", out)
	}
}

func TestCriticalFindingWithoutCiStillExitsZero(t *testing.T) {
	// Adding this tool to a pipeline must never be the thing that breaks the
	// build first. Findings are reported; only --ci makes them fatal.
	server := serve(t, 200, map[string]any{
		"project": "demo", "actionable": 1, "counts": map[string]int{"critical": 1},
		"findings": []map[string]any{
			{"package": "acme", "version": "1.0.0", "cve": "CVE-1", "severity": "critical"},
		},
	})
	code, out := run(t, "scan", project(t), "--api-key", "k", "--url", server.URL)
	if code != ExitOK {
		t.Fatalf("exit %d, want %d without --ci\n%s", code, ExitOK, out)
	}
}

func TestCiFailsOnCritical(t *testing.T) {
	server := serve(t, 200, map[string]any{
		"project": "demo", "actionable": 1, "counts": map[string]int{"critical": 1},
		"findings": []map[string]any{
			{"package": "acme", "version": "1.0.0", "cve": "CVE-1", "severity": "critical"},
		},
	})
	code, out := run(t, "scan", project(t), "--ci", "--api-key", "k", "--url", server.URL)
	if code != ExitFindings {
		t.Fatalf("exit %d, want %d\n%s", code, ExitFindings, out)
	}
}

func TestCiFailsOnExploitedEvenBelowCritical(t *testing.T) {
	// Confirmed exploitation outranks the severity label: a "high" that is
	// being used in the wild is more urgent than a critical that is not.
	server := serve(t, 200, map[string]any{
		"project": "demo", "actionable": 1, "counts": map[string]int{"high": 1},
		"findings": []map[string]any{
			{"package": "acme", "version": "1.0.0", "severity": "high", "exploited": true},
		},
	})
	code, _ := run(t, "scan", project(t), "--ci", "--api-key", "k", "--url", server.URL)
	if code != ExitFindings {
		t.Fatalf("exit %d, want %d for an exploited finding", code, ExitFindings)
	}
}

func TestCiPassesWhenNothingIsBlocking(t *testing.T) {
	server := serve(t, 200, map[string]any{
		"project": "demo", "actionable": 2, "counts": map[string]int{"high": 1, "medium": 1},
		"findings": []map[string]any{
			{"package": "a", "version": "1", "severity": "high"},
			{"package": "b", "version": "2", "severity": "medium"},
		},
	})
	code, out := run(t, "scan", project(t), "--ci", "--api-key", "k", "--url", server.URL)
	if code != ExitOK {
		t.Fatalf("exit %d, want %d — high is not blocking\n%s", code, ExitOK, out)
	}
}

func TestOneFindingBothCriticalAndExploitedCountsOnce(t *testing.T) {
	server := serve(t, 200, map[string]any{
		"project": "demo", "actionable": 1,
		"counts": map[string]int{"critical": 1, "exploited": 1},
		"findings": []map[string]any{
			{"package": "acme", "version": "1", "severity": "critical", "exploited": true},
		},
	})
	code, out := run(t, "scan", project(t), "--ci", "--api-key", "k", "--url", server.URL)
	if code != ExitFindings {
		t.Fatalf("exit %d, want %d", code, ExitFindings)
	}
	if !strings.Contains(out, "1 finding(s)") {
		t.Errorf("expected one blocking finding, not two summed counters:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Failures must be 2, never 1
// ---------------------------------------------------------------------------

func TestUnreachableServiceExitsTwo(t *testing.T) {
	// A pipeline that cannot tell "service down" from "vulnerabilities found"
	// will eventually treat an outage as a security finding.
	code, out := run(t, "scan", project(t), "--ci",
		"--api-key", "k", "--url", "http://127.0.0.1:1", "--timeout", "2")
	if code != ExitError {
		t.Fatalf("exit %d, want %d\n%s", code, ExitError, out)
	}
}

func TestRejectedKeyExitsTwo(t *testing.T) {
	server := serve(t, 401, map[string]any{"error": "invalid_key"})
	code, out := run(t, "scan", project(t), "--ci", "--api-key", "k", "--url", server.URL)
	if code != ExitError {
		t.Fatalf("exit %d, want %d\n%s", code, ExitError, out)
	}
	if !strings.Contains(out, "API key") {
		t.Errorf("the message should name the key as the problem:\n%s", out)
	}
}

func TestMissingKeyExitsTwoWithoutCallingTheServer(t *testing.T) {
	root := project(t)
	t.Setenv("WEEDOUT_API_KEY", "")
	code, out := run(t, "scan", root, "--url", "http://127.0.0.1:1")
	if code != ExitError {
		t.Fatalf("exit %d, want %d\n%s", code, ExitError, out)
	}
	if !strings.Contains(out, "No API key") {
		t.Errorf("expected a missing-key message:\n%s", out)
	}
}

func TestNoManifestExitsTwo(t *testing.T) {
	code, out := run(t, "scan", t.TempDir(), "--api-key", "k")
	if code != ExitError {
		t.Fatalf("exit %d, want %d\n%s", code, ExitError, out)
	}
	if !strings.Contains(out, "No manifest found") {
		t.Errorf("expected a not-found message:\n%s", out)
	}
}

func TestUnsupportedLockfileIsNamedInTheError(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "yarn.lock"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := run(t, "scan", root, "--api-key", "k")
	if code != ExitError {
		t.Fatalf("exit %d, want %d", code, ExitError)
	}
	if !strings.Contains(out, "yarn.lock") || !strings.Contains(out, "package.json") {
		t.Errorf("the message should name yarn.lock and suggest package.json:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Argument handling
// ---------------------------------------------------------------------------

func TestFlagsWorkBeforeOrAfterThePath(t *testing.T) {
	server := serve(t, 200, map[string]any{"project": "demo", "actionable": 0})
	root := project(t)

	for _, args := range [][]string{
		{"scan", root, "--api-key", "k", "--url", server.URL},
		{"scan", "--api-key", "k", "--url", server.URL, root},
	} {
		code, out := run(t, args...)
		if code != ExitOK {
			t.Errorf("exit %d for %v\n%s", code, args, out)
		}
	}
}

func TestUnknownCommandExitsTwo(t *testing.T) {
	if code, _ := run(t, "frobnicate"); code != ExitError {
		t.Errorf("exit %d, want %d", code, ExitError)
	}
}

func TestNoArgumentsPrintsUsage(t *testing.T) {
	code, out := run(t)
	if code != ExitError {
		t.Errorf("exit %d, want %d", code, ExitError)
	}
	if !strings.Contains(out, "weedout scan") {
		t.Errorf("expected usage text:\n%s", out)
	}
}

func TestVersionExitsZero(t *testing.T) {
	code, out := run(t, "version")
	if code != ExitOK || !strings.Contains(out, "weedout") {
		t.Errorf("exit %d out=%q", code, out)
	}
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

func TestInitWritesConfigAndWarnsAboutTheCredential(t *testing.T) {
	root := project(t)
	code, out := run(t, "init", root, "--api-key", "wo_secret")
	if code != ExitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}

	raw, err := os.ReadFile(filepath.Join(root, ".weedout"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "wo_secret") {
		t.Error("the key was not written")
	}
	if !strings.Contains(string(raw), ".gitignore") {
		t.Error("the file should warn that it holds a credential")
	}
	if !strings.Contains(out, ".gitignore") {
		t.Error("the command should say so too")
	}
}

func TestInitRefusesToClobberWithoutForce(t *testing.T) {
	root := project(t)
	if code, _ := run(t, "init", root, "--api-key", "first"); code != ExitOK {
		t.Fatal("setup failed")
	}
	code, _ := run(t, "init", root, "--api-key", "second")
	if code != ExitError {
		t.Fatalf("exit %d, want %d", code, ExitError)
	}

	raw, _ := os.ReadFile(filepath.Join(root, ".weedout"))
	if !strings.Contains(string(raw), "first") {
		t.Error("the existing key was overwritten without --force")
	}
}

// ---------------------------------------------------------------------------
// --fail-on and --json — what the GitHub Action depends on
// ---------------------------------------------------------------------------

// highOnly is a scan whose worst finding is high severity and not exploited:
// the one case the two thresholds disagree about.
func highOnly() map[string]any {
	return map[string]any{
		"project": "demo", "actionable": 1,
		"counts": map[string]int{"high": 1},
		"findings": []map[string]any{
			{"package": "acme", "version": "1.0.0", "cve": "CVE-1", "severity": "high", "fixed_in": "1.2.0"},
		},
	}
}

func TestDefaultThresholdIgnoresHigh(t *testing.T) {
	server := serve(t, 200, highOnly())
	code, out := run(t, "scan", project(t), "--ci", "--api-key", "k", "--url", server.URL)
	if code != ExitOK {
		t.Fatalf("exit %d, want %d: high must not fail at the default threshold\n%s",
			code, ExitOK, out)
	}
}

func TestFailOnHighFailsOnHigh(t *testing.T) {
	server := serve(t, 200, highOnly())
	code, out := run(t, "scan", project(t), "--ci", "--fail-on", "high",
		"--api-key", "k", "--url", server.URL)
	if code != ExitFindings {
		t.Fatalf("exit %d, want %d with --fail-on high\n%s", code, ExitFindings, out)
	}
}

func TestFailOnHighStillIgnoresMedium(t *testing.T) {
	// The flag raises the floor to high; it is not "fail on anything".
	server := serve(t, 200, map[string]any{
		"project": "demo", "actionable": 1,
		"counts": map[string]int{"medium": 1},
		"findings": []map[string]any{
			{"package": "acme", "version": "1.0.0", "severity": "medium"},
		},
	})
	code, out := run(t, "scan", project(t), "--ci", "--fail-on", "high",
		"--api-key", "k", "--url", server.URL)
	if code != ExitOK {
		t.Fatalf("exit %d, want %d: medium is below the high floor\n%s", code, ExitOK, out)
	}
}

func TestFailOnHighWithoutCiStillExitsZero(t *testing.T) {
	// --fail-on chooses the floor; --ci chooses whether it is fatal. Raising
	// the floor must not start failing builds that never asked to be gated.
	server := serve(t, 200, highOnly())
	code, out := run(t, "scan", project(t), "--fail-on", "high",
		"--api-key", "k", "--url", server.URL)
	if code != ExitOK {
		t.Fatalf("exit %d, want %d without --ci\n%s", code, ExitOK, out)
	}
}

func TestUnknownFailOnValueExitsTwoBeforeScanning(t *testing.T) {
	// Exit 2, not 1: a typo in the configuration did not find a vulnerability.
	// And it must not reach the server, or a bad flag costs a minute of CI.
	reached := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	code, out := run(t, "scan", project(t), "--ci", "--fail-on", "medium",
		"--api-key", "k", "--url", server.URL)
	if code != ExitError {
		t.Fatalf("exit %d, want %d for a bad --fail-on value\n%s", code, ExitError, out)
	}
	if reached {
		t.Error("a bad --fail-on value reached the server; it should fail first")
	}
	if !strings.Contains(out, "critical") || !strings.Contains(out, "high") {
		t.Errorf("the error should name the values that work, got:\n%s", out)
	}
}

func TestJSONOutputIsParseableAndCarriesTheDecision(t *testing.T) {
	server := serve(t, 200, highOnly())
	code, out := run(t, "scan", project(t), "--ci", "--fail-on", "high", "--json",
		"--api-key", "k", "--url", server.URL)
	if code != ExitFindings {
		t.Fatalf("exit %d, want %d\n%s", code, ExitFindings, out)
	}

	var report struct {
		Project      string         `json:"project"`
		FailOn       string         `json:"fail_on"`
		Blocking     int            `json:"blocking"`
		Failing      bool           `json:"failing"`
		DashboardURL string         `json:"dashboard_url"`
		Counts       map[string]int `json:"counts"`
		Findings     []struct {
			Package  string `json:"package"`
			CVE      string `json:"cve"`
			FixedIn  string `json:"fixed_in"`
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("--json did not produce JSON: %v\n%s", err, out)
	}

	if report.FailOn != "high" {
		t.Errorf("fail_on = %q, want high", report.FailOn)
	}
	if report.Blocking != 1 {
		t.Errorf("blocking = %d, want 1", report.Blocking)
	}
	if !report.Failing {
		t.Error("failing should be true: --ci was set and something blocked")
	}
	if len(report.Findings) != 1 || report.Findings[0].FixedIn != "1.2.0" {
		t.Errorf("the findings should survive into the JSON, got %+v", report.Findings)
	}
}

func TestJSONSaysNotFailingWithoutCi(t *testing.T) {
	// `failing` reports what the exit code is about to be, not what it might
	// have been under different flags. A summary that says "failing" beside a
	// green tick is worse than no summary.
	server := serve(t, 200, highOnly())
	code, out := run(t, "scan", project(t), "--fail-on", "high", "--json",
		"--api-key", "k", "--url", server.URL)
	if code != ExitOK {
		t.Fatalf("exit %d, want %d\n%s", code, ExitOK, out)
	}

	var report struct {
		Blocking int  `json:"blocking"`
		Failing  bool `json:"failing"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if report.Blocking != 1 {
		t.Errorf("blocking = %d, want 1: the finding is still counted", report.Blocking)
	}
	if report.Failing {
		t.Error("failing should be false without --ci")
	}
}

func TestJSONPrintsNothingButJSON(t *testing.T) {
	// The action pipes stdout straight into a parser. One stray line of prose
	// and the step fails with a message about the wrong thing entirely.
	server := serve(t, 200, highOnly())
	_, out := run(t, "scan", project(t), "--json", "--api-key", "k", "--url", server.URL)
	trimmed := strings.TrimSpace(out)
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		t.Errorf("--json output is not exactly one JSON document:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Malicious packages
//
// The regression these guard is specific and it was real: a malicious package
// advisory carries no CVSS score, so every check that ranked severity let the
// single worst finding this scanner can produce straight through the gate.
// ---------------------------------------------------------------------------

func maliciousResult() map[string]any {
	return map[string]any{
		"project": "demo", "actionable": 1,
		// No severity, because OSV publishes none: there is nothing to score.
		"counts": map[string]int{"malicious": 1, "unknown": 1},
		"findings": []map[string]any{
			{
				"package": "umi-rujaksoto75-sluey", "version": "1.0.0",
				"cve": "MAL-2025-137567", "severity": "unknown",
				"exploited": false, "malicious": true, "fixed_in": "",
			},
		},
	}
}

func TestCiFailsOnAMaliciousPackage(t *testing.T) {
	server := serve(t, 200, maliciousResult())
	code, out := run(t, "scan", project(t), "--ci", "--api-key", "k", "--url", server.URL)
	if code != ExitFindings {
		t.Fatalf("exit %d, want %d: malware must fail the build\n%s", code, ExitFindings, out)
	}
}

func TestMalwareFailsEvenAtTheDefaultThreshold(t *testing.T) {
	// --fail-on critical is the setting people leave on. A package that is
	// malware has no severity at all, so it must not depend on the threshold.
	server := serve(t, 200, maliciousResult())
	code, _ := run(t, "scan", project(t), "--ci", "--fail-on", "critical",
		"--api-key", "k", "--url", server.URL)
	if code != ExitFindings {
		t.Fatalf("exit %d, want %d at the default threshold", code, ExitFindings)
	}
}

func TestMalwareIsNamedInTheOutput(t *testing.T) {
	server := serve(t, 200, maliciousResult())
	_, out := run(t, "scan", project(t), "--api-key", "k", "--url", server.URL)
	if !strings.Contains(out, "malicious") {
		t.Errorf("the summary should say what this is, got:\n%s", out)
	}
	if !strings.Contains(out, "remove it") {
		t.Errorf("never tell somebody to upgrade malware; got:\n%s", out)
	}
}

func TestMalwareIsCountedInTheJSON(t *testing.T) {
	server := serve(t, 200, maliciousResult())
	_, out := run(t, "scan", project(t), "--ci", "--json", "--api-key", "k", "--url", server.URL)

	var report struct {
		Blocking int  `json:"blocking"`
		Failing  bool `json:"failing"`
		Findings []struct {
			Malicious bool `json:"malicious"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if report.Blocking != 1 || !report.Failing {
		t.Errorf("blocking=%d failing=%v, want 1 and true", report.Blocking, report.Failing)
	}
	if len(report.Findings) != 1 || !report.Findings[0].Malicious {
		t.Errorf("the malicious flag should survive into the JSON: %+v", report.Findings)
	}
}

func TestAnOldClientStillSeesSomethingSane(t *testing.T) {
	// `malicious` is its own field rather than a severity value, so a client
	// that predates it reads severity "unknown" and exploited false instead of
	// a level it cannot rank.
	server := serve(t, 200, maliciousResult())
	_, out := run(t, "scan", project(t), "--json", "--api-key", "k", "--url", server.URL)
	if strings.Contains(out, `"severity": "malicious"`) {
		t.Error("malicious leaked into the severity field")
	}
}

// ---------------------------------------------------------------------------
// Flag handling and quiet mode
// ---------------------------------------------------------------------------

func TestEveryValueFlagWorksOnEitherSideOfThePath(t *testing.T) {
	// The regression this guards: flag values used to be separated from the
	// path by a hand-maintained list of which flags take one. A flag missing
	// from that list had its value silently taken as the path, so
	// `weedout scan --fail-on high` would have scanned a directory called
	// "high". The flag set is asked now, so the list cannot drift.
	server := serve(t, 200, highOnly())
	dir := project(t)

	orders := [][]string{
		{"scan", dir, "--ci", "--fail-on", "high", "--api-key", "k", "--url", server.URL},
		{"scan", "--ci", "--fail-on", "high", dir, "--api-key", "k", "--url", server.URL},
		{"scan", "--fail-on", "high", "--api-key", "k", "--url", server.URL, "--ci", dir},
		{"scan", "--fail-on=high", dir, "--ci", "--api-key=k", "--url=" + server.URL},
	}
	for _, argv := range orders {
		code, out := run(t, argv...)
		if code != ExitFindings {
			t.Errorf("exit %d, want %d for %v\n%s", code, ExitFindings, argv, out)
		}
	}
}

func TestQuietPrintsNothingAndStillGates(t *testing.T) {
	server := serve(t, 200, highOnly())
	code, out := run(t, "scan", project(t), "--ci", "--fail-on", "high", "--quiet",
		"--api-key", "k", "--url", server.URL)

	if code != ExitFindings {
		t.Fatalf("exit %d, want %d: --quiet must still gate", code, ExitFindings)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("--quiet should print nothing, got:\n%s", out)
	}
}

func TestQuietStillReportsAScanThatCouldNotRun(t *testing.T) {
	// Silencing "your key was rejected" would turn a broken setup into a
	// passing build, which is the one failure this tool must never produce.
	server := serve(t, 401, map[string]any{"error": "invalid_key"})
	code, out := run(t, "scan", project(t), "--ci", "--quiet",
		"--api-key", "k", "--url", server.URL)

	if code != ExitError {
		t.Fatalf("exit %d, want %d", code, ExitError)
	}
	if strings.TrimSpace(out) == "" {
		t.Error("--quiet must not silence the reason a scan did not run")
	}
}

func TestAnOversizedManifestFailsBeforeUploading(t *testing.T) {
	// Fails in a sentence rather than by reading a bundle into memory and
	// sending it to be refused.
	reached := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	big := make([]byte, 6<<20)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), big, 0o644); err != nil {
		t.Fatal(err)
	}

	code, out := run(t, "scan", dir, "--api-key", "k", "--url", server.URL)
	if code != ExitError {
		t.Fatalf("exit %d, want %d", code, ExitError)
	}
	if reached {
		t.Error("an oversized manifest was uploaded instead of being refused locally")
	}
	if !strings.Contains(out, "limit is 5 MB") {
		t.Errorf("the refusal should say what the limit is, got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Retries
//
// This runs inside somebody's build. A momentary 502 that fails the pipeline
// is a flaky build, and a flaky security gate is one people start ignoring.
// ---------------------------------------------------------------------------

// noRetryDelay flattens the backoff for the duration of one test. The delays
// are real behaviour worth keeping; paying for them in the suite is not.
func noRetryDelay(t *testing.T) {
	t.Helper()
	original := api.RetryDelay
	api.RetryDelay = func(int) time.Duration { return 0 }
	t.Cleanup(func() { api.RetryDelay = original })
}

// flaky serves `failures` responses of `status`, then the payload.
func flaky(t *testing.T, status, failures int, payload any) (*httptest.Server, *int) {
	t.Helper()
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		// The body has to arrive intact on every attempt: an http.Request's
		// body is consumed by the first send, so a retry that does not rebuild
		// it uploads zero bytes.
		uploaded, _ := io.ReadAll(r.Body)
		if len(uploaded) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "empty upload on retry"})
			return
		}
		if attempts <= failures {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	t.Cleanup(server.Close)
	return server, &attempts
}

func TestATransientGatewayErrorIsRetried(t *testing.T) {
	noRetryDelay(t)
	clean := map[string]any{
		"project": "demo", "actionable": 0, "counts": map[string]int{}, "findings": []any{},
	}
	server, attempts := flaky(t, http.StatusBadGateway, 1, clean)

	code, out := run(t, "scan", project(t), "--ci", "--api-key", "k", "--url", server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d, want %d after a retry\n%s", code, ExitOK, out)
	}
	if *attempts != 2 {
		t.Errorf("attempts = %d, want 2", *attempts)
	}
}

func TestTheUploadSurvivesARetry(t *testing.T) {
	noRetryDelay(t)
	// The bug this guards: retrying without rebuilding the body sends zero
	// bytes, and the server answers 400 about a file that was fine.
	clean := map[string]any{
		"project": "demo", "actionable": 0, "counts": map[string]int{}, "findings": []any{},
	}
	server, _ := flaky(t, http.StatusServiceUnavailable, 2, clean)

	code, out := run(t, "scan", project(t), "--api-key", "k", "--url", server.URL)
	if code != ExitOK {
		t.Fatalf("exit %d, want %d; the retried upload was empty?\n%s", code, ExitOK, out)
	}
}

func TestARejectedKeyIsNotRetried(t *testing.T) {
	noRetryDelay(t)
	// A 401 will be a 401 next time. Retrying turns one clear "your key is
	// wrong" into three, and triples the time before the person sees it.
	server, attempts := flaky(t, http.StatusUnauthorized, 99, nil)

	code, _ := run(t, "scan", project(t), "--api-key", "k", "--url", server.URL)

	if code != ExitError {
		t.Fatalf("exit %d, want %d", code, ExitError)
	}
	if *attempts != 1 {
		t.Errorf("attempts = %d, want 1: a rejected key is not transient", *attempts)
	}
}

func TestGivingUpReportsTheServersOwnWords(t *testing.T) {
	noRetryDelay(t)
	server, attempts := flaky(t, http.StatusServiceUnavailable, 99, nil)

	code, out := run(t, "scan", project(t), "--ci", "--api-key", "k", "--url", server.URL)

	if code != ExitError {
		t.Fatalf("exit %d, want %d: a scan that never ran is not a clean one", code, ExitError)
	}
	if *attempts != 3 {
		t.Errorf("attempts = %d, want 3", *attempts)
	}
	if !strings.Contains(out, "not a clean result") {
		t.Errorf("the failure must not read as a pass, got:\n%s", out)
	}
}
