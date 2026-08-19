package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
