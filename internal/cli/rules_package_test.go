package cli

import (
	"strings"
	"testing"
)

// Ignoring a family of packages rather than one advisory.
//
// The case ignoring-by-id cannot serve: a private package mirrored under a name
// that also exists on the public registry matches advisories about somebody
// else's code, and the list of ids to enumerate grows every time that other
// project publishes one.

func TestIgnoreSendsThePackageKind(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{"identifier": "@acme/*"})

	code, out := run(t, "rules", "ignore", "--package", "@acme/*",
		"--reason", "internal mirror of a public name",
		"--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	// Always sent, so the server never has to infer which kind was meant from
	// the shape of the identifier.
	for _, want := range []string{`"kind":"package"`, `"identifier":"@acme/*"`} {
		if !strings.Contains(rec.body, want) {
			t.Errorf("missing %s in the request body:\n%s", want, rec.body)
		}
	}
}

func TestAnAdvisoryRuleStillSendsTheAdvisoryKind(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{"identifier": "CVE-2021-23337"})

	run(t, "rules", "ignore", "CVE-2021-23337", "--reason", "not reachable from our code",
		"--api-key", "wo_x", "--url", rec.server.URL)

	if !strings.Contains(rec.body, `"kind":"advisory"`) {
		t.Errorf("the kind was not sent:\n%s", rec.body)
	}
}

func TestIgnoreRefusesBothAtOnce(t *testing.T) {
	// No single reading, and guessing would silence something the caller did
	// not ask to silence.
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{})

	code, out := run(t, "rules", "ignore", "CVE-2021-23337", "--package", "@acme/*",
		"--reason", "both please", "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d: %s", ExitError, code, out)
	}
	if rec.called() {
		t.Error("an ambiguous rule should never reach the server")
	}
	if !strings.Contains(out, "not both") {
		t.Errorf("the refusal did not say why:\n%s", out)
	}
}

func TestIgnoreWithNeitherPointsAtBothWays(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{})

	code, out := run(t, "rules", "ignore", "--reason", "a reason on its own",
		"--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if !strings.Contains(out, "--package") {
		t.Errorf("the message did not mention the other way:\n%s", out)
	}
}

func TestAPackageRuleStillNeedsAReason(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{})

	code, out := run(t, "rules", "ignore", "--package", "@acme/*",
		"--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitError {
		t.Errorf("expected exit %d, got %d", ExitError, code)
	}
	if rec.called() {
		t.Error("a rule with no reason should never reach the server")
	}
	// The example shown has to be the shape of the rule being written, not the
	// advisory one, or it reads as a non sequitur.
	if !strings.Contains(out, "--package") {
		t.Errorf("the example did not match what was being written:\n%s", out)
	}
}

func TestAPackageRuleSaysWhatItCovers(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{"identifier": "@acme/*"})

	_, out := run(t, "rules", "ignore", "--package", "@acme/*",
		"--reason", "internal mirror of a public name",
		"--api-key", "wo_x", "--url", rec.server.URL)

	// "@acme/* will no longer be reported" would be wrong: the packages are
	// still scanned and still listed. What stops is the advisories about them.
	if !strings.Contains(out, "Advisories about @acme/*") {
		t.Errorf("the confirmation misdescribed the rule:\n%s", out)
	}
	if !strings.Contains(out, "known-exploited") {
		t.Errorf("the override was not mentioned:\n%s", out)
	}
}

func TestTheListingMarksPackageRules(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{
		"thresholds": map[string]any{"direct": "high", "transitive": "critical"},
		"ignores": []map[string]any{
			{
				"identifier": "CVE-2021-23337",
				"kind":       "advisory",
				"reason":     "not reachable from our code",
			},
			{
				"identifier": "@acme/*",
				"kind":       "package",
				"reason":     "internal mirror of a public name",
			},
		},
		"policy_file": map[string]any{"present": false},
	})

	code, out := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "every advisory") {
		t.Errorf("a package rule was listed as if it named one advisory:\n%s", out)
	}
	// And the advisory rule must not have picked up the same annotation.
	if strings.Count(out, "every advisory") != 1 {
		t.Errorf("the annotation was applied to the wrong rules:\n%s", out)
	}
}

func TestTheListingShowsPackageGlobsFromTheFile(t *testing.T) {
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{
		"thresholds": map[string]any{},
		"ignores":    []map[string]any{},
		"policy_file": map[string]any{
			"present":          true,
			"updated_at":       "2026-08-01T10:00:00+00:00",
			"ignores":          []string{"CVE-2021-23337"},
			"ignored_packages": []string{"karma-*"},
		},
	})

	code, out := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "karma-*") {
		t.Errorf("a package glob in the file was not listed:\n%s", out)
	}
	// Both kinds count towards the total, or the number disagrees with the
	// list printed under it.
	if !strings.Contains(out, "2 ignore rule(s)") {
		t.Errorf("the count did not include both kinds:\n%s", out)
	}
}

func TestAServerWithoutPackageRulesStillLists(t *testing.T) {
	// No `kind` on the wire means advisory, which is what every rule was
	// before this existed.
	rec := serveJSON(t, "/api/v1/rules", 200, map[string]any{
		"thresholds": map[string]any{},
		"ignores": []map[string]any{
			{"identifier": "CVE-2021-23337", "reason": "not reachable from our code"},
		},
		"policy_file": map[string]any{"present": false},
	})

	code, out := run(t, "rules", "--api-key", "wo_x", "--url", rec.server.URL)

	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	if strings.Contains(out, "every advisory") {
		t.Errorf("an advisory rule was annotated as a package rule:\n%s", out)
	}
}
